//! Xen `dump-core` layer.
//!
//! Xen writes a guest's memory as an ELF64 file whose sections, rather than
//! whose program headers, describe where each page belongs. `.xen_pages`
//! holds the pages themselves, one after another, and either `.xen_pfn` or
//! `.xen_p2m` says which guest frame each one is. The format is documented at
//! <https://xenbits.xen.org/docs/4.6-testing/misc/dump-core-format.txt>.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::{Segment, SegmentedLayer};
use crate::framework::layers::LayerContainer;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;

/// Every page a Xen dump holds is this large.
const PAGE_SIZE: u64 = 0x1000;

/// The value both tables use for a frame the dump does not hold.
const ABSENT: u64 = 0xFFFF_FFFF;

/// One entry of `.xen_p2m`: a guest frame and the machine frame behind it.
const P2M_ENTRY_SIZE: u64 = 16;

/// One entry of `.xen_pfn`: a guest frame on its own.
const PFN_ENTRY_SIZE: u64 = 8;

/// Read a little-endian unsigned integer of `width` bytes from `data` at `at`.
fn read_uint(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(width)?)?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

/// Verify that `layer` begins with a little-endian 64-bit ELF header.
///
/// A Xen dump is not obliged to call itself a core file, so this asks for less
/// than the ELF layer's own check does.
pub fn check_header(layers: &LayerContainer, layer: &str) -> Result<()> {
    let header = layers
        .read(layer, 0, 7, false)
        .map_err(|_| VolatilityError::layer(layer, "Offset 0x0 does not exist within the base layer"))?;
    if &header[0..4] != ELF_MAGIC {
        return Err(VolatilityError::layer(layer, "Bad magic at file offset 0x0"));
    }
    if header[4] != ELFCLASS64 {
        return Err(VolatilityError::layer(
            layer,
            format!("ELF class is not 64-bit (2): {}", header[4]),
        ));
    }
    Ok(())
}

/// A layer that supports the Xen Dump-Core format as documented at:
/// <https://xenbits.xen.org/docs/4.6-testing/misc/dump-core-format.txt>
pub fn build(
    layers: &LayerContainer,
    name: impl Into<String>,
    base_layer: impl Into<String>,
) -> Result<SegmentedLayer> {
    let name = name.into();
    let base_layer = base_layer.into();
    check_header(layers, &base_layer)?;

    let header = layers.read(&base_layer, 0, 0x40, false)?;
    let short = || VolatilityError::layer(&name, "ELF header is truncated");
    let section_offset = read_uint(&header, 0x28, 8).ok_or_else(short)?;
    let section_size = read_uint(&header, 0x3A, 2).ok_or_else(short)? as usize;
    let section_count = read_uint(&header, 0x3C, 2).ok_or_else(short)? as usize;
    let name_section = read_uint(&header, 0x3E, 2).ok_or_else(short)? as usize;

    // A section header holds a fixed set of fields, so one smaller than those
    // fields describes nothing that can be read.
    if section_size < 64 || section_count == 0 {
        return Err(VolatilityError::layer(
            &name,
            "Not a Xen Core Dump: it has no section headers",
        ));
    }
    let Some(table_size) = section_size.checked_mul(section_count) else {
        return Err(VolatilityError::layer(
            &name,
            "The section header table is larger than can be addressed",
        ));
    };
    let table = layers.read(&base_layer, section_offset, table_size, false)?;

    // Each header says where its own contents are and how long they are. The
    // one the file names as its string table holds every section's name.
    let mut sections: Vec<(u64, u64)> = Vec::new();
    for index in 0..section_count {
        let Some(entry) = table.get(index * section_size..(index + 1) * section_size) else {
            break;
        };
        let (Some(offset), Some(size)) = (read_uint(entry, 0x18, 8), read_uint(entry, 0x20, 8))
        else {
            break;
        };
        sections.push((offset, size));
    }
    let Some(&(names_offset, names_size)) = sections.get(name_section) else {
        return Err(VolatilityError::layer(
            &name,
            "No segment names, not a Xen Core Dump",
        ));
    };
    let names = layers.read(&base_layer, names_offset, names_size as usize, false)?;

    // The names are split the way the reference implementation splits them,
    // and the position of a name in that list is used as a section's index.
    // The table opens with a terminator, so the empty name that leaves at the
    // front lines up with the file's own empty first section.
    let names: Vec<&[u8]> = names.split(|byte| *byte == 0).collect();
    let section_named = |wanted: &[u8]| -> Option<(u64, u64)> {
        let index = names.iter().position(|entry| *entry == wanted)?;
        sections.get(index).copied()
    };

    let Some((pages_offset, _)) = section_named(b".xen_pages") else {
        return Err(VolatilityError::layer(
            &name,
            "Not a Xen Core Dump: it holds no .xen_pages section",
        ));
    };
    let pfn = section_named(b".xen_pfn");
    let p2m = section_named(b".xen_p2m");

    // Each entry names the guest frame the page at the matching position in
    // .xen_pages belongs to. A frame the dump does not hold is skipped rather
    // than mapped, which is what leaves a hole in the address space.
    let mut segments = Vec::new();
    match (pfn, p2m) {
        (Some(_), Some(_)) => {
            return Err(VolatilityError::layer(
                &name,
                "Both P2M and PFN in Xen Core Dump",
            ))
        }
        (Some((offset, size)), None) => {
            let data = layers.read(&base_layer, offset, size as usize, false)?;
            for (index, entry) in data.chunks_exact(PFN_ENTRY_SIZE as usize).enumerate() {
                let frame = read_uint(entry, 0, 8).unwrap_or(ABSENT);
                if frame == 0 || frame == ABSENT {
                    continue;
                }
                segments.push(Segment::linear(
                    frame * PAGE_SIZE,
                    pages_offset + index as u64 * PAGE_SIZE,
                    PAGE_SIZE,
                ));
            }
        }
        (None, Some((offset, size))) => {
            let data = layers.read(&base_layer, offset, size as usize, false)?;
            for (index, entry) in data.chunks_exact(P2M_ENTRY_SIZE as usize).enumerate() {
                let frame = read_uint(entry, 0, 8).unwrap_or(ABSENT);
                if frame == ABSENT {
                    continue;
                }
                segments.push(Segment::linear(
                    frame * PAGE_SIZE,
                    pages_offset + index as u64 * PAGE_SIZE,
                    PAGE_SIZE,
                ));
            }
        }
        (None, None) => {
            return Err(VolatilityError::layer(
                &name,
                "Neither P2M nor PFN in Xen Core Dump",
            ))
        }
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(
            &name,
            format!("No ELF segments defined in {base_layer}"),
        ));
    }

    SegmentedLayer::new(name, base_layer, segments, HashMap::new()).map(|layer| {
        layer
            .of_kind("XenCoreDumpLayer")
            .in_module("volatility3.framework.layers.xen")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::layers::DataLayer;
    use std::sync::Arc;

    /// A Xen dump holding two pages, the second of which the guest never had.
    fn dump() -> Vec<u8> {
        // Four sections: the empty one, the names, the frame table, the pages.
        let names: &[u8] = b"\0.shstrtab\0.xen_pfn\0.xen_pages\0";
        let section_table = 0x40usize;
        let names_at = section_table + 4 * 64;
        let pfn_at = names_at + names.len();
        let pages_at = pfn_at + 16;
        let mut data = vec![0u8; pages_at + 2 * 0x1000];

        data[0..4].copy_from_slice(ELF_MAGIC);
        data[4] = ELFCLASS64;
        data[5] = 1;
        data[0x28..0x30].copy_from_slice(&(section_table as u64).to_le_bytes());
        data[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        data[0x3C..0x3E].copy_from_slice(&4u16.to_le_bytes());
        data[0x3E..0x40].copy_from_slice(&1u16.to_le_bytes());

        let header = |data: &mut Vec<u8>, index: usize, offset: u64, size: u64| {
            let at = section_table + index * 64;
            data[at + 0x18..at + 0x20].copy_from_slice(&offset.to_le_bytes());
            data[at + 0x20..at + 0x28].copy_from_slice(&size.to_le_bytes());
        };
        header(&mut data, 1, names_at as u64, names.len() as u64);
        header(&mut data, 2, pfn_at as u64, 16);
        header(&mut data, 3, pages_at as u64, 2 * 0x1000);

        data[names_at..names_at + names.len()].copy_from_slice(names);
        // The first page is guest frame 3, the second is not present.
        data[pfn_at..pfn_at + 8].copy_from_slice(&3u64.to_le_bytes());
        data[pfn_at + 8..pfn_at + 16].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
        data[pages_at] = 0x5A;
        data
    }

    #[test]
    fn a_frame_table_places_each_page_where_the_guest_had_it() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", dump())));
        let layer = build(&layers, "xen", "base").expect("a Xen dump is recognised");

        assert_eq!(layer.minimum_address(), 3 * 0x1000);
        let page = layer
            .read(&layers, 3 * 0x1000, 1, false)
            .expect("the page the table names is readable");
        assert_eq!(page[0], 0x5A);
        // The frame the table marks as absent leaves a hole behind it.
        assert_eq!(layer.maximum_address(), 4 * 0x1000 - 1);
    }

    #[test]
    fn a_file_that_is_not_elf64_is_refused() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", vec![0u8; 0x200])));
        assert!(build(&layers, "xen", "base").is_err());
    }
}
