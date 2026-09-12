//! ELF core dump layer.
//!
//! Linux acquisition tools frequently write physical memory as an ELF core
//! file, with each `PT_LOAD` program header describing one run of memory.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::{Segment, SegmentedLayer};
use crate::framework::layers::LayerContainer;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;

/// Read a little-endian unsigned integer of `width` bytes from `data` at `at`.
///
/// A read that runs past the end of the data gives nothing, since the sizes
/// come from the file being read and cannot be trusted to fit.
fn read_uint(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(width)?)?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

/// Verify that `layer` starts with a little-endian ELF core header and report
/// its class (32- or 64-bit).
pub fn check_header(layers: &LayerContainer, layer: &str) -> Result<u8> {
    let header = layers
        .read(layer, 0, 0x40, false)
        .map_err(|_| VolatilityError::layer(layer, "Could not read ELF header"))?;

    if &header[0..4] != ELF_MAGIC {
        return Err(VolatilityError::layer(layer, "Not an ELF file"));
    }
    let class = header[4];
    if class != ELFCLASS32 && class != ELFCLASS64 {
        return Err(VolatilityError::layer(layer, "Unknown ELF class"));
    }
    if header[5] != ELFDATA2LSB {
        return Err(VolatilityError::layer(
            layer,
            "Only little-endian ELF files are supported",
        ));
    }
    let e_type = u16::from_le_bytes([header[16], header[17]]);
    if e_type != ET_CORE {
        return Err(VolatilityError::layer(layer, "ELF file is not a core dump"));
    }
    Ok(class)
}

/// Build a layer over the `PT_LOAD` segments of an ELF core dump.
pub fn build(
    layers: &LayerContainer,
    name: impl Into<String>,
    base_layer: impl Into<String>,
) -> Result<SegmentedLayer> {
    let name = name.into();
    let base_layer = base_layer.into();
    let class = check_header(layers, &base_layer)?;
    let is_64 = class == ELFCLASS64;

    // Field offsets differ between the two ELF classes.
    let (phoff_at, phentsize_at, phnum_at, word) = if is_64 {
        (0x20usize, 0x36usize, 0x38usize, 8usize)
    } else {
        (0x1C, 0x2A, 0x2C, 4)
    };

    let header = layers.read(&base_layer, 0, 0x40, false)?;
    let short = || VolatilityError::layer(&name, "ELF header is truncated");
    let phoff = read_uint(&header, phoff_at, word).ok_or_else(short)?;
    let phentsize = read_uint(&header, phentsize_at, 2).ok_or_else(short)? as usize;
    let phnum = read_uint(&header, phnum_at, 2).ok_or_else(short)? as usize;

    if phentsize == 0 || phnum == 0 {
        return Err(VolatilityError::layer(&name, "ELF file has no program headers"));
    }
    // A program header holds a fixed set of fields, so one smaller than those
    // fields describes nothing that can be read.
    let smallest = if is_64 { 56 } else { 32 };
    if phentsize < smallest {
        return Err(VolatilityError::layer(
            &name,
            format!("ELF program headers are {phentsize} bytes, less than the {smallest} a header takes"),
        ));
    }
    let Some(table_size) = phentsize.checked_mul(phnum) else {
        return Err(VolatilityError::layer(
            &name,
            "ELF program header table is larger than can be addressed",
        ));
    };

    let table = layers.read(&base_layer, phoff, table_size, false)?;
    let mut segments = Vec::new();

    for index in 0..phnum {
        let Some(entry) = table.get(index * phentsize..(index + 1) * phentsize) else {
            break;
        };
        let Some(p_type) = read_uint(entry, 0, 4) else {
            break;
        };
        if p_type as u32 != PT_LOAD {
            continue;
        }

        // 64-bit headers insert p_flags before p_offset. 32-bit places it last.
        let (offset_at, paddr_at, filesz_at, memsz_at) = if is_64 {
            (0x08usize, 0x18usize, 0x20usize, 0x28usize)
        } else {
            (0x04, 0x0C, 0x10, 0x14)
        };

        let (Some(p_offset), Some(p_paddr), Some(p_filesz), Some(p_memsz)) = (
            read_uint(entry, offset_at, word),
            read_uint(entry, paddr_at, word),
            read_uint(entry, filesz_at, word),
            read_uint(entry, memsz_at, word),
        ) else {
            break;
        };

        if p_filesz == 0 {
            continue;
        }
        // Only the bytes actually present in the file can be mapped. Any
        // trailing zero-fill described by p_memsz is left as a hole.
        segments.push(Segment::linear(p_paddr, p_offset, p_filesz.min(p_memsz.max(p_filesz))));
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(&name, "No PT_LOAD segments found"));
    }

    let mut metadata = HashMap::new();
    metadata.insert("os".to_string(), "Unknown".to_string());
    metadata.insert(
        "architecture".to_string(),
        if is_64 { "Intel64" } else { "Intel32" }.to_string(),
    );

    SegmentedLayer::new(name, base_layer, segments, metadata).map(|layer| layer.of_kind("Elf64Layer").in_module("volatility3.framework.layers.elf"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use std::sync::Arc;

    /// An ELF core file whose program headers are far too small to hold the
    /// fields a program header has.
    fn short_program_header() -> Vec<u8> {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(ELF_MAGIC);
        data[4] = ELFCLASS64;
        data[5] = ELFDATA2LSB;
        data[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&1u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[64] = 1;
        data
    }

    #[test]
    fn a_program_header_too_small_to_read_is_refused_rather_than_panicking() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", short_program_header())));

        let result = build(&layers, "elf", "base");
        assert!(result.is_err(), "a malformed program header must not be accepted");
    }

    #[test]
    fn reading_past_the_end_of_an_entry_gives_nothing() {
        assert_eq!(read_uint(&[1, 2, 3, 4], 0, 4), Some(0x04030201));
        assert_eq!(read_uint(&[1], 0, 4), None);
        assert_eq!(read_uint(&[1, 2, 3, 4], 2, 4), None);
        assert_eq!(read_uint(&[1, 2, 3, 4], usize::MAX, 4), None);
    }
}
