//! Windows crash dump layer.
//!
//! A crash dump opens with a header giving the page directory base and a
//! description of which physical pages the file contains. Two body formats are
//! supported: a full dump, whose header lists runs of contiguous pages, and a
//! bitmap dump, which carries a bitmap with one bit per present page.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::{Segment, SegmentedLayer};
use crate::framework::layers::LayerContainer;

const PAGE_SIZE: u64 = 0x1000;

/// `PAGE`, opening every crash dump.
const SIGNATURE: u32 = 0x4547_4150;
/// `DUMP`, marking a 32-bit dump.
const VALID_DUMP_32: u32 = 0x504D_5544;
/// `DU64`, marking a 64-bit dump.
const VALID_DUMP_64: u32 = 0x3436_5544;

/// Dump body formats this layer can read.
const DUMP_TYPE_FULL: u32 = 0x1;
const DUMP_TYPE_BITMAP: u32 = 0x5;

/// Field offsets within the dump header. These are fixed by the on-disk format
/// and differ between the 32- and 64-bit variants.
struct HeaderLayout {
    /// Offset of `DirectoryTableBase`.
    directory_table_base: u64,
    /// Width of `DirectoryTableBase` and of the run fields.
    word: usize,
    /// Offset of the physical memory descriptor.
    physical_memory_block: u64,
    /// Offset of `DumpType`.
    dump_type: u64,
    /// Bytes of header before the dump body begins.
    header_size: u64,
    /// Offset of the run array within the physical memory descriptor.
    runs_offset: u64,
}

const LAYOUT_32: HeaderLayout = HeaderLayout {
    directory_table_base: 0x10,
    word: 4,
    physical_memory_block: 0x64,
    dump_type: 0xF88,
    header_size: 0x1000,
    runs_offset: 8,
};

const LAYOUT_64: HeaderLayout = HeaderLayout {
    directory_table_base: 0x10,
    word: 8,
    physical_memory_block: 0x88,
    dump_type: 0xF98,
    header_size: 0x2000,
    runs_offset: 0x10,
};

/// What the header told us about a dump.
#[derive(Debug, Clone)]
pub struct CrashHeader {
    pub is_64bit: bool,
    /// The page directory base, which the Intel layer needs.
    pub directory_table_base: u64,
    pub dump_type: u32,
}

fn read_u32(layers: &LayerContainer, layer: &str, offset: u64) -> Result<u32> {
    let data = layers.read(layer, offset, 4, false)?;
    Ok(u32::from_le_bytes(data.try_into().unwrap()))
}

fn read_word(layers: &LayerContainer, layer: &str, offset: u64, width: usize) -> Result<u64> {
    let data = layers.read(layer, offset, width, false)?;
    let mut buffer = [0u8; 8];
    buffer[..width].copy_from_slice(&data);
    Ok(u64::from_le_bytes(buffer))
}

/// Read and validate a crash dump header.
pub fn check_header(layers: &LayerContainer, layer: &str) -> Result<CrashHeader> {
    let signature = read_u32(layers, layer, 0)
        .map_err(|_| VolatilityError::layer(layer, "Could not read crash dump header"))?;
    if signature != SIGNATURE {
        return Err(VolatilityError::layer(
            layer,
            format!("Bad crash dump signature {signature:#x}"),
        ));
    }

    let valid_dump = read_u32(layers, layer, 4)?;
    let is_64bit = match valid_dump {
        VALID_DUMP_64 => true,
        VALID_DUMP_32 => false,
        other => {
            return Err(VolatilityError::layer(
                layer,
                format!("Invalid crash dump marker {other:#x}"),
            ))
        }
    };

    let layout = if is_64bit { &LAYOUT_64 } else { &LAYOUT_32 };
    let directory_table_base =
        read_word(layers, layer, layout.directory_table_base, layout.word)?;
    let dump_type = read_u32(layers, layer, layout.dump_type)?;

    Ok(CrashHeader {
        is_64bit,
        directory_table_base,
        dump_type,
    })
}

/// Build a layer over a Windows crash dump.
pub fn build(
    layers: &LayerContainer,
    name: impl Into<String>,
    base_layer: impl Into<String>,
) -> Result<(SegmentedLayer, CrashHeader)> {
    let name = name.into();
    let base_layer = base_layer.into();
    let header = check_header(layers, &base_layer)?;
    let layout = if header.is_64bit {
        &LAYOUT_64
    } else {
        &LAYOUT_32
    };

    let segments = match header.dump_type {
        DUMP_TYPE_FULL => full_dump_segments(layers, &base_layer, layout)?,
        DUMP_TYPE_BITMAP => bitmap_dump_segments(layers, &base_layer, layout)?,
        other => {
            return Err(VolatilityError::layer(
                &name,
                format!("Unsupported crash dump format {other:#x}"),
            ))
        }
    };

    let mut metadata = HashMap::new();
    metadata.insert("os".to_string(), "Windows".to_string());
    metadata.insert(
        "architecture".to_string(),
        if header.is_64bit { "Intel64" } else { "Intel32" }.to_string(),
    );

    let layer = SegmentedLayer::new(name, base_layer, segments, metadata).map(|layer| layer.of_kind("WindowsCrashDump64Layer").in_module("volatility3.framework.layers.crash"))?;
    Ok((layer, header))
}

/// A full dump lists runs of contiguous physical pages, laid out in the file in
/// the order the runs are declared.
fn full_dump_segments(
    layers: &LayerContainer,
    layer: &str,
    layout: &HeaderLayout,
) -> Result<Vec<Segment>> {
    let block = layout.physical_memory_block;
    let number_of_runs = read_u32(layers, layer, block)? as u64;

    if number_of_runs == 0 || number_of_runs > 0x10000 {
        return Err(VolatilityError::layer(
            layer,
            format!("Implausible run count {number_of_runs} in crash dump header"),
        ));
    }

    let mut segments = Vec::new();
    // The body starts immediately after the header. Each run's pages follow the
    // previous run's in file order.
    let mut file_offset = layout.header_size;

    for index in 0..number_of_runs {
        let run = block + layout.runs_offset + index * (layout.word as u64 * 2);
        let base_page = read_word(layers, layer, run, layout.word)?;
        let page_count = read_word(layers, layer, run + layout.word as u64, layout.word)?;
        if page_count == 0 {
            continue;
        }

        let length = page_count * PAGE_SIZE;
        segments.push(Segment::linear(base_page * PAGE_SIZE, file_offset, length));
        file_offset += length;
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(layer, "Crash dump has no memory runs"));
    }
    Ok(segments)
}

/// A bitmap dump carries one bit per physical page, set when the page is
/// present in the file. Present pages are stored back-to-back, so a run of set
/// bits becomes one segment.
fn bitmap_dump_segments(
    layers: &LayerContainer,
    layer: &str,
    layout: &HeaderLayout,
) -> Result<Vec<Segment>> {
    // The bitmap header sits at the start of the dump body.
    let summary = layout.header_size;
    let header_size = read_word(layers, layer, summary + 0x20, 8)?;
    let bitmap_size = read_word(layers, layer, summary + 0x28, 8)?;

    if bitmap_size == 0 || bitmap_size > 1 << 32 {
        return Err(VolatilityError::layer(
            layer,
            format!("Implausible bitmap size {bitmap_size} in crash dump"),
        ));
    }

    let bitmap_bytes = bitmap_size.div_ceil(8);
    let bitmap = layers.read(layer, summary + 0x38, bitmap_bytes as usize, true)?;

    let mut segments = Vec::new();
    // Present pages are packed in the file starting at header_size, in bitmap
    // order, so the file offset advances once per present page regardless of
    // where the gaps fall.
    let mut file_offset = header_size;
    let mut run_start: Option<u64> = None;
    let mut run_file_offset = 0u64;

    for page in 0..bitmap_size {
        let byte = bitmap[(page / 8) as usize];
        let present = byte & (1 << (page % 8)) != 0;

        match (present, run_start) {
            (true, None) => {
                run_start = Some(page);
                run_file_offset = file_offset;
                file_offset += PAGE_SIZE;
            }
            (true, Some(_)) => file_offset += PAGE_SIZE,
            (false, Some(start)) => {
                segments.push(Segment::linear(
                    start * PAGE_SIZE,
                    run_file_offset,
                    (page - start) * PAGE_SIZE,
                ));
                run_start = None;
            }
            (false, None) => {}
        }
    }

    // A run reaching the end of the bitmap is closed off here.
    if let Some(start) = run_start {
        segments.push(Segment::linear(
            start * PAGE_SIZE,
            run_file_offset,
            (bitmap_size - start) * PAGE_SIZE,
        ));
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(
            layer,
            "Crash dump bitmap marks no pages present",
        ));
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::layers::DataLayer;
    use std::sync::Arc;

    /// Build a synthetic 64-bit full crash dump with two runs.
    fn build_full_dump() -> Vec<u8> {
        let mut data = vec![0u8; LAYOUT_64.header_size as usize + 3 * PAGE_SIZE as usize];
        data[0..4].copy_from_slice(&SIGNATURE.to_le_bytes());
        data[4..8].copy_from_slice(&VALID_DUMP_64.to_le_bytes());
        data[0x10..0x18].copy_from_slice(&0x1AB000u64.to_le_bytes());
        data[LAYOUT_64.dump_type as usize..LAYOUT_64.dump_type as usize + 4]
            .copy_from_slice(&DUMP_TYPE_FULL.to_le_bytes());

        let block = LAYOUT_64.physical_memory_block as usize;
        data[block..block + 4].copy_from_slice(&2u32.to_le_bytes());

        let runs = block + LAYOUT_64.runs_offset as usize;
        // Run 0: one page at physical page 0.
        data[runs..runs + 8].copy_from_slice(&0u64.to_le_bytes());
        data[runs + 8..runs + 16].copy_from_slice(&1u64.to_le_bytes());
        // Run 1: two pages at physical page 0x10, leaving a hole between them.
        data[runs + 16..runs + 24].copy_from_slice(&0x10u64.to_le_bytes());
        data[runs + 24..runs + 32].copy_from_slice(&2u64.to_le_bytes());

        // Body: page for run 0, then two pages for run 1.
        let body = LAYOUT_64.header_size as usize;
        data[body] = 0xAA;
        data[body + PAGE_SIZE as usize] = 0xBB;
        data[body + 2 * PAGE_SIZE as usize] = 0xCC;
        data
    }

    #[test]
    fn reads_a_full_dump_through_its_runs() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", build_full_dump())));

        let (layer, header) = build(&layers, "crash", "base").unwrap();
        assert!(header.is_64bit);
        assert_eq!(header.directory_table_base, 0x1AB000);
        assert_eq!(header.dump_type, DUMP_TYPE_FULL);

        // Run 0 maps physical 0. Run 1 maps physical 0x10000 onwards.
        assert_eq!(layer.read(&layers, 0, 1, false).unwrap(), vec![0xAA]);
        assert_eq!(layer.read(&layers, 0x10000, 1, false).unwrap(), vec![0xBB]);
        assert_eq!(layer.read(&layers, 0x11000, 1, false).unwrap(), vec![0xCC]);

        // The gap between the runs is genuinely absent, not silently zero.
        assert!(layer.read(&layers, 0x1000, 1, false).is_err());
    }

    /// Build a synthetic bitmap dump: pages 0, 1 and 3 present.
    fn build_bitmap_dump() -> Vec<u8> {
        let body_start = LAYOUT_64.header_size;
        let bitmap_header = body_start + 0x38;
        let data_start = bitmap_header + 0x1000;
        let mut data = vec![0u8; (data_start + 3 * PAGE_SIZE) as usize];

        data[0..4].copy_from_slice(&SIGNATURE.to_le_bytes());
        data[4..8].copy_from_slice(&VALID_DUMP_64.to_le_bytes());
        data[LAYOUT_64.dump_type as usize..LAYOUT_64.dump_type as usize + 4]
            .copy_from_slice(&DUMP_TYPE_BITMAP.to_le_bytes());

        let summary = body_start as usize;
        data[summary + 0x20..summary + 0x28].copy_from_slice(&data_start.to_le_bytes());
        data[summary + 0x28..summary + 0x30].copy_from_slice(&4u64.to_le_bytes());
        // Bits 0, 1 and 3 set: pages 0, 1 and 3 are present.
        data[summary + 0x38] = 0b1011;

        data[data_start as usize] = 0x11;
        data[(data_start + PAGE_SIZE) as usize] = 0x22;
        data[(data_start + 2 * PAGE_SIZE) as usize] = 0x33;
        data
    }

    #[test]
    fn reads_a_bitmap_dump_and_skips_absent_pages() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", build_bitmap_dump())));

        let (layer, header) = build(&layers, "crash", "base").unwrap();
        assert_eq!(header.dump_type, DUMP_TYPE_BITMAP);

        // Pages 0 and 1 form one run. Page 3 is a separate run whose bytes
        // follow immediately in the file despite the gap in address space.
        assert_eq!(layer.read(&layers, 0, 1, false).unwrap(), vec![0x11]);
        assert_eq!(layer.read(&layers, PAGE_SIZE, 1, false).unwrap(), vec![0x22]);
        assert_eq!(
            layer.read(&layers, 3 * PAGE_SIZE, 1, false).unwrap(),
            vec![0x33]
        );

        // Page 2 was not dumped.
        assert!(layer.read(&layers, 2 * PAGE_SIZE, 1, false).is_err());
    }

    #[test]
    fn rejects_files_that_are_not_crash_dumps() {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", vec![0u8; 0x3000])));
        assert!(check_header(&layers, "base").is_err());
    }
}
