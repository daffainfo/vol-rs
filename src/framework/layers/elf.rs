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
fn read_uint(data: &[u8], at: usize, width: usize) -> u64 {
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(&data[at..at + width]);
    u64::from_le_bytes(value)
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
    let phoff = read_uint(&header, phoff_at, word);
    let phentsize = read_uint(&header, phentsize_at, 2) as usize;
    let phnum = read_uint(&header, phnum_at, 2) as usize;

    if phentsize == 0 || phnum == 0 {
        return Err(VolatilityError::layer(&name, "ELF file has no program headers"));
    }

    let table = layers.read(&base_layer, phoff, phentsize * phnum, false)?;
    let mut segments = Vec::new();

    for index in 0..phnum {
        let entry = &table[index * phentsize..(index + 1) * phentsize];
        let p_type = read_uint(entry, 0, 4) as u32;
        if p_type != PT_LOAD {
            continue;
        }

        // 64-bit headers insert p_flags before p_offset. 32-bit places it last.
        let (offset_at, paddr_at, filesz_at, memsz_at) = if is_64 {
            (0x08usize, 0x18usize, 0x20usize, 0x28usize)
        } else {
            (0x04, 0x0C, 0x10, 0x14)
        };

        let p_offset = read_uint(entry, offset_at, word);
        let p_paddr = read_uint(entry, paddr_at, word);
        let p_filesz = read_uint(entry, filesz_at, word);
        let p_memsz = read_uint(entry, memsz_at, word);

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
