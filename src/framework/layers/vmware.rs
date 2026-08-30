//! VMware suspended-VM layer.
//!
//! VMware splits a snapshot in two: a `.vmem` file holding guest RAM and a
//! `.vmss`/`.vmsn` file holding metadata. The metadata is a tagged key/value
//! store. The `memory` group's `region*` tags say which parts of the `.vmem`
//! correspond to which guest physical addresses.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::{Segment, SegmentedLayer};
use crate::framework::layers::LayerContainer;

const PAGE_SIZE: u64 = 0x1000;
const HEADER_SIZE: u64 = 12;
/// name[64], tag_location, unknown
const GROUP_SIZE: u64 = 80;

/// The four snapshot magics VMware has used. The low nibble of the first byte
/// gives the format version.
const MAGICS: [[u8; 4]; 4] = [
    [0xD0, 0xBE, 0xD2, 0xBE],
    [0xD1, 0xBA, 0xD1, 0xBA],
    [0xD2, 0xBE, 0xD2, 0xBE],
    [0xD3, 0xBE, 0xD3, 0xBE],
];

/// A parsed tag: its name, its indices (tags may be arrays), and its value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TagKey {
    name: String,
    indices: Vec<u32>,
}

/// Confirm the metadata layer carries a VMware snapshot header.
pub fn check(layers: &LayerContainer, meta_layer: &str) -> Result<u8> {
    let data = layers.read(meta_layer, 0, HEADER_SIZE as usize, false)?;
    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if !MAGICS.contains(&magic) {
        return Err(VolatilityError::layer(
            meta_layer,
            format!("Wrong magic bytes for VMware layer: {magic:02x?}"),
        ));
    }
    Ok(magic[0] & 0xF)
}

fn read_uint(data: &[u8], width: usize) -> u64 {
    let mut value = [0u8; 8];
    let width = width.min(8);
    value[..width].copy_from_slice(&data[..width]);
    u64::from_le_bytes(value)
}

/// Parse the tag stream of the `memory` group.
fn read_tags(
    layers: &LayerContainer,
    meta_layer: &str,
    start: u64,
    version: u8,
) -> Result<HashMap<TagKey, u64>> {
    let mut tags = HashMap::new();
    let mut offset = start;
    // Indices are always 32-bit regardless of the snapshot version.
    let index_len: u64 = 4;

    loop {
        let prefix = layers.read(meta_layer, offset, 2, false)?;
        let flags = prefix[0];
        let name_len = prefix[1] as u64;
        // A zero flags/length pair terminates the group.
        if flags == 0 && name_len == 0 {
            break;
        }

        let name_bytes = layers.read(meta_layer, offset + 2, name_len as usize, false)?;
        let name = String::from_utf8_lossy(&name_bytes)
            .trim_end_matches('\0')
            .to_string();

        // The top two flag bits count how many indices follow the name.
        let indices_len = ((flags >> 6) & 3) as u64;
        let mut indices = Vec::new();
        for index in 0..indices_len {
            let at = offset + 2 + name_len + index * index_len;
            let raw = layers.read(meta_layer, at, index_len as usize, false)?;
            indices.push(read_uint(&raw, 4) as u32);
        }

        // The low six flag bits give the data length, with 62 and 63 reserved to
        // signal that a length word follows instead.
        let mut data_len = (flags & 0x3F) as u64;
        let value_at = offset + 2 + name_len + indices_len * index_len;

        let value = if data_len == 62 || data_len == 63 {
            data_len = if version == 0 { 4 } else { 8 };
            let size_raw = layers.read(meta_layer, value_at, data_len as usize, false)?;
            let data_size = read_uint(&size_raw, data_len as usize);
            // Two length words and two padding bytes precede the payload.
            let payload_at = value_at + 2 * data_len + 2;
            let payload = layers.read(
                meta_layer,
                payload_at,
                (data_size as usize).min(8),
                true,
            )?;
            offset = payload_at + data_size;
            read_uint(&payload, payload.len())
        } else {
            let raw = layers.read(meta_layer, value_at, data_len.max(1) as usize, true)?;
            offset = value_at + data_len;
            read_uint(&raw, data_len as usize)
        };

        tags.insert(TagKey { name, indices }, value);
    }
    Ok(tags)
}

/// Build a layer mapping the `.vmem` base layer using the `.vmss` metadata.
pub fn build(
    layers: &LayerContainer,
    name: impl Into<String>,
    base_layer: impl Into<String>,
    meta_layer: &str,
) -> Result<SegmentedLayer> {
    let name = name.into();
    let base_layer = base_layer.into();
    let version = check(layers, meta_layer)?;

    let header = layers.read(meta_layer, 0, HEADER_SIZE as usize, false)?;
    let group_count = u32::from_le_bytes(header[8..12].try_into().unwrap()) as u64;

    // Locate the `memory` group's tag stream.
    let mut memory_offset = None;
    for group in 0..group_count {
        let at = HEADER_SIZE + group * GROUP_SIZE;
        let entry = layers.read(meta_layer, at, GROUP_SIZE as usize, false)?;
        let group_name = String::from_utf8_lossy(&entry[0..64])
            .trim_end_matches('\0')
            .to_string();
        if group_name == "memory" {
            memory_offset = Some(u64::from_le_bytes(entry[64..72].try_into().unwrap()));
            break;
        }
    }
    let memory_offset = memory_offset
        .ok_or_else(|| VolatilityError::layer(&name, "VMware snapshot has no memory group"))?;

    let tags = read_tags(layers, meta_layer, memory_offset, version)?;

    let regions_count = tags
        .get(&TagKey {
            name: "regionsCount".to_string(),
            indices: vec![],
        })
        .copied()
        .unwrap_or(0);
    if regions_count == 0 {
        return Err(VolatilityError::layer(
            &name,
            "VMware VMEM is not split into regions",
        ));
    }

    let lookup = |tag: &str, region: u32| -> Option<u64> {
        tags.get(&TagKey {
            name: tag.to_string(),
            indices: vec![region],
        })
        .copied()
    };

    let mut segments = Vec::new();
    for region in 0..regions_count as u32 {
        let (Some(ppn), Some(page_num), Some(size)) = (
            lookup("regionPPN", region),
            lookup("regionPageNum", region),
            lookup("regionSize", region),
        ) else {
            continue;
        };
        segments.push(Segment::linear(
            ppn * PAGE_SIZE,
            page_num * PAGE_SIZE,
            size * PAGE_SIZE,
        ));
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(&name, "No VMware regions found"));
    }

    SegmentedLayer::new(name, base_layer, segments, HashMap::new())
        .map(|layer| layer.of_kind("VmwareLayer").in_module("volatility3.framework.layers.vmware").alongside(meta_layer))
}
