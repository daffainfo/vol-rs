//! LiME format layer.
//!
//! LiME stores physical memory as a sequence of `(header, bytes)` records, so
//! large holes in the physical address space cost nothing.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::{Segment, SegmentedLayer};
use crate::framework::layers::LayerContainer;

const MAGIC: u32 = 0x4C69_4D45;
const VERSION: u32 = 1;
/// magic, version, start, end, reserved
const HEADER_SIZE: u64 = 4 + 4 + 8 + 8 + 8;

/// Read and validate a LiME record header, returning its `(start, end)` range.
fn check_header(layers: &LayerContainer, layer: &str, offset: u64) -> Result<(u64, u64)> {
    let data = layers.read(layer, offset, HEADER_SIZE as usize, false)?;
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if magic != MAGIC || version != VERSION {
        return Err(VolatilityError::layer(
            layer,
            format!("Bad LiME header at file offset {offset:#x}"),
        ));
    }
    let start = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let end = u64::from_le_bytes(data[16..24].try_into().unwrap());
    Ok((start, end))
}

/// Confirm the base layer begins with a LiME header.
pub fn check(layers: &LayerContainer, layer: &str) -> Result<()> {
    check_header(layers, layer, 0).map(|_| ())
}

/// Walk the record chain and build a layer from it.
pub fn build(
    layers: &LayerContainer,
    name: impl Into<String>,
    base_layer: impl Into<String>,
) -> Result<SegmentedLayer> {
    let name = name.into();
    let base_layer = base_layer.into();
    let base_max = layers.get(&base_layer)?.maximum_address();

    let mut segments = Vec::new();
    let mut offset = 0u64;
    let mut highest = 0u64;

    while offset < base_max {
        let (start, end) = check_header(layers, &base_layer, offset)?;
        // Records must be ordered and non-overlapping. Anything else means the
        // file is truncated or corrupt rather than merely sparse.
        if (start < highest && !segments.is_empty()) || end < start {
            return Err(VolatilityError::layer(
                &name,
                format!("Bad start/end {start:#x}/{end:#x} at file offset {offset:#x}"),
            ));
        }
        let length = end - start + 1;
        segments.push(Segment::linear(start, offset + HEADER_SIZE, length));
        highest = end;
        offset += HEADER_SIZE + length;
    }

    if segments.is_empty() {
        return Err(VolatilityError::layer(&name, "No LiME segments defined"));
    }

    let mut metadata = HashMap::new();
    metadata.insert("os".to_string(), "Linux".to_string());
    SegmentedLayer::new(name, base_layer, segments, metadata).map(|layer| layer.of_kind("LimeLayer").in_module("volatility3.framework.layers.lime"))
}
