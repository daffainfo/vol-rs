//! Support for layers described by a list of segments.
//!
//! Many memory image formats (ELF cores, LiME, crash dumps, VMware snapshots)
//! amount to "here are N runs of physical memory and where their bytes live in
//! the file". `SegmentedLayer` holds that table and answers reads against it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::{DataLayer, LayerContainer, MappingEntry};

/// One run of memory: `length` bytes of this layer's address space starting at
/// `offset`, stored at `mapped_offset` in the base layer.
///
/// `mapped_length` differs from `length` only for non-linear layers, where the
/// stored bytes are compressed or otherwise encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub offset: u64,
    pub mapped_offset: u64,
    pub length: u64,
    pub mapped_length: u64,
}

impl Segment {
    /// A segment whose bytes are stored verbatim.
    pub fn linear(offset: u64, mapped_offset: u64, length: u64) -> Self {
        Self {
            offset,
            mapped_offset,
            length,
            mapped_length: length,
        }
    }

    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.offset && address < self.end()
    }
}

/// A layer defined by a sorted segment table over a single base layer.
pub struct SegmentedLayer {
    /// The class the reference implementation would build for this format.
    kind: &'static str,
    /// The module the class named by `kind` lives in.
    module: &'static str,
    /// Layers this one draws on beyond the one holding its data: a VMware
    /// image keeps its segment table in a second file, and an image's
    /// description lists that too.
    companions: Vec<String>,
    name: String,
    base_layer: String,
    /// Sorted by `offset`, so lookups can binary search.
    segments: Vec<Segment>,
    minimum_address: u64,
    maximum_address: u64,
    metadata: HashMap<String, String>,
}

impl SegmentedLayer {
    /// Build a layer from `segments`, which are sorted and bounds-derived here
    /// so callers may supply them in any order.
    pub fn new(
        name: impl Into<String>,
        base_layer: impl Into<String>,
        mut segments: Vec<Segment>,
        metadata: HashMap<String, String>,
    ) -> Result<Self> {
        let name = name.into();
        if segments.is_empty() {
            return Err(VolatilityError::layer(&name, "No segments defined for layer"));
        }
        segments.sort_unstable_by_key(|segment| segment.offset);

        let minimum_address = segments.first().map(|s| s.offset).unwrap_or(0);
        let maximum_address = segments
            .iter()
            .map(|s| s.end())
            .max()
            .unwrap_or(0)
            .saturating_sub(1);

        Ok(Self {
            kind: "SegmentedLayer",
            module: "volatility3.framework.layers.segmented",
            companions: Vec::new(),
            name,
            base_layer: base_layer.into(),
            segments,
            minimum_address,
            maximum_address,
            metadata,
        })
    }

    /// Name the format this layer was built for, which is what an image's
    /// description reports.
    pub fn of_kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }

    /// Note the module the class this layer stands for lives in, which a
    /// written-out configuration names in full.
    pub fn in_module(mut self, module: &'static str) -> Self {
        self.module = module;
        self
    }

    /// Note another layer this one was built from.
    pub fn alongside(mut self, layer: impl Into<String>) -> Self {
        self.companions.push(layer.into());
        self
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn base_layer(&self) -> &str {
        &self.base_layer
    }

    /// The segment covering `address`, if any.
    fn find_segment(&self, address: u64) -> Option<&Segment> {
        // partition_point gives the first segment starting after `address`, so
        // the candidate is the one immediately before it.
        let index = self.segments.partition_point(|s| s.offset <= address);
        if index == 0 {
            return None;
        }
        let candidate = &self.segments[index - 1];
        if candidate.contains(address) {
            Some(candidate)
        } else {
            None
        }
    }
}

impl DataLayer for SegmentedLayer {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn class_module(&self) -> &'static str {
        self.module
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        self.minimum_address
    }

    fn maximum_address(&self) -> u64 {
        self.maximum_address
    }

    fn mapped_regions(&self, _layers: &LayerContainer) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .map(|segment| (segment.offset, segment.length))
            .collect()
    }

    fn is_valid(&self, layers: &LayerContainer, offset: u64, length: u64) -> bool {
        match self.mapping(layers, offset, length, false) {
            Ok(entries) => entries
                .iter()
                .all(|entry| layers.is_valid(&entry.layer, entry.mapped_offset, entry.mapped_size)),
            Err(_) => false,
        }
    }

    fn dependencies(&self) -> Vec<String> {
        let mut layers = vec![self.base_layer.clone()];
        layers.extend(self.companions.iter().cloned());
        layers
    }

    fn mapping(
        &self,
        _layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let mut result = Vec::new();

        // A zero length is a request to translate a single address.
        if length == 0 {
            match self.find_segment(offset) {
                Some(segment) => {
                    let delta = offset - segment.offset;
                    result.push(MappingEntry {
                        offset,
                        size: 0,
                        mapped_offset: segment.mapped_offset + delta,
                        mapped_size: 0,
                        layer: self.base_layer.clone(),
                    });
                    return Ok(result);
                }
                None if ignore_errors => return Ok(result),
                None => {
                    return Err(VolatilityError::invalid_address(
                        &self.name,
                        offset,
                        "Offset is not within any segment",
                    ))
                }
            }
        }

        let mut current = offset;
        let end = offset.saturating_add(length);
        while current < end {
            match self.find_segment(current) {
                Some(segment) => {
                    let delta = current - segment.offset;
                    let available = segment.length - delta;
                    let chunk = available.min(end - current);
                    result.push(MappingEntry {
                        offset: current,
                        size: chunk,
                        mapped_offset: segment.mapped_offset + delta,
                        mapped_size: chunk,
                        layer: self.base_layer.clone(),
                    });
                    current += chunk;
                }
                None => {
                    if !ignore_errors {
                        return Err(VolatilityError::invalid_address(
                            &self.name,
                            current,
                            "Offset is not within any segment",
                        ));
                    }
                    // Skip to the start of the next segment, or give up if this
                    // address is past every segment.
                    let next = self
                        .segments
                        .iter()
                        .find(|s| s.offset > current)
                        .map(|s| s.offset);
                    match next {
                        Some(next) if next < end => current = next,
                        _ => break,
                    }
                }
            }
        }
        Ok(result)
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        read_via_mapping(self, layers, offset, length, pad)
    }

    fn with_bytes(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: usize,
        pad: bool,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        with_bytes_via_mapping(self, layers, offset, length, pad, visit)
    }

    fn write(&self, layers: &LayerContainer, offset: u64, data: &[u8]) -> Result<()> {
        let entries = self.mapping(layers, offset, data.len() as u64, false)?;
        for entry in entries {
            let start = (entry.offset - offset) as usize;
            let chunk = &data[start..start + entry.size as usize];
            layers.write(&entry.layer, entry.mapped_offset, chunk)?;
        }
        Ok(())
    }

    fn metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Lend the bytes of a range that falls inside a single region below.
///
/// A range spanning a gap or several segments has to be stitched together, and
/// then there is nothing to lend. That case reads as usual.
pub fn with_bytes_via_mapping<L: DataLayer + ?Sized>(
    layer: &L,
    layers: &LayerContainer,
    offset: u64,
    length: usize,
    pad: bool,
    visit: &mut dyn FnMut(&[u8]),
) -> Result<()> {
    if length > 0 {
        if let Ok(entries) = layer.mapping(layers, offset, length as u64, false) {
            if let [entry] = entries.as_slice() {
                if entry.offset == offset && entry.size as usize == length {
                    if let Ok(below) = layers.get(&entry.layer) {
                        return below.with_bytes(
                            layers,
                            entry.mapped_offset,
                            length,
                            pad,
                            visit,
                        );
                    }
                }
            }
        }
    }
    let data = layer.read(layers, offset, length, pad)?;
    visit(&data);
    Ok(())
}

/// Shared read implementation for translation layers: walk the mapping, pull
/// each region from the layer below, and stitch the pieces together.
///
/// Gaps are an error unless `pad` is set, in which case they become zeroes.
pub fn read_via_mapping<L: DataLayer + ?Sized>(
    layer: &L,
    layers: &LayerContainer,
    offset: u64,
    length: usize,
    pad: bool,
) -> Result<Vec<u8>> {
    let entries = layer.mapping(layers, offset, length as u64, pad)?;
    let mut output: Vec<u8> = Vec::with_capacity(length);
    let mut current = offset;

    for entry in entries {
        if entry.offset > current {
            if !pad {
                return Err(VolatilityError::invalid_address(
                    layer.name(),
                    current,
                    format!("Layer {} cannot map offset {current:#x}", layer.name()),
                ));
            }
            output.resize(output.len() + (entry.offset - current) as usize, 0);
            current = entry.offset;
        } else if entry.offset < current {
            return Err(VolatilityError::layer(
                layer.name(),
                "Mapping returned an overlapping element",
            ));
        }
        if entry.mapped_size > 0 {
            let chunk = layers.read(
                &entry.layer,
                entry.mapped_offset,
                entry.mapped_size as usize,
                pad,
            )?;
            output.extend_from_slice(&chunk);
        }
        current += entry.size;
    }

    // Anything the mapping did not cover is zero-filled so the caller always
    // receives exactly the length it asked for.
    output.resize(length, 0);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use std::sync::Arc;

    fn container() -> LayerContainer {
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", (0u8..=255).collect())));
        layers
    }

    #[test]
    fn segments_map_and_read_in_order() {
        let layers = container();
        // Expose base bytes 0x40.. at layer offset 0, and base 0x00.. at 0x100.
        let layer = SegmentedLayer::new(
            "seg",
            "base",
            vec![
                Segment::linear(0x100, 0x00, 0x10),
                Segment::linear(0x000, 0x40, 0x10),
            ],
            HashMap::new(),
        )
        .unwrap();

        assert_eq!(layer.minimum_address(), 0);
        assert_eq!(layer.maximum_address(), 0x10F);
        assert_eq!(layer.read(&layers, 0, 4, false).unwrap(), vec![0x40, 0x41, 0x42, 0x43]);
        assert_eq!(layer.read(&layers, 0x100, 4, false).unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn unmapped_gaps_error_unless_padding() {
        let layers = container();
        let layer = SegmentedLayer::new(
            "seg",
            "base",
            vec![Segment::linear(0, 0, 0x10), Segment::linear(0x20, 0x20, 0x10)],
            HashMap::new(),
        )
        .unwrap();

        assert!(layer.read(&layers, 0x0C, 0x20, false).is_err());
        let padded = layer.read(&layers, 0x0C, 0x18, true).unwrap();
        assert_eq!(&padded[0..4], &[0x0C, 0x0D, 0x0E, 0x0F]);
        // The 0x10..0x20 hole is zero-filled.
        assert_eq!(&padded[4..20], &[0u8; 16]);
        assert_eq!(&padded[20..24], &[0x20, 0x21, 0x22, 0x23]);
    }
}
