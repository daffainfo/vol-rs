//! AVML (Acquire Volatile Memory for Linux) layer.
//!
//! An AVML file is a series of ranges, each holding a snappy framed stream. The
//! layer records where every decompressed frame lives so reads can decompress
//! only the frames they touch.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::collections::{HashMap, HashSet};

use crate::error::{Result, VolatilityError};
use crate::framework::layers::segmented::Segment;
use crate::framework::layers::{DataLayer, LayerContainer, MappingEntry};

const MAGIC: u32 = 0x4C4D_5641;
const VERSION: u32 = 2;
/// magic, version, start, end, padding
const RANGE_HEADER_SIZE: u64 = 4 + 4 + 8 + 8 + 8;
/// Every snappy frame is preceded by a 4-byte type/length word, and data frames
/// carry a 4-byte CRC before their payload.
const FRAME_HEADER_LEN: usize = 4;
const CRC_LEN: usize = 4;

/// Verify the AVML magic at the start of the base layer.
pub fn check(layers: &LayerContainer, layer: &str) -> Result<()> {
    let header = layers.read(layer, 0, 8, false)?;
    let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if magic != MAGIC || version != VERSION {
        return Err(VolatilityError::layer(layer, "File not in AVML format"));
    }
    Ok(())
}

/// An AVML layer. Segments are non-linear: a compressed frame occupies fewer
/// bytes in the file than it does in the address space.
pub struct AvmlLayer {
    name: String,
    base_layer: String,
    segments: Vec<Segment>,
    /// File offsets of frames whose payload is snappy-compressed. Frames stored
    /// verbatim are absent and are copied straight through.
    compressed: HashSet<u64>,
    minimum_address: u64,
    maximum_address: u64,
}

impl AvmlLayer {
    pub fn build(
        layers: &LayerContainer,
        name: impl Into<String>,
        base_layer: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        let base_layer = base_layer.into();
        check(layers, &base_layer)?;

        let base_max = layers.get(&base_layer)?.maximum_address();
        let mut segments = Vec::new();
        let mut compressed = HashSet::new();
        let mut offset = 0u64;

        while offset + 4 < base_max {
            let header = layers.read(&base_layer, offset, RANGE_HEADER_SIZE as usize, false)?;
            let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
            let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if magic != MAGIC || version != VERSION {
                return Err(VolatilityError::layer(
                    &name,
                    "File not completely in AVML format",
                ));
            }
            let start = u64::from_le_bytes(header[8..16].try_into().unwrap());
            let end = u64::from_le_bytes(header[16..24].try_into().unwrap());

            let body_start = offset + RANGE_HEADER_SIZE;
            let available = (base_max - body_start).min(end - start);
            let chunk = layers.read(&base_layer, body_start, available as usize, true)?;

            let (frames, consumed) = read_snappy_frames(&chunk, end - start)?;
            for frame in &frames {
                let mapped_offset = body_start + frame.mapped_offset;
                segments.push(Segment {
                    offset: start + frame.offset,
                    mapped_offset,
                    length: frame.length,
                    mapped_length: frame.mapped_length,
                });
                if frame.compressed {
                    compressed.insert(mapped_offset);
                }
            }

            // Each range is followed by an 8-byte trailer.
            offset = body_start + consumed as u64 + 8;
        }

        if segments.is_empty() {
            return Err(VolatilityError::layer(&name, "No AVML segments found"));
        }

        segments.sort_unstable_by_key(|segment| segment.offset);
        let minimum_address = segments.first().unwrap().offset;
        let maximum_address = segments
            .iter()
            .map(|segment| segment.end())
            .max()
            .unwrap_or(0)
            .saturating_sub(1);

        Ok(Self {
            name,
            base_layer,
            segments,
            compressed,
            minimum_address,
            maximum_address,
        })
    }

    fn find_segment(&self, address: u64) -> Option<&Segment> {
        let index = self.segments.partition_point(|s| s.offset <= address);
        if index == 0 {
            return None;
        }
        let candidate = &self.segments[index - 1];
        candidate.contains(address).then_some(candidate)
    }
}

/// One snappy frame located within a range.
struct Frame {
    /// Offset of the decompressed bytes within the range.
    offset: u64,
    /// Offset of the stored bytes within the range.
    mapped_offset: u64,
    length: u64,
    mapped_length: u64,
    compressed: bool,
}

/// Walk a snappy framed stream, recording where each frame's payload lives
/// without decompressing it.
fn read_snappy_frames(data: &[u8], expected_length: u64) -> Result<(Vec<Frame>, usize)> {
    let mut frames = Vec::new();
    let mut decompressed_len: u64 = 0;
    let mut offset = 0usize;

    while decompressed_len < expected_length && offset + FRAME_HEADER_LEN <= data.len() {
        let header = u32::from_le_bytes(data[offset..offset + FRAME_HEADER_LEN].try_into().unwrap());
        let frame_type = (header & 0xFF) as u8;
        let frame_size = (header >> 8) as usize;
        let payload_start = offset + FRAME_HEADER_LEN;

        match frame_type {
            // Stream identifier.
            0xFF => {
                if data
                    .get(payload_start..payload_start + frame_size)
                    .map(|magic| magic != b"sNaPpY")
                    .unwrap_or(true)
                {
                    return Err(VolatilityError::Other(format!(
                        "Snappy stream header missing at offset {offset}"
                    )));
                }
            }
            // Compressed (0x00) or verbatim (0x01) data.
            0x00 | 0x01 => {
                let start = payload_start + CRC_LEN;
                let end = payload_start + frame_size;
                if end > data.len() {
                    break;
                }
                let payload = &data[start..end];
                let length = if frame_type == 0x00 {
                    snap::raw::decompress_len(payload).map_err(|e| {
                        VolatilityError::Other(format!("Invalid snappy frame: {e}"))
                    })? as u64
                } else {
                    payload.len() as u64
                };
                frames.push(Frame {
                    offset: decompressed_len,
                    mapped_offset: start as u64,
                    length,
                    mapped_length: (frame_size - CRC_LEN) as u64,
                    compressed: frame_type == 0x00,
                });
                decompressed_len += length;
            }
            // 0x02..=0x7F are reserved and must not be skipped.
            0x02..=0x7F => {
                return Err(VolatilityError::Other(format!(
                    "Unskippable snappy chunk of type {frame_type} at offset {offset}"
                )))
            }
            // 0x80..=0xFE are reserved but skippable.
            _ => {}
        }
        offset += FRAME_HEADER_LEN + frame_size;
    }

    Ok((frames, offset))
}

impl DataLayer for AvmlLayer {
    fn kind(&self) -> &'static str {
        "AVMLLayer"
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.avml"
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

    fn is_valid(&self, _layers: &LayerContainer, offset: u64, length: u64) -> bool {
        let end = offset.saturating_add(length.max(1) - 1);
        self.find_segment(offset).is_some() && self.find_segment(end).is_some()
    }

    fn dependencies(&self) -> Vec<String> {
        vec![self.base_layer.clone()]
    }

    fn is_linear(&self) -> bool {
        false
    }

    fn mapping(
        &self,
        _layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let mut result = Vec::new();
        let end = offset.saturating_add(length.max(1));
        let mut current = offset;

        while current < end {
            match self.find_segment(current) {
                Some(segment) => {
                    // A compressed frame must be fetched whole, so the mapping
                    // covers the entire segment even for a partial read.
                    let delta = current - segment.offset;
                    let chunk = (segment.length - delta).min(end - current);
                    result.push(MappingEntry {
                        offset: segment.offset,
                        size: segment.length,
                        mapped_offset: segment.mapped_offset,
                        mapped_size: segment.mapped_length,
                        layer: self.base_layer.clone(),
                    });
                    current += chunk;
                }
                None => {
                    if !ignore_errors {
                        return Err(VolatilityError::invalid_address(
                            &self.name,
                            current,
                            "Offset is not within any AVML segment",
                        ));
                    }
                    match self.segments.iter().find(|s| s.offset > current) {
                        Some(next) if next.offset < end => current = next.offset,
                        _ => break,
                    }
                }
            }
        }
        Ok(result)
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        // Decompress whole frames, then slice out the requested window.
        let entries = self.mapping(layers, offset, length as u64, pad)?;
        let mut output = vec![0u8; length];

        for entry in entries {
            let raw = layers.read(
                &entry.layer,
                entry.mapped_offset,
                entry.mapped_size as usize,
                pad,
            )?;
            let decoded = if self.compressed.contains(&entry.mapped_offset) {
                snap::raw::Decoder::new()
                    .decompress_vec(&raw)
                    .map_err(|e| VolatilityError::layer(&self.name, format!("Snappy error: {e}")))?
            } else {
                raw
            };

            // Intersect the frame's address range with the requested range.
            let frame_start = entry.offset;
            let frame_end = frame_start + decoded.len() as u64;
            let copy_start = frame_start.max(offset);
            let copy_end = frame_end.min(offset + length as u64);
            if copy_start >= copy_end {
                continue;
            }
            let source = (copy_start - frame_start) as usize;
            let destination = (copy_start - offset) as usize;
            let count = (copy_end - copy_start) as usize;
            output[destination..destination + count]
                .copy_from_slice(&decoded[source..source + count]);
        }
        Ok(output)
    }

    fn metadata(&self) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("os".to_string(), "Linux".to_string());
        metadata
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
