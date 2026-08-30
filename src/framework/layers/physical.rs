//! Leaf layers that expose raw bytes: an in-memory buffer and a file on disk.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use memmap2::Mmap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::{DataLayer, LayerContainer};

/// A layer backed by bytes held in memory. Useful for tests and for wrapping
/// small extracted regions.
pub struct BufferLayer {
    name: String,
    buffer: Vec<u8>,
}

impl BufferLayer {
    pub fn new(name: impl Into<String>, buffer: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            buffer,
        }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl DataLayer for BufferLayer {
    fn kind(&self) -> &'static str {
        "BufferDataLayer"
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.physical"
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        0
    }

    fn maximum_address(&self) -> u64 {
        (self.buffer.len() as u64).saturating_sub(1)
    }

    fn is_valid(&self, _layers: &LayerContainer, offset: u64, length: u64) -> bool {
        if self.buffer.is_empty() {
            return false;
        }
        let end = match offset.checked_add(length.max(1) - 1) {
            Some(end) => end,
            None => return false,
        };
        offset <= self.maximum_address() && end <= self.maximum_address()
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        // Padding fills the holes a translation leaves. A layer of bytes has
        // no holes, so reading past its end is a failure however the caller
        // asked for it.
        let _ = pad;
        if !self.is_valid(layers, offset, length as u64) {
            // Report the first unreadable address so callers can see how far
            // the layer did extend.
            let invalid = if offset <= self.maximum_address() {
                self.maximum_address() + 1
            } else {
                offset
            };
            return Err(VolatilityError::invalid_address(
                &self.name,
                invalid,
                "Offset outside of the buffer boundaries",
            ));
        }
        let start = offset as usize;
        Ok(self.buffer[start..start + length].to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A layer backed by a file, memory-mapped for fast random access.
pub struct FileLayer {
    name: String,
    location: PathBuf,
    map: Mmap,
    write_warned: AtomicBool,
}

impl FileLayer {
    /// Open `location` read-only and map it into memory.
    pub fn new(name: impl Into<String>, location: impl AsRef<Path>) -> Result<Self> {
        let location = location.as_ref().to_path_buf();
        let file = File::open(&location).map_err(|e| {
            VolatilityError::Io(format!("Could not open {}: {e}", location.display()))
        })?;
        // Safety: the mapping is read-only and the layer keeps it alive for its
        // whole lifetime. A concurrent truncation of the backing file would be
        // undefined behaviour, which matches the usual assumption that a memory
        // image is not modified underneath the analysis.
        let map = unsafe { Mmap::map(&file) }.map_err(|e| {
            VolatilityError::Io(format!("Could not map {}: {e}", location.display()))
        })?;
        Ok(Self {
            name: name.into(),
            location,
            map,
            write_warned: AtomicBool::new(false),
        })
    }

    pub fn location(&self) -> &Path {
        &self.location
    }

    /// The whole file as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.map
    }
}

impl DataLayer for FileLayer {
    fn kind(&self) -> &'static str {
        "FileLayer"
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.physical"
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        0
    }

    fn maximum_address(&self) -> u64 {
        (self.map.len() as u64).saturating_sub(1)
    }

    fn is_valid(&self, _layers: &LayerContainer, offset: u64, length: u64) -> bool {
        if self.map.is_empty() {
            return false;
        }
        let end = match offset.checked_add(length.max(1) - 1) {
            Some(end) => end,
            None => return false,
        };
        offset <= self.maximum_address() && end <= self.maximum_address()
    }

    fn with_bytes(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: usize,
        pad: bool,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        // The file is already in memory. A range that lies inside it needs no
        // copy at all.
        if length > 0 && self.is_valid(layers, offset, length as u64) {
            let start = offset as usize;
            visit(&self.map[start..start + length]);
            return Ok(());
        }
        let data = self.read(layers, offset, length, pad)?;
        visit(&data);
        Ok(())
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        // Padding fills the holes a translation leaves. A file has no holes,
        // so reading past its end is a failure however the caller asked for
        // it.
        let _ = pad;
        if !self.is_valid(layers, offset, length as u64) {
            let invalid = if offset <= self.maximum_address() {
                self.maximum_address() + 1
            } else {
                offset
            };
            return Err(VolatilityError::invalid_address(
                &self.name,
                invalid,
                "Offset outside of the file boundaries",
            ));
        }
        let start = offset as usize;
        Ok(self.map[start..start + length].to_vec())
    }

    fn write(&self, _layers: &LayerContainer, _offset: u64, _data: &[u8]) -> Result<()> {
        // Images are opened read-only. Warn once rather than on every write so a
        // plugin that writes speculatively does not flood the log.
        if !self.write_warned.swap(true, Ordering::Relaxed) {
            log::warn!("Attempted to write to unwritable layer: {}", self.name);
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_layer_reads_and_bounds_check() {
        let layers = LayerContainer::new();
        let layer = BufferLayer::new("base", (0u8..=255).collect());
        assert_eq!(layer.maximum_address(), 255);
        assert_eq!(layer.read(&layers, 0, 4, false).unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(layer.read(&layers, 252, 4, false).unwrap(), vec![252, 253, 254, 255]);
        assert!(layer.read(&layers, 254, 4, false).is_err());
    }

    #[test]
    fn buffer_layer_refuses_to_read_past_the_end_even_when_padding() {
        // Padding fills in what a higher layer knows is absent. Running off
        // the end of the image itself is a different thing, and the layer says
        // so rather than inventing zeroes.
        let layers = LayerContainer::new();
        let layer = BufferLayer::new("base", vec![1, 2, 3]);
        assert!(layer.read(&layers, 1, 4, true).is_err());
        assert_eq!(layer.read(&layers, 1, 2, true).unwrap(), vec![2, 3]);
    }
}
