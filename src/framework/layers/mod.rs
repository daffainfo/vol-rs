//! Layers: sources of data, and translations applied on top of them.
//!
//! A `DataLayer` is a leaf that directly holds data and does not translate it,
//! exposing raw bytes from a file or a buffer. It directly accesses a data
//! source and exposes it within volatility.
//!
//! A translation layer provides a layer that translates or transforms another
//! layer or layers, and always depends on another layer, typically translating
//! offsets in a virtual offset space into a smaller physical offset space:
//! virtual-to-physical paging, decompression of a crash dump, and so on.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod physical;
pub mod segmented;
pub mod intel;
pub mod elf;
pub mod lime;
pub mod crash;
pub mod vmware;
pub mod qemu;
pub mod avml;
pub mod scanners;
pub mod registry;
pub mod xen;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Result, VolatilityError};

/// One contiguous region of this layer's address space and where it lands in
/// a lower layer.
///
/// `ignore_errors` will provide all available maps with gaps, but their total
/// length may not add up to the requested length. This allows translation
/// layers to provide maps of contiguous regions in one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    /// Offset within *this* layer.
    pub offset: u64,
    /// Length of the region within this layer.
    pub size: u64,
    /// Offset within the lower layer.
    pub mapped_offset: u64,
    /// Length of the region within the lower layer. This differs from `size`
    /// only for non-linear layers (compressed dumps, for instance).
    pub mapped_size: u64,
    /// Name of the lower layer the region lands in.
    pub layer: String,
}

/// The interface every layer implements.
///
/// Methods take `&LayerContainer` rather than holding a back-reference to the
/// context, which keeps layers free of reference cycles and lets the container
/// own them behind an `Arc`.
pub trait DataLayer: Send + Sync {
    /// The layer's name within the container.
    fn name(&self) -> &str;

    /// Returns the minimum valid address of the space.
    fn minimum_address(&self) -> u64;

    /// Returns the maximum valid address of the space.
    fn maximum_address(&self) -> u64;

    /// The regions of this layer that actually hold data.
    ///
    /// A layer built from a capture file has gaps between its segments. Scanning
    /// has to skip them: reading a gap as zeroes can fabricate a match that
    /// spans the hole.
    fn mapped_regions(&self, _layers: &LayerContainer) -> Vec<(u64, u64)> {
        vec![(
            self.minimum_address(),
            self.maximum_address() - self.minimum_address() + 1,
        )]
    }

    /// Returns a mask which encapsulates all the active bits of an address for
    /// this layer.
    ///
    /// A 4-level Intel layer addresses 48 bits, so the sign-extension in the
    /// top 16 bits of a kernel pointer is not part of the address. Masking it
    /// off is what makes an object's offset comparable to a pointer's value,
    /// and is why tools report `0x8ad54085d180` rather than
    /// `0xffff8ad54085d180`.
    fn address_mask(&self) -> u64 {
        let maximum = self.maximum_address();
        if maximum == 0 {
            return 0;
        }
        // ceil(log2(maximum)): one less bit when the maximum is itself a power
        // of two, since that value needs no bit above the one it sets.
        let bits = if maximum.is_power_of_two() {
            maximum.trailing_zeros()
        } else {
            u64::BITS - maximum.leading_zeros()
        };
        if bits >= u64::BITS {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    /// Returns a boolean based on whether the entire chunk of data (from
    /// offset to length) is valid or not.
    ///
    /// # Args
    ///
    /// * `offset` - The address to start determining whether bytes are
    ///   readable/valid
    /// * `length` - The number of bytes from offset of which to test the
    ///   validity
    fn is_valid(&self, layers: &LayerContainer, offset: u64, length: u64) -> bool;

    /// Reads an offset for length bytes and returns the bytes read.
    ///
    /// If there is a fault of any kind (such as a page fault), an error will be
    /// returned unless `pad` is set, in which case the read errors will be
    /// replaced by null characters.
    ///
    /// # Args
    ///
    /// * `offset` - The offset at which to begin reading within the layer
    /// * `length` - The number of bytes to read within the layer
    /// * `pad` - Whether errors should be raised or bad bytes replaced with
    ///   null characters
    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>>;

    /// Writes a chunk of data at offset.
    ///
    /// Any unavailable sections in the underlying bases will cause an error.
    /// Note: writes are not guaranteed atomic, therefore some data may have
    /// been written, even if an error is returned. Layers backed by read-only
    /// sources may ignore this, warning once.
    fn write(&self, _layers: &LayerContainer, _offset: u64, _data: &[u8]) -> Result<()> {
        Err(VolatilityError::layer(
            self.name(),
            "This layer does not support writing",
        ))
    }

    /// A list of other layer names required by this layer.
    ///
    /// Note: data layers must never define other layers, so a leaf returns an
    /// empty list.
    fn dependencies(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns a sorted iterable of (offset, sublength, mapped_offset,
    /// mapped_length, layer) mappings.
    ///
    /// Leaf layers map onto themselves. `ignore_errors` will provide all
    /// available maps with gaps, but their total length may not add up to the
    /// requested length. This allows translation layers to provide maps of
    /// contiguous regions in one layer.
    fn mapping(
        &self,
        _layers: &LayerContainer,
        offset: u64,
        length: u64,
        _ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        Ok(vec![MappingEntry {
            offset,
            size: length,
            mapped_offset: offset,
            mapped_size: length,
            layer: self.name().to_string(),
        }])
    }

    /// Walk a range's mapping a piece at a time, without merging the pieces.
    ///
    /// [`mapping`](Self::mapping) joins neighbouring pieces into one entry,
    /// which is what a caller reading bytes wants. A caller asking which page
    /// each address came from needs the pieces as the paging structures gave
    /// them, and a walk over the whole of an address space is too large to
    /// hold in memory, so the pieces are handed over one at a time.
    fn walk_mapping(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
        on_entry: &mut dyn FnMut(&MappingEntry),
    ) -> Result<()> {
        for entry in self.mapping(layers, offset, length, ignore_errors)? {
            on_entry(&entry);
        }
        Ok(())
    }

    /// The name of the class the reference implementation would build for this
    /// layer, which some plugins report as part of an image's description.
    fn kind(&self) -> &'static str {
        "DataLayer"
    }

    /// The module that class lives in, which a written-out configuration names
    /// in full so the layer can be rebuilt from it.
    fn class_module(&self) -> &'static str {
        "volatility3.framework.interfaces.layers"
    }

    /// The class's full name, as a configuration file spells it.
    fn class_path(&self) -> String {
        format!("{}.{}", self.class_module(), self.kind())
    }

    /// Show the bytes at `offset` to `visit`, without copying them when the
    /// layer can lend a view of storage it already holds.
    ///
    /// Scanning reads the whole image in large chunks, and copying each chunk
    /// out of a memory-mapped file costs about as much as examining it. A layer
    /// that cannot lend its bytes (because the range spans a gap, or because it
    /// has to be assembled) falls back to reading them, so the caller sees no
    /// difference beyond the speed.
    fn with_bytes(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: usize,
        pad: bool,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        let data = self.read(layers, offset, length, pad)?;
        visit(&data);
        Ok(())
    }

    /// Metadata this layer publishes directly (architecture, OS, and so on).
    fn metadata(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Page size, for layers that have a meaningful one.
    fn page_size(&self) -> Option<u64> {
        None
    }

    /// Differentiates linearly mapped layers, where `a => b` implies that
    /// `a + c => b + c`.
    ///
    /// Scanners use this to read large contiguous blocks. Upstream redefines
    /// `read` for such layers for speed reasons, so that it does not call a
    /// processing method per page.
    fn is_linear(&self) -> bool {
        true
    }

    /// Support for downcasting to concrete layer types.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Holds the layers making up a memory image and dispatches reads by name.
#[derive(Default)]
pub struct LayerContainer {
    layers: RwLock<HashMap<String, Arc<dyn DataLayer>>>,
    /// The names in the order they were added.
    ///
    /// Upstream holds its layers in a `Dict`, which iterates in insertion
    /// order, and that order is observable: `layerwriter` with no layer named
    /// writes out the last one that is not a view of another, so a stack whose
    /// names happen to sort differently would write a different layer.
    order: RwLock<Vec<String>>,
}

impl LayerContainer {
    pub fn new() -> Self {
        Self {
            layers: RwLock::new(HashMap::new()),
            order: RwLock::new(Vec::new()),
        }
    }

    /// Add a layer, replacing any existing layer of the same name.
    pub fn add(&self, layer: Arc<dyn DataLayer>) {
        let name = layer.name().to_string();
        // Re-adding under a name already taken keeps that name's original
        // place, which is what replacing a value in a dict does.
        if self
            .layers
            .write()
            .unwrap()
            .insert(name.clone(), layer)
            .is_none()
        {
            self.order.write().unwrap().push(name);
        }
    }

    /// Fetch a layer by name.
    pub fn get(&self, name: &str) -> Result<Arc<dyn DataLayer>> {
        self.layers
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| VolatilityError::layer(name, "Layer does not exist"))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.layers.read().unwrap().contains_key(name)
    }

    /// Move a layer to a different name.
    ///
    /// A plugin that asks for a layer by name has the one automagic built
    /// registered under the name it asked for.
    pub fn rename(&self, from: &str, to: &str) {
        let mut layers = self.layers.write().unwrap();
        if let Some(layer) = layers.remove(from) {
            layers.insert(to.to_string(), layer);
            // The new name takes the old one's place in the order, so a rename
            // does not move the layer to the end of the listing.
            let mut order = self.order.write().unwrap();
            order.retain(|held| held != to);
            match order.iter_mut().find(|held| *held == from) {
                Some(held) => *held = to.to_string(),
                None => order.push(to.to_string()),
            }
        }
    }

    pub fn remove(&self, name: &str) {
        self.layers.write().unwrap().remove(name);
        self.order.write().unwrap().retain(|held| held != name);
    }

    /// All layer names currently registered, in the order they were added.
    pub fn names(&self) -> Vec<String> {
        self.order.read().unwrap().clone()
    }

    /// A layer name not currently in use, derived from `prefix`.
    pub fn free_name(&self, prefix: &str) -> String {
        let guard = self.layers.read().unwrap();
        if !guard.contains_key(prefix) {
            return prefix.to_string();
        }
        for index in 1.. {
            let candidate = format!("{prefix}_{index}");
            if !guard.contains_key(&candidate) {
                return candidate;
            }
        }
        unreachable!()
    }

    /// Read from a named layer.
    pub fn read(&self, layer: &str, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        let target = self.get(layer)?;
        target.read(self, offset, length, pad)
    }

    /// Write to a named layer.
    pub fn write(&self, layer: &str, offset: u64, data: &[u8]) -> Result<()> {
        let target = self.get(layer)?;
        target.write(self, offset, data)
    }

    /// The address mask of a layer, or an all-ones mask if it is unknown.
    pub fn address_mask(&self, layer: &str) -> u64 {
        self.get(layer).map(|l| l.address_mask()).unwrap_or(u64::MAX)
    }

    pub fn is_valid(&self, layer: &str, offset: u64, length: u64) -> bool {
        match self.get(layer) {
            Ok(target) => target.is_valid(self, offset, length),
            Err(_) => false,
        }
    }
}

/// Take a list of (start, length) sections and coalesce any adjacent sections,
/// clamping them to the layer's addressable range.
pub fn coalesce_sections(
    sections: &[(u64, u64)],
    minimum: u64,
    maximum: u64,
) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = sections.to_vec();
    sorted.sort_unstable();

    let mut result: Vec<(u64, u64)> = Vec::new();
    let mut position: u64 = 0;
    for (start, length) in sorted {
        if !result.is_empty() && start <= position {
            let (initial_start, _) = result.pop().unwrap();
            let end = start.saturating_add(length).max(position);
            result.push((initial_start, end - initial_start));
        } else {
            result.push((start, length));
        }
        position = start.saturating_add(length);
    }

    // Trim anything falling outside the layer's valid addresses.
    result
        .into_iter()
        .filter_map(|(start, length)| {
            let end = start.saturating_add(length);
            if end <= minimum || start > maximum {
                return None;
            }
            let new_start = start.max(minimum);
            let new_end = end.min(maximum.saturating_add(1));
            if new_end <= new_start {
                None
            } else {
                Some((new_start, new_end - new_start))
            }
        })
        .collect()
}
