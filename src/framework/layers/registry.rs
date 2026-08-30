//! Windows registry hive layer.
//!
//! A hive in memory is not contiguous: it is a two-level directory of blocks,
//! and registry structures refer to each other by *cell index* rather than by
//! address. This layer turns cell indices into addresses in the layer holding
//! the hive, so the registry can be walked with ordinary object reads.
//!
//! A cell index packs three fields plus a flag:
//!
//! ```text
//!  31        30..21          20..12        11..0
//! [volatile][directory index][table index][offset within block]
//! ```
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::Context;
use crate::framework::layers::segmented::read_via_mapping;
use crate::framework::layers::{DataLayer, LayerContainer, MappingEntry};
use crate::framework::objects::Object;

/// Blocks are a page each, and a cell index's low twelve bits address within one.
const BLOCK_SIZE: u64 = 0x1000;

/// The two storage areas a hive has: the on-disk one and the volatile one that
/// exists only while the system is running.
const STORAGE_STABLE: u64 = 0;
const STORAGE_VOLATILE: u64 = 1;

/// Extract bits `[low, high]` inclusive.
fn mask_bits(value: u64, high: u32, low: u32) -> u64 {
    let high_mask = if high >= 63 {
        u64::MAX
    } else {
        (1u64 << (high + 1)) - 1
    };
    let low_mask = if low == 0 { 0 } else { (1u64 << low) - 1 };
    value & (high_mask ^ low_mask)
}

/// A registry hive, presented as a layer addressed by cell index.
pub struct RegistryHive {
    name: String,
    /// The layer the hive's blocks live in, normally the kernel virtual layer.
    base_layer: String,
    /// The `_CMHIVE` describing this hive.
    hive: Object,
    context: Arc<Context>,
    /// Highest valid cell index in each storage area.
    maximum_stable: u64,
    maximum_volatile: u64,
    /// The hive's name, as the kernel records it.
    hive_name: Option<String>,
    /// Cell index of the root key.
    root_cell: u64,
}

impl RegistryHive {
    /// Build a layer for the hive described by `hive` (a `_CMHIVE`).
    pub fn new(
        context: Arc<Context>,
        name: impl Into<String>,
        base_layer: impl Into<String>,
        hive: Object,
    ) -> Result<Self> {
        let name = name.into();
        let base_layer = base_layer.into();

        // The hive proper is nested inside the _CMHIVE. Older kernels name it
        // Hive, and the storage lengths bound each area's cell indices.
        let inner = hive.member("Hive").unwrap_or_else(|_| hive.clone());

        // A hive says so in its header. Anything else is not one, however it
        // came to be on the list.
        let signature = inner
            .member("Signature")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        if signature != 0xBEE0_BEE0 {
            return Err(VolatilityError::layer(
                &name,
                "Hive does not carry a valid signature",
            ));
        }

        let storage = inner.member("Storage")?;

        let maximum_stable = storage
            .index(STORAGE_STABLE)
            .and_then(|area| area.member("Length"))
            .and_then(|length| length.as_u64())
            .unwrap_or(0);
        let maximum_volatile = storage
            .index(STORAGE_VOLATILE)
            .and_then(|area| area.member("Length"))
            .and_then(|length| length.as_u64())
            .unwrap_or(0);

        if maximum_stable == 0 && maximum_volatile == 0 {
            return Err(VolatilityError::layer(
                &name,
                "Hive has no storage; it is probably not a valid _CMHIVE",
            ));
        }

        // The base block holds the root cell index. A hive whose base block is
        // paged out can still be walked if the root is recoverable elsewhere,
        // so a failure here is not fatal.
        let root_cell = inner
            .member("BaseBlock")
            .and_then(|block| block.dereference())
            .and_then(|block| block.member("RootCell"))
            .and_then(|cell| cell.as_u64())
            .unwrap_or(0x20);

        let hive_name = read_hive_name(&hive);

        // Windows 10 gave the registry a process of its own, and most hives
        // are mapped there rather than in kernel space, so their bins are read
        // through its page tables.
        let base_layer = registry_process_layer(&context, &hive).unwrap_or(base_layer);

        Ok(Self {
            name,
            base_layer,
            hive,
            context,
            maximum_stable,
            maximum_volatile,
            hive_name,
            root_cell,
        })
    }

    /// The hive's file name, as the kernel recorded it.
    pub fn hive_name(&self) -> Option<&str> {
        self.hive_name.as_deref()
    }

    /// Where the `_CMHIVE` itself lives.
    pub fn hive_offset(&self) -> u64 {
        self.hive.offset()
    }

    /// The cell index of the hive's root key.
    pub fn root_cell_offset(&self) -> u64 {
        self.root_cell
    }

    /// The last cell index the hive's stable store holds, which is what says
    /// whether a listed subkey belongs to this hive at all.
    pub fn maximum_index(&self) -> u64 {
        self.maximum_stable
    }

    fn maximum_for(&self, volatile: bool) -> u64 {
        if volatile {
            self.maximum_volatile
        } else {
            self.maximum_stable
        }
    }

    /// Translate a cell index into an address in the base layer.
    fn translate(&self, offset: u64) -> Result<u64> {
        let volatile = mask_bits(offset, 31, 31) >> 31 != 0;
        let index = offset & 0x7FFF_FFFF;

        if index > self.maximum_for(volatile) {
            return Err(VolatilityError::invalid_address(
                &self.name,
                offset,
                format!(
                    "Cell index {index:#x} is beyond the end of the {} store",
                    if volatile { "volatile" } else { "stable" }
                ),
            ));
        }

        let directory_index = mask_bits(offset, 30, 21) >> 21;
        let table_index = mask_bits(offset, 20, 12) >> 12;
        let sub_offset = mask_bits(offset, 11, 0);

        let inner = self
            .hive
            .member("Hive")
            .unwrap_or_else(|_| self.hive.clone());
        let storage = inner.member("Storage")?.index(volatile as u64)?;

        let table = storage
            .member("Map")?
            .dereference()
            .unwrap_or_else(|_| storage.member("Map").unwrap())
            .member("Directory")?
            .index(directory_index)?
            .dereference()?
            .member("Table")?
            .index(table_index)?;

        // The bin's address has flag bits in its low nibble that are not part
        // of the address, and the block sits at a recorded distance into the
        // bin. Older kernels name a single block address instead.
        let block = match (
            table.member("PermanentBinAddress").and_then(|v| v.as_u64()),
            table.member("BlockOffset").and_then(|v| v.as_u64()),
        ) {
            (Ok(bin), Ok(within)) => (bin & !0xF) + within,
            _ => table.member("BlockAddress")?.as_u64()?,
        };
        Ok(block + sub_offset)
    }

    /// The cell data at a cell index.
    ///
    /// Every cell is preceded by a four-byte size, so the data begins after it.
    pub fn cell(&self, cell_index: u64, type_name: &str) -> Result<Object> {
        let template = self.context.symbol_space.get_type(type_name)?;
        Ok(self
            .context
            .object_from_template(template, &self.name, cell_index + 4))
    }
}

/// Read the hive's file name from whichever member the kernel version uses.
fn read_hive_name(hive: &Object) -> Option<String> {
    for member in ["FileFullPath", "FileUserName", "HiveRootPath"] {
        if let Ok(field) = hive.member(member) {
            if let Ok(name) = crate::framework::objects::utility::unicode_string(&field) {
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

impl DataLayer for RegistryHive {
    fn address_mask(&self) -> u64 {
        // A cell index is a full 32-bit value whose top bit says which store
        // it belongs to. Narrowing it to the size of the hive would strip that
        // bit and send every volatile lookup into the stable store.
        0xFFFF_FFFF
    }

    fn kind(&self) -> &'static str {
        "RegistryHive"
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.registry"
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        0
    }

    fn maximum_address(&self) -> u64 {
        self.maximum_stable
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
        vec![self.base_layer.clone()]
    }

    fn mapping(
        &self,
        _layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let mut result = Vec::new();

        if length == 0 {
            match self.translate(offset) {
                Ok(mapped_offset) => result.push(MappingEntry {
                    offset,
                    size: 0,
                    mapped_offset,
                    mapped_size: 0,
                    layer: self.base_layer.clone(),
                }),
                Err(error) if !ignore_errors => return Err(error),
                Err(_) => {}
            }
            return Ok(result);
        }

        // Blocks are not contiguous, so a read is split at every block boundary
        // and each piece translated separately.
        let mut current = offset;
        let end = offset + length;
        while current < end {
            let block_offset = current & (BLOCK_SIZE - 1);
            let chunk = (BLOCK_SIZE - block_offset).min(end - current);

            match self.translate(current) {
                Ok(mapped_offset) => result.push(MappingEntry {
                    offset: current,
                    size: chunk,
                    mapped_offset,
                    mapped_size: chunk,
                    layer: self.base_layer.clone(),
                }),
                Err(error) => {
                    if !ignore_errors {
                        return Err(error);
                    }
                }
            }
            current += chunk;
        }
        Ok(result)
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        read_via_mapping(self, layers, offset, length, pad)
    }

    fn metadata(&self) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("os".to_string(), "Windows".to_string());
        if let Some(name) = &self.hive_name {
            metadata.insert("hive_name".to_string(), name.clone());
        }
        metadata
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_indices_split_into_their_fields() {
        // Volatile flag set, directory 3, table 5, offset 0x123.
        let index = (1u64 << 31) | (3 << 21) | (5 << 12) | 0x123;
        assert_eq!(mask_bits(index, 31, 31) >> 31, 1);
        assert_eq!(mask_bits(index, 30, 21) >> 21, 3);
        assert_eq!(mask_bits(index, 20, 12) >> 12, 5);
        assert_eq!(mask_bits(index, 11, 0), 0x123);
    }

    #[test]
    fn the_volatile_flag_does_not_leak_into_the_index() {
        let index = (1u64 << 31) | 0x1234;
        assert_eq!(index & 0x7FFF_FFFF, 0x1234);
    }
}

/// The address space the Registry process maps its hives into.
///
/// Before Windows 10 the hives lived in kernel space and there was no such
/// process. Then this returns nothing and the caller keeps the layer it had.
fn registry_process_layer(context: &Arc<Context>, hive: &Object) -> Option<String> {
    let kernel = context.module("kernel").ok()?;
    let processes = crate::framework::symbols::windows::list_processes(context, &kernel).ok()?;
    let physical = crate::framework::symbols::windows::poolscanner::physical_beneath(
        context,
        &kernel.layer_name,
    );

    for process in processes {
        // The registry's own process, which is a child of the system process.
        if process.image_file_name().ok().as_deref() != Some("Registry")
            || process.parent_pid().ok() != Some(4)
        {
            continue;
        }
        if let Ok(layer) = process.address_space(&physical) {
            log::debug!(
                "Reading hive {:#x} through the Registry process",
                hive.offset()
            );
            return Some(layer);
        }
    }
    None
}
