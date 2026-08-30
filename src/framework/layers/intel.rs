//! Intel IA-32 / IA-32e virtual address translation.
//!
//! One implementation covers every variant by describing the paging structure
//! as data: how many bits each level consumes, whether that level may hold a
//! large page, and how wide entries and addresses are. Windows and Linux each
//! reinterpret a handful of entry bits, which is captured by `Flavour`.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

use crate::error::{AddressFault, Result, VolatilityError};
use crate::framework::layers::segmented::read_via_mapping;
use crate::framework::layers::{DataLayer, LayerContainer, MappingEntry};

/// Bit positions within a page table entry that the translation logic cares
/// about.
const PAGE_BIT_PRESENT: u32 = 0;
/// Page Size Extension: this entry maps a large page rather than a table.
const PAGE_BIT_PSE: u32 = 7;
/// Linux marks `PROT_NONE` pages present-but-inaccessible with this bit.
const PAGE_BIT_PROTNONE: u32 = 8;
/// Page Attribute Table bit, which sits inside the address field of a large page.
const PAGE_BIT_PAT_LARGE: u32 = 12;

const PAGE_PRESENT: u64 = 1 << PAGE_BIT_PRESENT;
const PAGE_PSE: u64 = 1 << PAGE_BIT_PSE;
const PAGE_PROTNONE: u64 = 1 << PAGE_BIT_PROTNONE;
const PAGE_PAT_LARGE: u64 = 1 << PAGE_BIT_PAT_LARGE;

/// Windows stores extra state in the "available" bits of a non-present entry.
const PAGE_BIT_PROTOTYPE: u32 = 10;
const PAGE_BIT_TRANSITION: u32 = 11;

/// One level of the paging hierarchy.
#[derive(Debug, Clone, Copy)]
pub struct PagingLevel {
    /// Human-readable name, used in fault messages.
    pub name: &'static str,
    /// How many bits of the virtual address this level indexes with.
    pub size: u32,
    /// Whether an entry at this level may terminate translation with a large page.
    pub large_page: bool,
}

const fn level(name: &'static str, size: u32, large_page: bool) -> PagingLevel {
    PagingLevel { name, size, large_page }
}

/// OS-specific reinterpretation of page table entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// Plain Intel semantics: an entry is valid if the present bit is set.
    Generic,
    /// Windows additionally treats transition pages (not prototype) as valid,
    /// and encodes swapped pages in non-present entries.
    Windows,
    /// Linux treats `PROT_NONE` pages as present and inverts their entries.
    Linux,
}

/// Everything that distinguishes one Intel layer variant from another.
#[derive(Debug, Clone)]
pub struct IntelConfig {
    /// Width of a page table entry in bytes (4 for legacy 32-bit, else 8).
    pub entry_size: usize,
    /// log2 of the page size. 12 for the 4KiB pages every variant uses.
    pub page_size_in_bits: u32,
    /// Width of the architecture's registers, which bounds virtual addresses.
    pub bits_per_register: u32,
    /// MAXPHYADDR as defined by Intel: the number of significant physical
    /// address bits, *not* the maximum physical address.
    pub maxphyaddr: u32,
    /// Number of significant virtual address bits.
    pub maxvirtaddr: u32,
    /// The paging levels, outermost first.
    pub structure: &'static [PagingLevel],
    pub flavour: Flavour,
    pub architecture: &'static str,
    /// The name the reference implementation gives this configuration's class.
    pub class_name: &'static str,
    pub pae: bool,
    /// Bit offset used when decoding a Windows swap entry into a swap offset.
    pub swap_bit_offset: u32,
}

/// The IA-32 two-level paging structure with 4-byte entries.
pub const INTEL: IntelConfig = IntelConfig {
    entry_size: 4,
    page_size_in_bits: 12,
    bits_per_register: 32,
    maxphyaddr: 32,
    maxvirtaddr: 32,
    structure: &[level("page directory", 10, true), level("page table", 10, false)],
    flavour: Flavour::Generic,
    architecture: "Intel32",
    class_name: "Intel",
    pae: false,
    swap_bit_offset: 12,
};

/// Physical Address Extension: three levels, 8-byte entries, 40-bit physical
/// addresses over a 32-bit virtual space.
pub const INTEL_PAE: IntelConfig = IntelConfig {
    entry_size: 8,
    page_size_in_bits: 12,
    bits_per_register: 32,
    maxphyaddr: 40,
    maxvirtaddr: 32,
    structure: &[
        level("page directory pointer", 2, false),
        level("page directory", 9, true),
        level("page table", 9, false),
    ],
    flavour: Flavour::Generic,
    architecture: "Intel32",
    class_name: "IntelPAE",
    pae: true,
    swap_bit_offset: 32,
};

/// IA-32e (long mode): four levels over a 48-bit canonical virtual space.
pub const INTEL_32E: IntelConfig = IntelConfig {
    entry_size: 8,
    page_size_in_bits: 12,
    bits_per_register: 64,
    maxphyaddr: 52,
    maxvirtaddr: 48,
    structure: &[
        level("page map level 4", 9, false),
        level("page directory pointer", 9, true),
        level("page directory", 9, true),
        level("page table", 9, false),
    ],
    flavour: Flavour::Generic,
    architecture: "Intel64",
    class_name: "Intel32e",
    pae: false,
    swap_bit_offset: 32,
};

/// Windows flavours. The 64-bit variant narrows MAXPHYADDR to 45 bits because
/// Windows repurposes a high bit of the PFN field for pages in transition.
pub const WINDOWS_INTEL: IntelConfig = IntelConfig {
    flavour: Flavour::Windows,
    class_name: "WindowsIntel",
    swap_bit_offset: 12,
    ..INTEL
};
pub const WINDOWS_INTEL_PAE: IntelConfig = IntelConfig {
    flavour: Flavour::Windows,
    class_name: "WindowsIntelPAE",
    swap_bit_offset: 32,
    ..INTEL_PAE
};
pub const WINDOWS_INTEL_32E: IntelConfig = IntelConfig {
    flavour: Flavour::Windows,
    class_name: "WindowsIntel32e",
    maxphyaddr: 45,
    swap_bit_offset: 32,
    ..INTEL_32E
};

/// Linux flavours. The 64-bit variant uses a 46-bit physical mask, which
/// matches what the kernel used before 4.17 and still gives correct results for
/// `PROT_NONE` pages on later kernels.
pub const LINUX_INTEL: IntelConfig = IntelConfig {
    flavour: Flavour::Linux,
    ..INTEL
};
pub const LINUX_INTEL_PAE: IntelConfig = IntelConfig {
    flavour: Flavour::Linux,
    ..INTEL_PAE
};
pub const LINUX_INTEL_32E: IntelConfig = IntelConfig {
    flavour: Flavour::Linux,
    maxphyaddr: 46,
    ..INTEL_32E
};

/// Look up an architecture by the name used in layer configurations.
pub fn config_by_name(name: &str) -> Option<IntelConfig> {
    Some(match name {
        "Intel" | "intel" => INTEL,
        "IntelPAE" | "intel-pae" => INTEL_PAE,
        "Intel32e" | "intel-32e" => INTEL_32E,
        "WindowsIntel" => WINDOWS_INTEL,
        "WindowsIntelPAE" => WINDOWS_INTEL_PAE,
        "WindowsIntel32e" => WINDOWS_INTEL_32E,
        "LinuxIntel" => LINUX_INTEL,
        "LinuxIntelPAE" => LINUX_INTEL_PAE,
        "LinuxIntel32e" => LINUX_INTEL_32E,
        _ => return None,
    })
}

/// Extract bits `[low_bit, high_bit]` inclusive from `value`.
fn mask_bits(value: u64, high_bit: u32, low_bit: u32) -> u64 {
    let high_mask = if high_bit >= 63 {
        u64::MAX
    } else {
        (1u64 << (high_bit + 1)) - 1
    };
    let low_mask = if low_bit == 0 {
        0
    } else if low_bit >= 64 {
        u64::MAX
    } else {
        (1u64 << low_bit) - 1
    };
    value & (high_mask ^ low_mask)
}

/// The result of walking the page tables for one address.
struct TranslatedEntry {
    entry: u64,
    /// Bits of the virtual address still unconsumed when the walk finished,
    /// which gives the size of the page that was found.
    position: u32,
}

/// An Intel paging layer over a physical base layer.
pub struct IntelLayer {
    name: String,
    base_layer: String,
    swap_layers: Vec<String>,
    page_map_offset: u64,
    config: IntelConfig,
    /// Precomputed constants.
    initial_position: u32,
    initial_entry: u64,
    index_shift: u32,
    canonical_prefix: u64,
    address_mask: u64,
    metadata: HashMap<String, String>,
    /// Page tables read during translation, keyed by physical base address.
    /// `None` records a table that was read but rejected as bogus.
    table_cache: Mutex<LruCache<u64, Option<Vec<u8>>>>,
    /// Completed translations, keyed by page-aligned virtual address.
    entry_cache: Mutex<LruCache<u64, std::result::Result<(u64, u32), ()>>>,
}

/// Name the layers holding swap, in the order their indices refer to them.
pub fn set_swap_layers(layers: Vec<String>) {
    *IntelLayer::configured_swap().write().unwrap() = layers;
}

/// The swap layers a new address space will consult.
pub fn swap_layers() -> Vec<String> {
    IntelLayer::configured_swap().read().unwrap().clone()
}

impl IntelLayer {
    pub fn new(
        name: impl Into<String>,
        base_layer: impl Into<String>,
        page_map_offset: u64,
        config: IntelConfig,
    ) -> Self {
        // Any swap files the run was given back every address space, since a
        // page swapped out of one process is read the same way as any other.
        Self::with_swap(name, base_layer, page_map_offset, config, swap_layers())
    }

    /// The swap layers every address space should consult.
    fn configured_swap() -> &'static std::sync::RwLock<Vec<String>> {
        static SWAP: std::sync::OnceLock<std::sync::RwLock<Vec<String>>> =
            std::sync::OnceLock::new();
        SWAP.get_or_init(|| std::sync::RwLock::new(Vec::new()))
    }

    pub fn with_swap(
        name: impl Into<String>,
        base_layer: impl Into<String>,
        page_map_offset: u64,
        config: IntelConfig,
        swap_layers: Vec<String>,
    ) -> Self {
        let initial_position = config.maxvirtaddr.min(config.bits_per_register) - 1;
        // OR in the present bit so the root of the walk always looks valid.
        let initial_entry = mask_bits(page_map_offset, initial_position, 0) | 1;
        let index_shift = (config.entry_size as f64).log2().ceil() as u32;
        let canonical_prefix = mask_bits(
            if config.bits_per_register >= 64 {
                u64::MAX
            } else {
                (1u64 << config.bits_per_register) - 1
            },
            config.bits_per_register.saturating_sub(1),
            config.maxvirtaddr,
        );

        let maximum_address = (1u64 << config.maxvirtaddr) - 1;
        let address_mask = (1u64 << (64 - maximum_address.leading_zeros())) - 1;

        let mut metadata = HashMap::new();
        metadata.insert("architecture".to_string(), config.architecture.to_string());
        metadata.insert("mapped".to_string(), "true".to_string());
        if config.pae {
            metadata.insert("pae".to_string(), "true".to_string());
        }

        Self {
            name: name.into(),
            base_layer: base_layer.into(),
            swap_layers,
            page_map_offset,
            config,
            initial_position,
            initial_entry,
            index_shift,
            canonical_prefix,
            address_mask,
            metadata,
            table_cache: Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
            entry_cache: Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
        }
    }

    pub fn page_map_offset(&self) -> u64 {
        self.page_map_offset
    }

    pub fn base_layer_name(&self) -> &str {
        &self.base_layer
    }

    pub fn config(&self) -> &IntelConfig {
        &self.config
    }

    pub fn page_shift(&self) -> u32 {
        self.config.page_size_in_bits
    }

    pub fn page_size(&self) -> u64 {
        1 << self.config.page_size_in_bits
    }

    /// Page mask, limited to the register width so the complement stays inside
    /// the architecture's pointer size.
    fn page_mask(&self) -> u64 {
        let register_mask = self.register_mask();
        !(self.page_size() - 1) & register_mask
    }

    fn register_mask(&self) -> u64 {
        if self.config.bits_per_register >= 64 {
            u64::MAX
        } else {
            (1u64 << self.config.bits_per_register) - 1
        }
    }

    fn physical_mask(&self) -> u64 {
        if self.config.maxphyaddr >= 64 {
            u64::MAX
        } else {
            (1u64 << self.config.maxphyaddr) - 1
        }
    }

    /// Sign-extend an address into its canonical form on architectures whose
    /// virtual space is narrower than their registers.
    pub fn canonicalize(&self, address: u64) -> u64 {
        if self.config.bits_per_register <= self.config.maxvirtaddr {
            address & self.address_mask
        } else if address < (1u64 << (self.config.maxvirtaddr - 1)) {
            address
        } else {
            mask_bits(address, self.config.maxvirtaddr, 0) | self.canonical_prefix
        }
    }

    /// Undo canonicalization, bringing a sign-extended address back into range.
    pub fn decanonicalize(&self, address: u64) -> u64 {
        if address < (1u64 << (self.config.maxvirtaddr - 1)) {
            address
        } else {
            address ^ self.canonical_prefix
        }
    }

    /// Whether an entry marks a usable page, per the OS flavour.
    fn page_is_valid(&self, entry: u64) -> bool {
        match self.config.flavour {
            Flavour::Generic => entry & PAGE_PRESENT != 0,
            // Windows keeps transition pages resident and readable, but a
            // prototype entry points elsewhere and cannot be followed here.
            Flavour::Windows => {
                entry & PAGE_PRESENT != 0
                    || (entry & (1 << PAGE_BIT_TRANSITION) != 0
                        && entry & (1 << PAGE_BIT_PROTOTYPE) == 0)
            }
            // Linux keeps PROT_NONE pages mapped but marked not-present.
            Flavour::Linux => {
                let flags = entry & !self.pte_pfn_mask() & self.register_mask();
                flags & (PAGE_PRESENT | PAGE_PROTNONE) != 0
            }
        }
    }

    fn pte_pfn_mask(&self) -> u64 {
        self.page_mask() & self.physical_mask()
    }

    /// Extract the page frame number from a page table entry.
    fn pte_pfn(&self, entry: u64) -> u64 {
        match self.config.flavour {
            Flavour::Linux => {
                // A PROT_NONE entry has its bits inverted by the kernel to keep
                // it from being confused with a genuine mapping. Undo that.
                let needs_invert = entry != 0 && entry & PAGE_PRESENT == 0;
                let pfn = if needs_invert {
                    entry ^ self.register_mask()
                } else {
                    entry
                };
                (pfn & self.pte_pfn_mask()) >> self.page_shift()
            }
            _ => mask_bits(entry, self.config.maxphyaddr - 1, 0) >> self.page_shift(),
        }
    }

    fn page_is_dirty(entry: u64) -> bool {
        entry & (1 << 6) != 0
    }

    /// Read a page table, rejecting tables whose entries are all identical.
    ///
    /// Windows 10 and later map large stretches of unused virtual memory to a
    /// single physical page. Treating such a table as absent costs a rare false
    /// negative but saves scans from walking millions of duplicate mappings.
    fn get_valid_table(&self, layers: &LayerContainer, base_address: u64) -> Option<Vec<u8>> {
        if let Some(cached) = self.table_cache.lock().unwrap().get(&base_address) {
            return cached.clone();
        }

        let table = layers
            .read(&self.base_layer, base_address, self.page_size() as usize, false)
            .ok();

        let table = table.and_then(|table| {
            let first = &table[..self.config.entry_size];
            let all_same = table
                .chunks_exact(self.config.entry_size)
                .all(|chunk| chunk == first);
            if all_same {
                None
            } else {
                Some(table)
            }
        });

        self.table_cache
            .lock()
            .unwrap()
            .put(base_address, table.clone());
        table
    }

    fn read_entry(&self, table: &[u8], index: usize) -> u64 {
        let start = index << self.index_shift;
        let bytes = &table[start..start + self.config.entry_size];
        let mut value = [0u8; 8];
        value[..self.config.entry_size].copy_from_slice(bytes);
        u64::from_le_bytes(value)
    }

    /// Walk the paging structures for a page-aligned virtual address.
    fn translate_entry(&self, layers: &LayerContainer, page_address: u64) -> Result<TranslatedEntry> {
        if let Some(cached) = self.entry_cache.lock().unwrap().get(&page_address) {
            return match cached {
                Ok((entry, position)) => Ok(TranslatedEntry {
                    entry: *entry,
                    position: *position,
                }),
                Err(()) => Err(VolatilityError::paged(
                    &self.name,
                    page_address,
                    self.config.page_size_in_bits,
                    0,
                    "Cached page fault",
                )),
            };
        }

        let result = self.translate_entry_uncached(layers, page_address);
        // Only successes and plain faults are worth caching. A fault carries its
        // own detail which we do not want to lose, so it is recorded as a bare
        // miss and recomputed if the detail is needed.
        let cache_value = match &result {
            Ok(t) => Ok((t.entry, t.position)),
            Err(_) => Err(()),
        };
        if cache_value.is_ok() {
            self.entry_cache.lock().unwrap().put(page_address, cache_value);
        }
        result
    }

    fn translate_entry_uncached(
        &self,
        layers: &LayerContainer,
        page_address: u64,
    ) -> Result<TranslatedEntry> {
        let mut position = self.initial_position;
        let mut entry = self.initial_entry;

        if (page_address & self.address_mask) > self.maximum_address() {
            return Err(VolatilityError::paged(
                &self.name,
                page_address,
                position + 1,
                entry,
                "Entry outside virtual address range",
            ));
        }

        for level in self.config.structure {
            if !self.page_is_valid(entry) {
                return Err(VolatilityError::paged(
                    &self.name,
                    page_address,
                    position + 1,
                    entry,
                    format!("Page fault at entry {entry:#x} in table {}", level.name),
                ));
            }

            // The entry's address field points at the next table.
            let base_address = mask_bits(
                entry,
                self.config.maxphyaddr - 1,
                level.size + self.index_shift,
            );

            let table = self.get_valid_table(layers, base_address).ok_or_else(|| {
                VolatilityError::paged(
                    &self.name,
                    page_address,
                    position + 1,
                    entry,
                    format!("Page fault at entry {entry:#x} in table {}", level.name),
                )
            })?;

            let start = position;
            position -= level.size;
            let index = (mask_bits(page_address, start, position + 1) >> (position + 1)) as usize;
            entry = self.read_entry(&table, index);

            if level.large_page && entry & PAGE_PSE != 0 {
                // A large page terminates the walk. The PAT bit sits inside what
                // would otherwise be address bits, so clear it before use.
                if entry & PAGE_PAT_LARGE != 0 {
                    entry -= PAGE_PAT_LARGE;
                }
                break;
            }
        }

        Ok(TranslatedEntry { entry, position })
    }

    /// Translate a virtual address to `(physical offset, page size, layer)`.
    fn translate(&self, layers: &LayerContainer, offset: u64) -> Result<(u64, u64, String)> {
        let result = self.translate_entry(layers, offset & self.page_mask());

        let translated = match result {
            Ok(translated) => translated,
            Err(error) => return self.handle_swap(offset, error),
        };

        if !self.page_is_valid(translated.entry) {
            let error = VolatilityError::paged(
                &self.name,
                offset,
                translated.position + 1,
                translated.entry,
                format!("Page fault at entry {:#x} in page entry", translated.entry),
            );
            return self.handle_swap(offset, error);
        }

        let pfn = self.pte_pfn(translated.entry);
        let page_offset = mask_bits(offset, translated.position, 0);
        let page = (pfn << self.page_shift()) | page_offset;

        Ok((page, 1u64 << (translated.position + 1), self.base_layer.clone()))
    }

    /// Windows encodes swapped-out pages in otherwise invalid entries. Decode
    /// one if this is a Windows layer and the entry has the right shape.
    fn handle_swap(&self, offset: u64, error: VolatilityError) -> Result<(u64, u64, String)> {
        if self.config.flavour != Flavour::Windows {
            return Err(error);
        }
        let (entry, invalid_bits) = match &error {
            VolatilityError::InvalidAddress {
                fault: AddressFault::Paged { entry, invalid_bits },
                ..
            } => (*entry, *invalid_bits),
            _ => return Err(error),
        };

        let transition = entry & (1 << PAGE_BIT_TRANSITION) != 0;
        let prototype = entry & (1 << PAGE_BIT_PROTOTYPE) != 0;
        let page_file = entry & (1 << 7) != 0;
        let valid = entry & PAGE_PRESENT != 0;
        // Which of the configured swap layers holds the page.
        let swap_index = ((entry >> 1) & 0xF) as usize;

        let is_swapped = !transition && !prototype && !valid && page_file;
        if !is_swapped || (entry >> self.config.swap_bit_offset) == 0 {
            return Err(error);
        }

        let swap_offset = (entry >> self.config.swap_bit_offset) << invalid_bits;
        if let Some(swap_layer) = self.swap_layers.get(swap_index) {
            return Ok((swap_offset, 1u64 << invalid_bits, swap_layer.clone()));
        }

        Err(VolatilityError::InvalidAddress {
            layer: self.name.clone(),
            address: offset,
            message: format!("Page has been swapped out to offset {swap_offset:#x}"),
            fault: AddressFault::Swapped {
                invalid_bits,
                entry,
                swap_offset,
            },
        })
    }

    /// Whether the page backing `offset` is marked dirty.
    pub fn is_dirty(&self, layers: &LayerContainer, offset: u64) -> bool {
        self.translate_entry(layers, offset & self.page_mask())
            .map(|t| Self::page_is_dirty(t.entry))
            .unwrap_or(false)
    }

    /// Translate a single address, returning the physical offset and the layer
    /// it lands in.
    pub fn translate_single(&self, layers: &LayerContainer, offset: u64) -> Result<(u64, String)> {
        let (mapped, _, layer) = self.translate(layers, offset)?;
        Ok((mapped, layer))
    }
}

impl DataLayer for IntelLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        self.config.class_name
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.intel"
    }

    fn minimum_address(&self) -> u64 {
        0
    }

    fn maximum_address(&self) -> u64 {
        (1u64 << self.config.maxvirtaddr) - 1
    }

    fn is_valid(&self, layers: &LayerContainer, offset: u64, length: u64) -> bool {
        match self.mapping(layers, offset, length, false) {
            Ok(entries) => entries
                .iter()
                .all(|entry| layers.is_valid(&entry.layer, entry.mapped_offset, 1)),
            Err(_) => false,
        }
    }

    fn dependencies(&self) -> Vec<String> {
        let mut deps = vec![self.base_layer.clone()];
        deps.extend(self.swap_layers.iter().cloned());
        deps
    }

    fn mapped_regions(&self, layers: &LayerContainer) -> Vec<(u64, u64)> {
        // Only the pages the page tables actually describe are worth scanning.
        // The address space itself is far too large to walk byte by byte.
        let length = self.maximum_address() - self.minimum_address() + 1;
        match self.mapping(layers, self.minimum_address(), length, true) {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| (entry.offset, entry.size))
                .collect(),
            Err(_) => vec![(self.minimum_address(), length)],
        }
    }

    fn mapping(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let raw = self.mapping_raw(layers, offset, length, ignore_errors)?;
        Ok(coalesce_mappings(raw))
    }

    fn walk_mapping(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
        on_entry: &mut dyn FnMut(&MappingEntry),
    ) -> Result<()> {
        // The pieces are handed over as the paging structures produced them,
        // one per page or large page, rather than joined together: a caller
        // walking an entire address space cannot hold the joined list, and
        // wants to know which page each address came from anyway.
        self.walk_mapping_raw(layers, offset, length, ignore_errors, on_entry)
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        read_via_mapping(self, layers, offset, length, pad)
    }

    fn write(&self, layers: &LayerContainer, offset: u64, data: &[u8]) -> Result<()> {
        let entries = self.mapping(layers, offset, data.len() as u64, false)?;
        for entry in entries {
            let start = (entry.offset - offset) as usize;
            layers.write(
                &entry.layer,
                entry.mapped_offset,
                &data[start..start + entry.size as usize],
            )?;
        }
        Ok(())
    }

    fn metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }

    fn page_size(&self) -> Option<u64> {
        Some(self.page_size())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl IntelLayer {
    /// Produce the per-page mappings for a range, before adjacent entries are
    /// merged.
    fn mapping_raw(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let mut result = Vec::new();
        self.walk_mapping_raw(layers, offset, length, ignore_errors, &mut |entry| {
            result.push(entry.clone())
        })?;
        Ok(result)
    }

    /// The per-page pieces of a range's mapping, handed over one at a time.
    fn walk_mapping_raw(
        &self,
        layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
        on_entry: &mut dyn FnMut(&MappingEntry),
    ) -> Result<()> {

        if length == 0 {
            match self.translate(layers, offset) {
                Ok((mapped_offset, _, layer)) => {
                    if !layers.is_valid(&layer, mapped_offset, 1) {
                        if ignore_errors {
                            return Ok(());
                        }
                        return Err(VolatilityError::invalid_address(
                            &layer,
                            mapped_offset,
                            "Translated address is not valid in the base layer",
                        ));
                    }
                    on_entry(&MappingEntry {
                        offset,
                        size: 0,
                        mapped_offset,
                        mapped_size: 0,
                        layer,
                    });
                }
                Err(error) => {
                    if !ignore_errors {
                        return Err(error);
                    }
                }
            }
            return Ok(());
        }

        let mut offset = offset;
        let mut length = length;
        while length > 0 {
            let mut skip_mask: Option<u64> = None;
            let outcome = match self.translate(layers, offset) {
                Ok((chunk_offset, page_size, layer)) => {
                    let chunk_size = (page_size - (offset % page_size)).min(length);
                    if layers.is_valid(&layer, chunk_offset, chunk_size) {
                        Ok((chunk_offset, chunk_size, layer))
                    } else {
                        // Translation is contiguous across the chunk, so a failure
                        // here means the whole chunk is absent and can be skipped.
                        skip_mask = Some(chunk_size - 1);
                        Err(VolatilityError::invalid_address(
                            &layer,
                            chunk_offset,
                            "Mapped address is not valid in the base layer",
                        ))
                    }
                }
                Err(error) => Err(error),
            };

            match outcome {
                Ok((chunk_offset, chunk_size, layer)) => {
                    on_entry(&MappingEntry {
                        offset,
                        size: chunk_size,
                        mapped_offset: chunk_offset,
                        mapped_size: chunk_size,
                        layer,
                    });
                    length -= chunk_size;
                    offset += chunk_size;
                }
                Err(error) => {
                    if !ignore_errors {
                        return Err(error);
                    }
                    // Jump past the whole unmapped region. When the fault came
                    // from a specific paging level we know exactly how much of
                    // the address space it covers.
                    let mask = skip_mask.unwrap_or_else(|| {
                        let bits = error.invalid_bits().unwrap_or(self.config.page_size_in_bits);
                        (1u64 << bits) - 1
                    });
                    let advance = mask + 1 - (offset & mask);
                    if advance >= length {
                        break;
                    }
                    length -= advance;
                    offset += advance;
                }
            }
        }
        Ok(())
    }
}

/// Merge mapping entries that are contiguous in both address spaces and land in
/// the same layer.
pub fn coalesce_mappings(entries: Vec<MappingEntry>) -> Vec<MappingEntry> {
    let mut result: Vec<MappingEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        match result.last_mut() {
            Some(last)
                if last.offset + last.size == entry.offset
                    && last.mapped_offset + last.mapped_size == entry.mapped_offset
                    && last.layer == entry.layer =>
            {
                last.size += entry.size;
                last.mapped_size += entry.mapped_size;
            }
            _ => result.push(entry),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use std::sync::Arc;

    /// Build a minimal 4-level page table mapping one virtual page.
    fn build_32e_image(virtual_address: u64, physical_page: u64) -> (Vec<u8>, u64) {
        let mut memory = vec![0u8; 0x100000];
        let pml4 = 0x1000u64;
        let pdpt = 0x2000u64;
        let pd = 0x3000u64;
        let pt = 0x4000u64;

        let write_entry = |memory: &mut Vec<u8>, table: u64, index: u64, value: u64| {
            let position = (table + index * 8) as usize;
            memory[position..position + 8].copy_from_slice(&value.to_le_bytes());
        };

        let pml4_index = (virtual_address >> 39) & 0x1FF;
        let pdpt_index = (virtual_address >> 30) & 0x1FF;
        let pd_index = (virtual_address >> 21) & 0x1FF;
        let pt_index = (virtual_address >> 12) & 0x1FF;

        write_entry(&mut memory, pml4, pml4_index, pdpt | 1);
        write_entry(&mut memory, pdpt, pdpt_index, pd | 1);
        write_entry(&mut memory, pd, pd_index, pt | 1);
        write_entry(&mut memory, pt, pt_index, physical_page | 1);

        // Vary a second entry in each table so the duplicate-table heuristic
        // does not reject them.
        write_entry(&mut memory, pml4, (pml4_index + 1) % 512, 0xAB);
        write_entry(&mut memory, pdpt, (pdpt_index + 1) % 512, 0xAB);
        write_entry(&mut memory, pd, (pd_index + 1) % 512, 0xAB);
        write_entry(&mut memory, pt, (pt_index + 1) % 512, 0xAB);

        (memory, pml4)
    }

    #[test]
    fn translates_a_four_level_mapping() {
        let virtual_address = 0x7FFF_1234_5000u64;
        let physical_page = 0x8000u64;
        let (mut memory, pml4) = build_32e_image(virtual_address, physical_page);
        memory[physical_page as usize..physical_page as usize + 4]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", memory)));
        let layer = IntelLayer::new("virtual", "base", pml4, INTEL_32E);

        let (mapped, _) = layer.translate_single(&layers, virtual_address).unwrap();
        assert_eq!(mapped, physical_page);
        assert_eq!(
            layer.read(&layers, virtual_address, 4, false).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn unmapped_addresses_fault() {
        let (memory, pml4) = build_32e_image(0x1000, 0x8000);
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", memory)));
        let layer = IntelLayer::new("virtual", "base", pml4, INTEL_32E);

        let error = layer.read(&layers, 0x7FFF_0000_0000, 4, false).unwrap_err();
        assert!(error.is_invalid_address());
    }

    #[test]
    fn canonical_addresses_round_trip() {
        let layer = IntelLayer::new("virtual", "base", 0x1000, INTEL_32E);
        let kernel_address = 0xFFFF_F800_0000_0000u64;
        assert_eq!(layer.canonicalize(layer.decanonicalize(kernel_address)), kernel_address);
    }

    #[test]
    fn mask_bits_extracts_inclusive_ranges() {
        assert_eq!(mask_bits(0xFF, 3, 0), 0x0F);
        assert_eq!(mask_bits(0xFF, 7, 4), 0xF0);
        assert_eq!(mask_bits(u64::MAX, 63, 60), 0xF000_0000_0000_0000);
    }
}
