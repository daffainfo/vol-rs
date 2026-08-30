//! Identifying a Windows image and building its kernel virtual layer.
//!
//! The page directory base (DTB) is found by exploiting a quirk of how Windows
//! maps its own page tables: one entry of the top-level table points back at the
//! table itself, so that page tables are reachable through virtual memory. A
//! page containing exactly one such self-reference, at a plausible index, is
//! almost certainly the DTB.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use rayon::prelude::*;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::automagic::image_cache;
use crate::framework::automagic::pdbscan;
use crate::framework::automagic::DetectedOs;
use crate::framework::context::{Context, Module};
use crate::framework::layers::intel::{IntelLayer, WINDOWS_INTEL, WINDOWS_INTEL_32E, WINDOWS_INTEL_PAE};
use crate::framework::symbols::intermed::{create_table, SymbolFinder};

const PAGE_SIZE: usize = 0x1000;

/// One way of recognising a self-referential page table.
struct SelfReferenceTest {
    /// Width of a table entry.
    entry_size: usize,
    /// Bits of an entry that hold the physical address.
    address_mask: u64,
    /// Entry indices at which a self-reference is expected. Windows uses a
    /// fixed index on older versions and a randomised one on newer ones.
    valid_indices: &'static [usize],
    /// Bits that must never be set in a present entry. If they are, this page
    /// is not a page table at all.
    reserved_bits: u64,
    label: &'static str,
}

/// 64-bit Windows with a randomised self-reference index.
const TEST_64: SelfReferenceTest = SelfReferenceTest {
    entry_size: 8,
    address_mask: 0x3FFF_FFFF_F000,
    // Any index is possible once the location is randomised.
    valid_indices: &[],
    reserved_bits: 0x80,
    label: "Intel64",
};

/// Older 64-bit Windows, which always used index 0x1ED.
const TEST_64_LEGACY: SelfReferenceTest = SelfReferenceTest {
    entry_size: 8,
    address_mask: 0x3FFF_FFFF_F000,
    valid_indices: &[0x1ED],
    reserved_bits: 0x80,
    label: "Intel64",
};

/// 32-bit Windows without PAE, whose page directory self-references at 0x300.
const TEST_32: SelfReferenceTest = SelfReferenceTest {
    entry_size: 4,
    address_mask: 0xFFFF_F000,
    valid_indices: &[0x300],
    reserved_bits: 0,
    label: "Intel32",
};

impl SelfReferenceTest {
    /// Test one page. Returns the index of the self-referential entry.
    ///
    /// A genuine DTB self-references exactly once. A page that points at itself
    /// repeatedly is data that happens to contain the right bytes.
    fn check(&self, page: &[u8], page_address: u64) -> Option<usize> {
        if page.len() < PAGE_SIZE || page_address == 0 {
            return None;
        }

        let mut found: Option<usize> = None;
        let mut count = 0usize;

        for (index, chunk) in page.chunks_exact(self.entry_size).enumerate() {
            let mut buffer = [0u8; 8];
            buffer[..self.entry_size].copy_from_slice(chunk);
            let entry = u64::from_le_bytes(buffer);

            let present = entry & 1 != 0;
            // A present entry with reserved bits set means this is not a table.
            if present && self.reserved_bits != 0 && entry & self.reserved_bits != 0 {
                return None;
            }

            if present && (entry & self.address_mask) == page_address {
                count += 1;
                if count > 1 {
                    return None;
                }
                found = Some(index);
            }
        }

        let index = found?;
        if self.valid_indices.is_empty() || self.valid_indices.contains(&index) {
            Some(index)
        } else {
            None
        }
    }
}

/// Address ranges Windows is known to place the DTB in, searched before
/// falling back to a wider sweep.
///
/// Ordered cheapest-first: recent Windows clusters the DTB tightly, so most
/// images are identified in the first pass without scanning gigabytes.
const PRIORITY_RANGES: &[(u64, u64)] = &[
    (0x150000, 0x150000),
    (0x550000, 0x1A0000),
    (0x900000, 0x100000),
    (0x30000, 0x100_0000),
    (0xA00000, 0x500_0000),
];

/// Scan `layer` for a page directory base.
///
/// Returns the DTB and the layer configuration that matched it.
pub fn find_dtb(context: &Arc<Context>, layer_name: &str) -> Result<Option<(u64, &'static str)>> {
    let layer = context.layers.get(layer_name)?;
    let maximum = layer.maximum_address();

    // 64-bit is overwhelmingly the common case, so try it across every range
    // before considering the legacy 32-bit layouts.
    let attempts: [(&SelfReferenceTest, &str); 3] = [
        (&TEST_64, "WindowsIntel32e"),
        (&TEST_64_LEGACY, "WindowsIntel32e"),
        (&TEST_32, "WindowsIntel"),
    ];

    for (test, layer_kind) in attempts {
        for (start, length) in PRIORITY_RANGES {
            let end = (start + length).min(maximum);

            // Read a batch of pages at a time. A per-page read would spend all
            // its time in layer dispatch. The batches are laid out first so
            // they can be examined on every core at once, and the lowest
            // address that matches still wins, whichever core found it.
            let batch_size = 0x100 * PAGE_SIZE;
            let batches: Vec<u64> = (*start..end).step_by(batch_size).collect();

            let found = batches
                .par_iter()
                .filter_map(|address| {
                    let want = batch_size.min((end - address) as usize);
                    let data = layer.read(&context.layers, *address, want, true).ok()?;
                    data.chunks(PAGE_SIZE).enumerate().find_map(|(index, page)| {
                        let page_address = address + (index * PAGE_SIZE) as u64;
                        test.check(page, page_address).map(|_| page_address)
                    })
                })
                .min();

            if let Some(page_address) = found {
                log::debug!(
                    "Found a {} self-referential page table at {page_address:#x}",
                    test.label
                );
                return Ok(Some((page_address, layer_kind)));
            }
        }
    }
    Ok(None)
}

/// Detect a Windows image and build its kernel virtual layer.
pub fn detect(
    context: &Arc<Context>,
    physical_layer: &str,
    finder: &SymbolFinder,
) -> Result<Option<DetectedOs>> {
    // What a previous run learned about this exact file. Every one of those
    // answers is checked again below rather than believed.
    let remembered = context
        .config
        .get_string("automagic.image_identity")
        .and_then(|identity| image_cache::get(&identity))
        .filter(|facts| facts.operating_system == "windows");

    // Prefer a page directory base the image format stated outright, then one
    // a previous run found. Scanning is the fallback.
    let declared = context
        .config
        .get_int("automagic.declared_dtb")
        .filter(|dtb| *dtb > 0)
        .map(|dtb| (dtb as u64, "WindowsIntel32e"))
        .or_else(|| {
            remembered
                .as_ref()
                .filter(|facts| facts.dtb > 0)
                .map(|facts| (facts.dtb, "WindowsIntel32e"))
        });

    let found = match declared {
        Some(found) => Some(found),
        None => find_dtb(context, physical_layer)?,
    };
    let Some((dtb, layer_kind)) = found else {
        return Ok(None);
    };

    let config = match layer_kind {
        "WindowsIntel" => WINDOWS_INTEL,
        "WindowsIntelPAE" => WINDOWS_INTEL_PAE,
        _ => WINDOWS_INTEL_32E,
    };

    let layer_name = context.layers.free_name("layer_name");
    let layer = IntelLayer::new(&layer_name, physical_layer, dtb, config);
    context.layers.add(Arc::new(layer));

    context.config.set(
        "automagic.dtb",
        crate::framework::context::ConfigValue::Int(dtb as i64),
    );

    log::info!("Windows kernel layer '{layer_name}' built with DTB {dtb:#x}");

    // The kernel names the symbol file that describes it, so finding the kernel
    // and loading its symbols are one step. A kernel found before is looked for
    // where it was, which either answers at once or falls through to the
    // search that found it the first time.
    let started = std::time::Instant::now();
    let recalled = remembered.as_ref().and_then(|facts| {
        if facts.kernel_offset == 0 || facts.banner_offset == 0 {
            return None;
        }
        let found = pdbscan::kernel_at_known_record(
            context,
            &layer_name,
            facts.kernel_offset,
            facts.banner_offset,
        )?;
        (found.candidate.symbol_file_name() == facts.banner).then_some(found)
    });
    let found = match recalled {
        Some(found) => {
            log::debug!(
                "Kernel base {:#x} confirmed where it was last found",
                found.virtual_offset
            );
            Some(found)
        }
        None => pdbscan::find_kernel(context, &layer_name, physical_layer),
    };
    log::debug!("Finding the kernel took {:?}", started.elapsed());

    let Some(found) = found else {
        return Ok(Some(DetectedOs {
            layer_name,
            module_name: None,
        }));
    };

    let identity = found.candidate.symbol_file_name();
    let Some(location) = finder.find(&found.candidate.symbol_directory(), &identity) else {
        log::warn!(
            "This kernel is described by {}/{identity}, which is not installed",
            found.candidate.symbol_directory()
        );
        return Ok(Some(DetectedOs {
            layer_name,
            module_name: None,
        }));
    };
    log::info!(
        "Matched kernel {identity} to symbols at {}",
        location.display()
    );

    let started = std::time::Instant::now();
    let table_name = context.symbol_space.free_table_name("symbol_table_name");
    let table = create_table(&table_name, location.load()?);
    table.set_source(location.url());
    context.add_symbol_table(table);
    log::debug!("Loading the symbol table took {:?}", started.elapsed());

    // A PDB records each symbol's offset within the image, so the module
    // carries where that image is loaded and every symbol is read from there.
    let module_name = "kernel".to_string();
    context.add_module(Module::new(
        &module_name,
        &table_name,
        &layer_name,
        found.virtual_offset,
    ));
    log::info!(
        "Windows kernel module built at {:#x}",
        found.virtual_offset
    );

    // Write down where the kernel was, so the next run over the same file
    // looks there first. A run that only confirmed what was already written
    // has nothing to add.
    let already_known = remembered.as_ref().is_some_and(|facts| {
        facts.kernel_offset == found.virtual_offset
            && facts.banner_offset == found.candidate.signature_offset
            && facts.dtb == dtb
            && facts.banner == identity
    });
    if let Some(image_identity) = context
        .config
        .get_string("automagic.image_identity")
        .filter(|_| !already_known)
    {
        image_cache::put(
            &image_identity,
            &image_cache::ImageFacts {
                operating_system: "windows".to_string(),
                // Where the record naming the kernel's database was found,
                // which is what makes confirming it cheap next time.
                banner_offset: found.candidate.signature_offset,
                banner: identity.clone(),
                symbols: location.display(),
                task_offset: 0,
                physical_shift: 0,
                virtual_shift: 0,
                kernel_offset: found.virtual_offset,
                dtb,
            },
        );
    }

    Ok(Some(DetectedOs {
        layer_name,
        module_name: Some(module_name),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page whose entry at `index` points back at the page itself.
    fn self_referential_page(page_address: u64, index: usize, entry_size: usize) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_SIZE];
        let entry = page_address | 1;
        let at = index * entry_size;
        page[at..at + entry_size].copy_from_slice(&entry.to_le_bytes()[..entry_size]);
        page
    }

    #[test]
    fn recognises_a_single_self_reference() {
        let address = 0x1AB000u64;
        let page = self_referential_page(address, 0x1ED, 8);
        assert_eq!(TEST_64.check(&page, address), Some(0x1ED));
        assert_eq!(TEST_64_LEGACY.check(&page, address), Some(0x1ED));
    }

    #[test]
    fn rejects_pages_that_self_reference_more_than_once() {
        let address = 0x1AB000u64;
        let mut page = self_referential_page(address, 0x1ED, 8);
        // A second self-reference means this is data, not a page directory.
        let entry = (address | 1).to_le_bytes();
        page[0x100 * 8..0x100 * 8 + 8].copy_from_slice(&entry);
        assert_eq!(TEST_64.check(&page, address), None);
    }

    #[test]
    fn legacy_test_rejects_a_randomised_index() {
        let address = 0x1AB000u64;
        let page = self_referential_page(address, 0x100, 8);
        // The generic 64-bit test accepts any index. The legacy one does not.
        assert_eq!(TEST_64.check(&page, address), Some(0x100));
        assert_eq!(TEST_64_LEGACY.check(&page, address), None);
    }

    #[test]
    fn reserved_bits_disqualify_a_page() {
        let address = 0x1AB000u64;
        let mut page = self_referential_page(address, 0x1ED, 8);
        // Bit 7 is reserved in a PML4 entry. A present entry setting it means
        // this page is not a top-level table.
        page[0..8].copy_from_slice(&(0x81u64).to_le_bytes());
        assert_eq!(TEST_64.check(&page, address), None);
    }

    #[test]
    fn a_zero_address_page_is_never_a_dtb() {
        let page = self_referential_page(0, 0x1ED, 8);
        assert_eq!(TEST_64.check(&page, 0), None);
    }
}
