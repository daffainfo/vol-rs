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
use crate::framework::layers::DataLayer;
use crate::framework::symbols::intermed::{create_table, SymbolFinder};

const PAGE_SIZE: usize = 0x1000;

/// A generic DTB test which looks for a self-referential pointer at *any*
/// index within the page.
struct SelfReferenceTest {
    /// Width of a table entry.
    entry_size: usize,
    /// Bits of an entry that hold the physical address.
    address_mask: u64,
    /// Entry indices at which a self-reference is expected. Windows uses a
    /// fixed index on older versions and a randomised one on newer ones.
    valid_indices: IndexRange,
    /// Bits that must never be set in a present entry. If they are, this page
    /// is not a page table at all.
    reserved_bits: u64,
    /// The kind of layer a match builds.
    label: &'static str,
    /// The highest address that kind of layer admits, which bounds the
    /// pointers a real table may hold.
    maximum_address: u64,
}

/// Windows 10 and later, whose self-reference sits at a randomised index
/// within the upper half of the table.
const TEST_64: SelfReferenceTest = SelfReferenceTest {
    entry_size: 8,
    address_mask: 0x3FFF_FFFF_FFF000,
    // Upstream accepts any index from 0x100 up to but not including 0x1FF.
    valid_indices: IndexRange::Between(0x100, 0x1FF),
    reserved_bits: 0x80,
    label: "WindowsIntel32e",
    maximum_address: 0xFFFF_FFFF_FFFF,
};

/// Older 64-bit Windows, which always used index 0x1ED.
const TEST_64_LEGACY: SelfReferenceTest = SelfReferenceTest {
    entry_size: 8,
    address_mask: 0x3FFF_FFFF_FFF000,
    valid_indices: IndexRange::Only(0x1ED),
    reserved_bits: 0x80,
    label: "WindowsIntel32e",
    maximum_address: 0xFFFF_FFFF_FFFF,
};

/// 32-bit Windows without PAE, whose page directory self-references at 0x300.
const TEST_32: SelfReferenceTest = SelfReferenceTest {
    entry_size: 4,
    address_mask: 0xFFFF_F000,
    valid_indices: IndexRange::Only(0x300),
    reserved_bits: 0,
    label: "WindowsIntel",
    maximum_address: 0xFFFF_FFFF,
};

/// 32-bit Windows with PAE, whose page directory pointer table
/// self-references at index three. A match there is confirmed by the four
/// pages the table above it should map.
const TEST_PAE: SelfReferenceTest = SelfReferenceTest {
    entry_size: 8,
    address_mask: 0x3FFF_FFFF_FFF000,
    valid_indices: IndexRange::Only(0x3),
    reserved_bits: 0,
    label: "WindowsIntelPAE",
    maximum_address: 0xFFFF_FFFF,
};

/// Which indices a self-reference may sit at.
#[derive(Clone, Copy)]
enum IndexRange {
    /// One index and no other.
    Only(usize),
    /// From the first up to but not including the second, which is how
    /// upstream writes the range it accepts.
    Between(usize, usize),
}

impl IndexRange {
    fn accepts(&self, index: usize) -> bool {
        match self {
            IndexRange::Only(only) => index == *only,
            IndexRange::Between(first, last) => (*first..*last).contains(&index),
        }
    }
}

impl SelfReferenceTest {
    /// Test one page. Returns the index of the self-referential entry.
    ///
    /// For both Intel-32e, bit 7 is reserved (more are reserved in PAE), so if
    /// that's ever set we can move on, and the pointer must be valid. The DTB
    /// is extremely unlikely to refer back to itself, so the number of
    /// references should always be exactly 1: a page that points at itself more
    /// than once is data that happens to hold the right bytes.
    fn check(&self, page: &[u8], page_address: u64) -> Option<usize> {
        if page.len() < PAGE_SIZE || page_address == 0 {
            return None;
        }

        let mut found: Option<usize> = None;
        let mut count = 0usize;

        for (index, chunk) in page[..PAGE_SIZE].chunks_exact(self.entry_size).enumerate() {
            let entry = read_entry(chunk);
            let present = entry & 1 != 0;
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
        self.valid_indices.accepts(index).then_some(index)
    }

    /// Whether a page really looks like a page table.
    ///
    /// A table with almost nothing in it is a decoy that recent Windows
    /// leaves lying around, and one holding a pointer past the end of the
    /// address space its layer admits is not a table for that layer. Both
    /// checks are the ones upstream makes after a match.
    fn table_holds_up(&self, page: &[u8], limit: u64) -> bool {
        let mut valid = 0usize;
        let mut highest = 0u64;
        for chunk in page.chunks_exact(self.entry_size) {
            let entry = read_entry(chunk);
            // A large page needs more working out than this is worth, so only
            // ordinary present entries count.
            if entry & 1 == 0 || entry & 0x80 != 0 {
                continue;
            }
            valid += 1;
            highest = highest.max((entry ^ (entry & 0xFFF)) % self.maximum_address);
        }
        // Ten is the count upstream settles for.
        valid >= 10 && highest <= limit
    }
}

/// Whether a candidate address space really is a Windows one.
///
/// These addresses are at a fixed location: "The KUSER_SHARED_DATA structure is
/// a single page (4096 bytes) in memory that is mapped at a fixed, hardcoded
/// address in both kernel and user side of VAS." See
/// <https://www.microsoft.com/en-us/msrc/blog/2022/04/randomizing-the-kuser_shared_data-structure-on-windows>
///
/// This constraint verifies that `_KUSER_SHARED_DATA` is shared between user
/// and kernel address spaces. Where the user-side translation fails, which it
/// usually does, the `NtMajorVersion` field is read instead.
fn looks_like_windows(
    context: &Arc<Context>,
    layer: &crate::framework::layers::intel::IntelLayer,
) -> bool {
    /// Mapped at the same place in every Windows release.
    const USER_SPACE: u64 = 0x7FFE_0000;
    /// This field offset did not change across Windows versions. Instead of
    /// storing a complete struct definition only for this check, it is named
    /// here.
    const NT_MAJOR_OFFSET: u64 = 0x26C;
    const NT_MAJOR_VALIDS: [u32; 5] = [3, 4, 5, 6, 10];

    let kernel_space = if layer.config().bits_per_register == 64 {
        0xFFFF_F780_0000_0000u64
    } else {
        0xFFDF_0000
    };

    let kernel_address = layer
        .translate_single(&context.layers, kernel_space)
        .ok()
        .map(|(mapped, _)| mapped);
    // Translation of the user address usually fails, which upstream passes
    // over rather than treating as an answer.
    let user_address = layer
        .translate_single(&context.layers, USER_SPACE)
        .ok()
        .map(|(mapped, _)| mapped);
    if let (Some(kernel), Some(user)) = (kernel_address, user_address) {
        if kernel != 0 && kernel == user {
            return true;
        }
    }

    // Validate by reading the `_KUSER_SHARED_DATA.NtMajorVersion` field.
    if kernel_address.is_some() {
        if let Ok(data) = layer.read(&context.layers, kernel_space + NT_MAJOR_OFFSET, 4, true) {
            if let Ok(raw) = <[u8; 4]>::try_from(&data[..]) {
                if NT_MAJOR_VALIDS.contains(&u32::from_le_bytes(raw)) {
                    return true;
                }
            }
        }
    }

    false
}

/// Read a table entry of up to eight bytes.
fn read_entry(chunk: &[u8]) -> u64 {
    let mut buffer = [0u8; 8];
    let take = chunk.len().min(8);
    buffer[..take].copy_from_slice(&chunk[..take]);
    u64::from_le_bytes(buffer)
}

/// Which paging the page table at `dtb` is built for.
///
/// A page directory base that is already known still has to be matched against
/// the paging it was built for, since a 32-bit table read as a 64-bit one
/// translates nothing.
pub fn paging_at(context: &Arc<Context>, layer_name: &str, dtb: u64) -> Option<&'static str> {
    let layer = context.layers.get(layer_name).ok()?;
    let page = layer.read(&context.layers, dtb, PAGE_SIZE, true).ok()?;
    [&TEST_64, &TEST_64_LEGACY, &TEST_PAE, &TEST_32]
        .into_iter()
        .find_map(|test| test.check(&page, dtb).map(|_| test.label))
}

/// The two passes upstream makes over the image, each with its own tests and
/// its own places to look.
///
/// Where the DTB scan fails, upstream attempts a heuristic of checking for the
/// DTB within a specific range. New versions of windows, with randomized
/// self-referential pointers, appear to always load their dtb within a small
/// specific range (`0x1a0000` and `0x1b0000`), so instead we scan for all
/// self-referential pointers in that range, and ignore any that contain
/// multiple self-references (since the DTB is very unlikely to point to itself
/// more than once).
///
/// The tests are grouped by region so we only run over the data once.
const SEARCHES: &[(&[&SelfReferenceTest], &[(u64, u64)])] = &[
    (
        &[&TEST_64],
        &[
            (0x150000, 0x150000),
            (0x550000, 0x1A0000),
            (0x900000, 0x100000),
        ],
    ),
    (
        &[&TEST_PAE, &TEST_32, &TEST_64_LEGACY],
        &[(0x30000, 0x100_0000)],
    ),
];

/// Scans through all pages using DTB tests to determine a dtb offset and
/// architecture.
///
/// Returns the DTB and the kind of layer that matched it. Within a pass the
/// matches are considered in the order the tests are declared and then by
/// address, which is the order upstream considers them in.
pub fn find_dtb(context: &Arc<Context>, layer_name: &str) -> Result<Option<(u64, &'static str)>> {
    let layer = context.layers.get(layer_name)?;
    let maximum = layer.maximum_address();

    for (tests, ranges) in SEARCHES {
        // Every match in this pass, tagged with which test found it.
        let mut hits: Vec<(usize, u64)> = Vec::new();

        for (start, length) in *ranges {
            let end = (start + length).min(maximum);
            if *start >= end {
                continue;
            }

            // Read a batch of pages at a time. A per-page read would spend
            // all its time in layer dispatch.
            let batch_size = 0x100 * PAGE_SIZE;
            let batches: Vec<u64> = (*start..end).step_by(batch_size).collect();

            let mut found: Vec<(usize, u64)> = batches
                .par_iter()
                .flat_map_iter(|address| {
                    let want = batch_size.min((end - address) as usize);
                    let data = layer
                        .read(&context.layers, *address, want, true)
                        .unwrap_or_default();
                    let mut matched = Vec::new();
                    for (index, page) in data.chunks(PAGE_SIZE).enumerate() {
                        let page_address = address + (index * PAGE_SIZE) as u64;
                        for (which, test) in tests.iter().enumerate() {
                            if test.check(page, page_address).is_some() {
                                matched.push((which, page_address));
                            }
                        }
                    }
                    matched
                })
                .collect();
            hits.append(&mut found);
        }

        hits.sort_unstable();
        for (which, dtb) in hits {
            let test = tests[which];
            let Ok(page) = layer.read(&context.layers, dtb, PAGE_SIZE, false) else {
                continue;
            };
            if !test.table_holds_up(&page, maximum) {
                log::debug!("The table at {dtb:#x} does not hold up; ignoring it");
                continue;
            }
            // A match on the PAE test names the table four pages below it,
            // confirmed by the four pages that table should map.
            let dtb = match test.label {
                "WindowsIntelPAE" => match pae_top_page(context, layer_name, dtb) {
                    Some(top) => top,
                    None => continue,
                },
                _ => dtb,
            };
            // A page that passes the table tests still has to translate like a
            // Windows address space, which is what upstream builds a throwaway
            // layer to find out.
            let Some(config) = crate::framework::layers::intel::config_by_name(test.label) else {
                continue;
            };
            let probe = crate::framework::layers::intel::IntelLayer::new(
                "IntelHelper", layer_name, dtb, config,
            );
            if !looks_like_windows(context, &probe) {
                log::debug!(
                    "DTB {dtb:x} failed {} _KUSER_SHARED_DATA check, ignoring",
                    test.label
                );
                continue;
            }
            log::debug!("DTB was found at: {dtb:#x}");
            return Ok(Some((dtb, test.label)));
        }
    }
    Ok(None)
}

/// The page directory pointer table above a PAE self-reference.
///
/// Find the top page: it sits four pages below the match. The top page should
/// map to the next four pages after it, so what the page table is expected to
/// be is built and compared, with the page bits of the top level page map
/// masked off.
fn pae_top_page(context: &Arc<Context>, layer_name: &str, dtb: u64) -> Option<u64> {
    let top = dtb.checked_sub(0x4000)?;
    let data = context.layers.read(layer_name, top, 4 * 8, false).ok()?;
    for (index, chunk) in data.chunks_exact(8).enumerate() {
        let entry = read_entry(chunk);
        // Only the address bits are compared, which is what masking off the
        // low twelve and the top four amounts to.
        let expected = top + ((index as u64 + 1) * 0x1000);
        if entry & 0x0000_FFFF_FFFF_F000 != expected & 0x0000_FFFF_FFFF_F000 {
            return None;
        }
    }
    Some(top)
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
    let known = context
        .config
        .get_int("automagic.declared_dtb")
        .filter(|dtb| *dtb > 0)
        .map(|dtb| dtb as u64)
        .or_else(|| {
            remembered
                .as_ref()
                .filter(|facts| facts.dtb > 0)
                .map(|facts| facts.dtb)
        });
    // A known base still has to say which paging it is for, and one that
    // matches none of them is not believed.
    let declared = known.and_then(|dtb| {
        paging_at(context, physical_layer, dtb).map(|kind| (dtb, kind))
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
    let directory = found.candidate.symbol_directory();
    let location = match finder.find(&directory, &identity) {
        Some(location) => location,
        // Nothing describes this kernel yet, so the database Microsoft
        // publishes for it is fetched and turned into one.
        None => match build_symbols(&found.candidate, finder) {
            Ok(location) => location,
            Err(error) => {
                log::warn!(
                    "This kernel is described by {directory}/{identity}, \
                     which is not installed and could not be built: {error}"
                );
                return Ok(Some(DetectedOs {
                    layer_name,
                    module_name: None,
                }));
            }
        },
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

/// Build a symbol file for a kernel nothing yet describes.
///
/// Microsoft publishes a database for every binary it ships, named by the
/// identifier the binary carries. Fetching that database and converting it
/// gives the same description a symbol pack would, and it is written into the
/// symbol directory so the work is done only once.
fn build_symbols(
    candidate: &pdbscan::KernelCandidate,
    finder: &SymbolFinder,
) -> Result<crate::framework::symbols::intermed::SymbolLocation> {
    use crate::framework::symbols::intermed::SymbolLocation;
    use crate::framework::symbols::windows::{pdb, pdbconv};

    let identity = candidate.symbol_file_name();
    let database = candidate.pdb_name.trim_end_matches('\0').to_string();
    log::info!("Fetching {database} for {identity} from the symbol server");

    let raw = pdb::fetch(&database, &candidate.guid, candidate.age)?;
    let isf = pdbconv::to_isf(&raw, &database, &candidate.guid, candidate.age)?;
    let json = serde_json::to_vec(&isf)
        .map_err(|error| crate::error::VolatilityError::Other(format!("{error}")))?;

    // The first directory that can be written to is where it is kept, so a
    // later run finds it without fetching anything.
    let written = finder.base_paths().iter().find_map(|base| {
        let directory = base.join(candidate.symbol_directory());
        std::fs::create_dir_all(&directory).ok()?;
        let path = directory.join(format!("{identity}.json"));
        std::fs::write(&path, &json).ok()?;
        Some(path)
    });

    match written {
        Some(path) => {
            log::info!("Built {} from {database}", path.display());
            Ok(SymbolLocation::File(path))
        }
        None => Err(crate::error::VolatilityError::Other(
            "Nowhere to keep the symbols that were built".to_string(),
        )),
    }
}
