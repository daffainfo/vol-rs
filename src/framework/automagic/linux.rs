//! Identifying a Linux image.
//!
//! Linux is recognised by its version banner, which also names the exact kernel
//! build and so selects the matching symbol file. The page tables are then found
//! through the `swapper_pg_dir` symbol, whose virtual address is converted to a
//! physical one using the kernel's fixed virtual/physical offset.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::automagic::image_cache;
use crate::framework::automagic::symbol_finder::{first_known_banner, BannerIndex, FoundBanner};
use crate::framework::layers::scanners::{scan_layer_until, RegExScanner};
use crate::framework::automagic::DetectedOs;
use crate::framework::context::{Context, Module};
use crate::framework::layers::intel::{
    INTEL, INTEL_32E, INTEL_PAE, IntelLayer, LINUX_INTEL, LINUX_INTEL_32E,
};
use crate::framework::symbols::intermed::{create_table, SymbolFinder};

/// The banner prefix every Linux kernel writes.
const BANNER_PREFIX: &str = "Linux version ";

/// The signature of `init_task`'s command name, which is how the idle task is
/// found in physical memory.
const SWAPPER_SIGNATURE: &str = r"swapper(/0|\x00\x00)\x00\x00\x00\x00\x00\x00";

/// Detect a Linux image, load its symbols and build the kernel layer.
///
/// Bails out by default unless it can stack properly, and never stacks on top
/// of an intel layer.
pub fn detect(
    context: &Arc<Context>,
    physical_layer: &str,
    finder: &SymbolFinder,
) -> Result<Option<DetectedOs>> {
    // If we have no banners, don't bother scanning. The index is built first
    // so the scan can stop at the first banner whose symbols are actually
    // installed, rather than reading the whole image to collect banners that
    // will not be used.
    let started = std::time::Instant::now();
    let index = BannerIndex::build(finder, "linux");
    log::debug!("Indexing symbol files took {:?}", started.elapsed());
    if index.is_empty() {
        log::debug!("No Linux symbol files are installed");
        return Ok(None);
    }

    // What was learned about this image before, if it is the same image. It is
    // checked rather than trusted: the banner has to still be at the offset it
    // was found, and the shifts have to come out the same when re-derived from
    // the task they were measured against.
    let remembered = context
        .config
        .get_string("automagic.image_identity")
        .and_then(|identity| image_cache::get(&identity))
        .filter(|facts| facts.operating_system == "linux");

    let started = std::time::Instant::now();
    let banners = match remembered
        .as_ref()
        .and_then(|facts| confirm_banner(context, physical_layer, facts))
    {
        Some(found) => {
            log::debug!("Banner confirmed where it was last seen");
            vec![found]
        }
        None => first_known_banner(context, physical_layer, BANNER_PREFIX, |banner| {
            index.lookup(banner).is_some()
        })?
        .into_iter()
        .collect::<Vec<_>>(),
    };
    log::debug!("Finding the banner took {:?}", started.elapsed());
    if banners.is_empty() {
        return Ok(None);
    }

    for found in &banners {
        let Some(location) = index.lookup(&found.banner) else {
            continue;
        };
        log::info!(
            "Matched banner '{}' to symbols at {}",
            found.banner,
            location.display()
        );

        let started = std::time::Instant::now();
        let table_name = context.symbol_space.free_table_name("kernel_symbols");
        let table = create_table(&table_name, location.load()?);
        table.set_source(location.url());
        log::debug!("Loading the symbol table took {:?}", started.elapsed());
        let pointer_size = table.pointer_size();
        context.add_symbol_table(table);

        // The kernel is loaded at a randomised address, so the symbol
        // addresses in the file are offset from where things actually are.
        // Recovering that shift is what makes every later read land correctly.
        // Upstream does not raise where it finds none, because an image may
        // legitimately have no ASLR shift, but it does report it.
        let started = std::time::Instant::now();
        let confirmed = remembered.as_ref().and_then(|facts| {
            let probe = TaskProbe::new(context, physical_layer, &table_name).ok()??;
            let shifts = probe.examine(facts.task_offset)?;
            // Only if the task still yields exactly what was recorded.
            (shifts.physical == facts.physical_shift
                && shifts.virtual_shift == facts.virtual_shift)
                .then_some(shifts)
        });
        let shifts = match confirmed {
            Some(shifts) => {
                log::debug!("ASLR shifts confirmed from the task they were measured against");
                Some(shifts)
            }
            None => find_aslr_shift(context, physical_layer, &table_name)?,
        };
        log::debug!("Finding the ASLR shift took {:?}", started.elapsed());
        let Some(shifts) = shifts else {
            log::debug!("Could not determine the ASLR shift for this image");
            continue;
        };

        // Kernels from 4.13 renamed the top-level page table. Try each name
        // the symbol file might use.
        let dtb_symbol = ["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"]
            .iter()
            .find(|name| {
                context
                    .symbol_space
                    .has_symbol(&crate::framework::symbols::join_name(&table_name, name))
            })
            .copied();

        let Some(dtb_symbol) = dtb_symbol else {
            log::debug!("Symbol file names no top-level page table");
            continue;
        };

        let symbol = context
            .symbol_space
            .get_symbol(&crate::framework::symbols::join_name(&table_name, dtb_symbol))?;

        // The page table's physical address is its unshifted virtual address
        // translated, plus the physical shift.
        let Some(unshifted) = virtual_to_physical(symbol.address, pointer_size) else {
            continue;
        };
        let dtb = unshifted.wrapping_add(shifts.physical);

        // Which class the layer gets is observable, and upstream decides it by
        // which of its two Linux stackers claims the image. Stackers are tried
        // in ascending `stack_order`, so `LinuxIntelVMCOREINFOStacker` (34)
        // goes before `LinuxIntelStacker` (35). A kernel that left a usable
        // VMCOREINFO note behind is therefore claimed by the first, which
        // builds a plain `Intel` layer, and only a kernel without one falls
        // through to the second and its `LinuxIntel` layer. The difference is
        // not only the name: the Linux classes carry `LinuxMixin`, which
        // inverts PROT_NONE entries and narrows MAXPHYADDR to 46 bits.
        //
        // The page table address and the shifts are the ones derived from the
        // symbols above rather than from the note, because both routes agree
        // on them wherever the note is usable at all.
        let config = match vmcoreinfo_layer_config(context, physical_layer, &found.banner) {
            Some(config) => config,
            None if pointer_size == 8 => LINUX_INTEL_32E,
            None => LINUX_INTEL,
        };
        let layer_name = context.layers.free_name("layer_name");
        context.layers.add(Arc::new(IntelLayer::new(
            &layer_name,
            physical_layer,
            dtb,
            config,
        )));

        // Symbol addresses are absolute but need the virtual shift applied, so
        // the module carries it as its load offset.
        let module_name = "kernel".to_string();
        context.add_module(Module::new(&module_name, &table_name, &layer_name, shifts.virtual_shift));

        // What the layer was built from, which is what describing the
        // configuration reports back.
        context.config.set(
            "automagic.kernel_virtual_offset",
            crate::framework::context::ConfigValue::Int(shifts.virtual_shift as i64),
        );
        // The banner recorded is the one the symbol file declares, whitespace
        // and terminator included, rather than the trimmed form the search
        // matched on.
        let declared = context
            .symbol_space
            .get_symbol(&crate::framework::symbols::join_name(&table_name, "linux_banner"))
            .ok()
            .and_then(|symbol| symbol.constant_data)
            .map(|data| String::from_utf8_lossy(&data).to_string())
            .unwrap_or_else(|| found.banner.clone());
        context.config.set(
            "automagic.kernel_banner",
            crate::framework::context::ConfigValue::Str(declared),
        );

        log::info!(
            "Linux kernel layer '{layer_name}' built with DTB {dtb:#x} from {dtb_symbol} \
             (physical shift {:#x}, virtual shift {:#x})",
            shifts.physical,
            shifts.virtual_shift
        );

        // Only when there is something new to say: a run that confirmed what
        // was already written has nothing to add.
        let already_known = remembered.as_ref().is_some_and(|facts| {
            facts.banner_offset == found.offset
                && facts.task_offset == shifts.task_offset
                && facts.physical_shift == shifts.physical
                && facts.virtual_shift == shifts.virtual_shift
        });
        if let Some(identity) = context
            .config
            .get_string("automagic.image_identity")
            .filter(|_| !already_known)
        {
            image_cache::put(
                &identity,
                &image_cache::ImageFacts {
                    operating_system: "linux".to_string(),
                    banner_offset: found.offset,
                    banner: found.banner.clone(),
                    symbols: location.display(),
                    task_offset: shifts.task_offset,
                    physical_shift: shifts.physical,
                    virtual_shift: shifts.virtual_shift,
                    kernel_offset: 0,
                    dtb: 0,
                },
            );
        }
        return Ok(Some(DetectedOs {
            layer_name,
            module_name: Some(module_name),
        }));
    }

    log::warn!(
        "Found Linux banner(s) but none yielded a usable kernel layer. Banners seen: {}",
        banners
            .iter()
            .map(|b| b.banner.as_str())
            .collect::<Vec<&str>>()
            .join("; ")
    );
    Ok(None)
}

/// How far the running kernel is shifted from the addresses in its symbol file.
struct AslrShift {
    /// Added to a translated symbol address to reach its physical location.
    physical: u64,
    /// Added to a symbol address to reach its virtual location.
    virtual_shift: u64,
    /// Where the idle task was found, which is what these were measured from.
    task_offset: u64,
}

/// Decides whether an address holds the idle task, and what the kernel's
/// displacement must be if it does.
///
/// The symbol lookups it needs are done once and reused for every candidate,
/// since a scan for the idle task's name turns up a great many of them.
struct TaskProbe<'a> {
    context: &'a Arc<Context>,
    physical_layer: &'a str,
    task_type: Arc<crate::framework::objects::template::Template>,
    /// Where the command name sits inside the task, which is what turns a hit
    /// on the string into the address of the structure.
    comm_offset: u64,
    pointer_size: usize,
    init_task: crate::framework::symbols::Symbol,
    init_mm: Option<crate::framework::symbols::Symbol>,
    init_files: Option<crate::framework::symbols::Symbol>,
}

impl<'a> TaskProbe<'a> {
    fn new(
        context: &'a Arc<Context>,
        physical_layer: &'a str,
        table_name: &str,
    ) -> Result<Option<Self>> {
        let qualified = |name: &str| crate::framework::symbols::join_name(table_name, name);
        let task_type = context.symbol_space.get_type(&qualified("task_struct"))?;
        let Some((comm_offset, _)) = context.symbol_space.find_member(&task_type, "comm")? else {
            return Ok(None);
        };
        Ok(Some(Self {
            context,
            physical_layer,
            task_type,
            comm_offset,
            pointer_size: context
                .symbol_space
                .table(table_name)
                .map(|table| table.pointer_size())
                .unwrap_or(8),
            init_task: context.symbol_space.get_symbol(&qualified("init_task"))?,
            init_mm: context.symbol_space.get_symbol(&qualified("init_mm")).ok(),
            init_files: context.symbol_space.get_symbol(&qualified("init_files")).ok(),
        }))
    }

    /// The shift implied by a hit on the idle task's name, if that is what it is.
    fn examine(&self, hit: u64) -> Option<AslrShift> {
        let task_address = hit.checked_sub(self.comm_offset)?;
        let task = self.context.object_from_template(
            self.task_type.clone(),
            self.physical_layer,
            task_address,
        );

        // The idle task has process zero and is not running.
        if task.member("pid").and_then(|pid| pid.as_u64()).unwrap_or(1) != 0 {
            return None;
        }
        if task
            .member("state")
            .and_then(|state| state.as_u64())
            .map(|state| state != 0)
            .unwrap_or(false)
        {
            return None;
        }

        // The idle task steals `mm` from the previously running task, i.e.
        // `init_mm` is only used as long as no CPU has ever been idle. This
        // catches cases where we found a fragment of the unrelocated ELF file
        // instead of the running kernel: requiring the task list to be
        // self-referential rules it out, since only the live structure links to
        // itself before any other task is created.
        if let Some(init_mm) = &self.init_mm {
            let active_mm = task
                .member("active_mm")
                .and_then(|mm| mm.pointer_value())
                .unwrap_or(0);
            let links_match = task
                .member("tasks")
                .and_then(|tasks| {
                    Ok((
                        tasks.member("next")?.pointer_value()?,
                        tasks.member("prev")?.pointer_value()?,
                    ))
                })
                .map(|(next, prev)| next == prev)
                .unwrap_or(false);
            if active_mm == init_mm.address && links_match {
                return None;
            }
        }

        let expected = virtual_to_physical(self.init_task.address, self.pointer_size)?;
        let physical = task_address.wrapping_sub(expected);

        // The virtual shift falls out of a pointer the task already holds:
        // comparing where `files` actually points against where the symbol file
        // says `init_files` lives gives the displacement directly.
        let virtual_shift = match &self.init_files {
            Some(init_files) => task
                .member("files")
                // Read as raw bytes rather than as a pointer: a pointer value is
                // masked to the bits its layer addresses, and the shift has to be
                // measured against the full symbol address the ISF records.
                .and_then(|files| files.bytes())
                .map(|bytes| {
                    let mut raw = [0u8; 8];
                    let take = bytes.len().min(8);
                    raw[..take].copy_from_slice(&bytes[..take]);
                    u64::from_le_bytes(raw)
                })
                .map(|value| value.wrapping_sub(init_files.address))
                .unwrap_or(0),
            None => 0,
        };

        // Both shifts are whole pages. Anything else means the candidate was
        // not really the idle task.
        if physical & 0xFFF != 0 || virtual_shift & 0xFFF != 0 {
            return None;
        }

        Some(AslrShift {
            physical,
            virtual_shift,
            task_offset: hit,
        })
    }
}

/// Determine the ASLR shift by locating the idle task in physical memory.
///
/// `init_task`'s command name is the fixed string `swapper/0`, so scanning for
/// it and stepping back to the start of the structure gives the task's real
/// physical address. Comparing that against where the symbol file says it
/// should be yields the shift.
fn find_aslr_shift(
    context: &Arc<Context>,
    physical_layer: &str,
    table_name: &str,
) -> Result<Option<AslrShift>> {
    let Some(probe) = TaskProbe::new(context, physical_layer, table_name)? else {
        return Ok(None);
    };

    let layer = context.layers.get(physical_layer)?;
    let scanner = RegExScanner::new(SWAPPER_SIGNATURE)?;

    // Every candidate is checked as it is found, so the scan ends at the idle
    // task rather than reading the whole image for hits nobody will look at.
    let mut shift = None;
    scan_layer_until(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        shift = probe.examine(offset);
        shift.is_none()
    })?;

    if let Some(shift) = shift {
        log::debug!(
            "Linux ASLR shifts determined: physical {:#x} virtual {:#x}",
            shift.physical,
            shift.virtual_shift
        );
        return Ok(Some(shift));
    }

    log::debug!("Could not determine an ASLR shift; assuming none");
    Ok(Some(AslrShift {
        physical: 0,
        virtual_shift: 0,
        task_offset: 0,
    }))
}

/// Convert a kernel virtual address to a physical one.
///
/// The kernel's direct map places physical memory at a fixed virtual base, so
/// masking off that base recovers the physical address. The bases differ
/// between 32- and 64-bit kernels.
pub fn virtual_to_physical(address: u64, pointer_size: usize) -> Option<u64> {
    if pointer_size == 8 {
        // x86-64 maps the kernel image at 0xffffffff80000000 and the physical
        // direct map at 0xffff888000000000.
        const KERNEL_IMAGE_BASE: u64 = 0xFFFF_FFFF_8000_0000;
        const DIRECT_MAP_BASE: u64 = 0xFFFF_8880_0000_0000;

        if address >= KERNEL_IMAGE_BASE {
            Some(address - KERNEL_IMAGE_BASE)
        } else if address >= DIRECT_MAP_BASE {
            Some(address - DIRECT_MAP_BASE)
        } else {
            None
        }
    } else {
        // 32-bit kernels map physical memory at 0xC0000000.
        const PAGE_OFFSET_32: u64 = 0xC000_0000;
        (address >= PAGE_OFFSET_32).then(|| address - PAGE_OFFSET_32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_both_kernel_mappings_to_physical() {
        // An address in the kernel image mapping.
        assert_eq!(virtual_to_physical(0xFFFF_FFFF_8100_0000, 8), Some(0x100_0000));
        // An address in the physical direct map.
        assert_eq!(virtual_to_physical(0xFFFF_8880_0200_0000, 8), Some(0x200_0000));
        // A user-space address is not part of either mapping.
        assert_eq!(virtual_to_physical(0x0000_7FFF_0000_0000, 8), None);
    }

    #[test]
    fn thirty_two_bit_kernels_use_the_page_offset() {
        assert_eq!(virtual_to_physical(0xC010_0000, 4), Some(0x10_0000));
        assert_eq!(virtual_to_physical(0x0800_0000, 4), None);
    }
}

/// Check that the banner is still where it was last found.
///
/// One page read against a scan of the whole image: if the text matches, the
/// search would have found exactly this, so there is nothing to search for.
fn confirm_banner(
    context: &Arc<Context>,
    physical_layer: &str,
    facts: &image_cache::ImageFacts,
) -> Option<FoundBanner> {
    let layer = context.layers.get(physical_layer).ok()?;
    let wanted = facts.banner.as_bytes();
    let data = layer
        .read(&context.layers, facts.banner_offset, wanted.len(), false)
        .ok()?;
    (data == wanted).then(|| FoundBanner {
        banner: facts.banner.clone(),
        offset: facts.banner_offset,
    })
}

/// The layer configuration upstream's VMCOREINFO stacker would build, if that
/// stacker would claim this image at all.
///
/// A note counts only when it describes the same kernel as the banner that was
/// matched, and when it carries everything the stacker needs: `phys_base` and
/// `KERNELOFFSET` to recover the shifts, and `SYMBOL(swapper_pg_dir)` to find
/// the page tables. A note missing any of them is passed over, exactly as
/// upstream passes it over and tries the next one.
fn vmcoreinfo_layer_config(
    context: &Arc<Context>,
    physical_layer: &str,
    banner: &str,
) -> Option<crate::framework::layers::intel::IntelConfig> {
    use crate::framework::plugins::linux::vmcoreinfo;

    // The note is searched for rather than read from `vmcoreinfo_note`, whose
    // address the symbols do give. On the kernels that matter that symbol is a
    // `u32 *`, so it holds a pointer to the note rather than the note itself,
    // and the pages it points at live in the direct map, whose base is itself
    // randomised. Searching avoids having to undo two shifts to find something
    // the search finds anyway.
    //
    // The search stops at the first note that would satisfy upstream, which is
    // also the one upstream would use. It still reads a good part of the image
    // on a capture whose note sits late, which costs a second or so. If that
    // ever matters it belongs in the image cache beside the banner offset and
    // the shifts, which are already remembered per image.
    let chosen = vmcoreinfo::first_note_matching(context, physical_layer, |(_, pairs)| {
        note_layer_config(banner, pairs).is_some()
    })
    .ok()??;
    note_layer_config(banner, &chosen.1)
}

/// The configuration one VMCOREINFO note implies, or nothing if upstream would
/// pass this note over.
fn note_layer_config(
    banner: &str,
    pairs: &[(String, String)],
) -> Option<crate::framework::layers::intel::IntelConfig> {
    let value = |key: &str| {
        pairs
            .iter()
            .find(|(held, _)| held == key)
            .map(|(_, value)| value.as_str())
    };

    // The note has to be describing the kernel the banner named. See how the
    // kernel builds `linux_banner` from its release.
    let release = value("OSRELEASE")?;
    if !banner.starts_with(&format!("Linux version {release} (")) {
        return None;
    }

    // Kernels before 4.10 may carry a `SYMBOL(phys_base)` instead, which is
    // not usable for this, so only the number will do. Without `KERNELOFFSET`,
    // added in 3.14, KASLR may not be implemented at all, and upstream only
    // proceeds when both are present.
    value("NUMBER(phys_base)")?;
    value("KERNELOFFSET")?;

    // A note that does not name the page tables is passed over.
    let dtb_virtual = value("SYMBOL(swapper_pg_dir)")
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())?;

    // PAE implies 32-bit. Otherwise the width of the page table's own virtual
    // address says which it is.
    let pae = value("CONFIG_X86_PAE").unwrap_or("n") == "y";
    let bits32 = pae || dtb_virtual <= 1u64 << 32;
    Some(match (bits32, pae) {
        (true, true) => INTEL_PAE,
        (true, false) => INTEL,
        (false, _) => INTEL_32E,
    })
}
