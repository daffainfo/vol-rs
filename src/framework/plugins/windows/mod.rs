//! Windows plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod pslist;
pub mod pstree;
pub mod psscan;
pub mod dlllist;
pub mod cmdline;
pub mod info;
pub mod modules;
pub mod handles;
pub mod vadinfo;
pub mod filescan;
pub mod mutantscan;
pub mod symlinkscan;
pub mod driverscan;
pub mod unloadedmodules;
pub mod envars;
pub mod memmap;
pub mod virtmap;
pub mod vadwalk;
pub mod getsids;
pub mod privileges;
pub mod statistics;
pub mod svclist;
pub mod thrdscan;
pub mod threads;
pub mod sessions;
pub mod registry;
pub mod bigpools;
pub mod driverirp;
pub mod devicetree;
pub mod malware;
pub mod getservicesids;
pub mod ssdt;
pub mod kpcrs;
pub mod netscan;
pub mod callbacks;
pub mod mftscan;
pub mod svcscan;
pub mod verinfo;
pub mod joblinks;
pub mod iat;
pub mod dumpfiles;
pub mod timers;
pub mod crashinfo;
pub mod vadregexscan;
pub mod mbrscan;
pub mod poolscanner;
pub mod suspended_threads;
pub mod pedump;
pub mod truecrypt;
pub mod etwpatch;
pub mod debugregisters;
pub mod shimcachemem;
pub mod strings;
pub mod pe_symbols;
pub mod consoles;
pub mod netstat;
pub mod windowstations;
pub mod vadyarascan;

use std::sync::Arc;

use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(pslist::PsList));
    registry.add(Arc::new(pstree::PsTree));
    registry.add(Arc::new(psscan::PsScan));
    registry.add(Arc::new(dlllist::DllList));
    registry.add(Arc::new(cmdline::CmdLine));
    registry.add(Arc::new(info::Info));
    registry.add(Arc::new(modules::Modules));
    registry.add(Arc::new(modules::ModScan));
    registry.add(Arc::new(threads::Threads));
    registry.add(Arc::new(threads::OrphanKernelThreads));
    registry.add(Arc::new(windowstations::DeskScan));
    registry.add(Arc::new(statistics::Statistics));
    registry.add(Arc::new(svclist::SvcList));
    registry.add(Arc::new(svclist::SvcDiff {
        name: "windows.svcdiff.SvcDiff",
    }));
    registry.add(Arc::new(svclist::SvcDiff {
        name: "windows.malware.svcdiff.SvcDiff",
    }));
    registry.add(Arc::new(handles::Handles));
    registry.add(Arc::new(vadinfo::VadInfo));
    registry.add(Arc::new(filescan::FileScan));
    registry.add(Arc::new(mutantscan::MutantScan));
    registry.add(Arc::new(symlinkscan::SymlinkScan));
    registry.add(Arc::new(driverscan::DriverScan));
    registry.add(Arc::new(unloadedmodules::UnloadedModules));
    registry.add(Arc::new(envars::Envars));
    registry.add(Arc::new(memmap::MemMap));
    registry.add(Arc::new(virtmap::VirtMap));
    registry.add(Arc::new(vadwalk::VadWalk));
    registry.add(Arc::new(getsids::GetSids));
    registry.add(Arc::new(privileges::Privileges));
    registry.add(Arc::new(thrdscan::ThrdScan));
    registry.add(Arc::new(sessions::Sessions));
    registry.add(Arc::new(bigpools::BigPools));
    registry.add(Arc::new(driverirp::DriverIrp));
    registry.add(Arc::new(devicetree::DeviceTree));
    self::registry::register(registry);
    malware::register(registry);
    registry.add(Arc::new(getservicesids::GetServiceSids));
    registry.add(Arc::new(ssdt::Ssdt));
    registry.add(Arc::new(kpcrs::Kpcrs));
    registry.add(Arc::new(netscan::NetScan));
    registry.add(Arc::new(callbacks::Callbacks));
    registry.add(Arc::new(mftscan::MftScan));
    registry.add(Arc::new(mftscan::Ads));
    registry.add(Arc::new(mftscan::ResidentData));
    registry.add(Arc::new(svcscan::SvcScan));
    registry.add(Arc::new(verinfo::VerInfo));
    registry.add(Arc::new(joblinks::JobLinks));
    registry.add(Arc::new(iat::Iat));
    registry.add(Arc::new(dumpfiles::DumpFiles));
    registry.add(Arc::new(timers::Timers));
    registry.add(Arc::new(crashinfo::CrashInfo));
    registry.add(Arc::new(vadregexscan::VadRegExScan));
    registry.add(Arc::new(mbrscan::MbrScan));
    registry.add(Arc::new(poolscanner::PoolScanner));
    registry.add(Arc::new(suspended_threads::SuspendedThreads));
    registry.add(Arc::new(pedump::PeDump));
    registry.add(Arc::new(truecrypt::Passphrase));
    registry.add(Arc::new(etwpatch::EtwPatch));
    registry.add(Arc::new(debugregisters::DebugRegisters));
    registry.add(Arc::new(shimcachemem::ShimcacheMem));
    registry.add(Arc::new(strings::Strings));
    registry.add(Arc::new(pe_symbols::PeSymbols));
    registry.add(Arc::new(consoles::Consoles));
    registry.add(Arc::new(consoles::CmdScan));
    registry.add(Arc::new(netstat::NetStat));
    registry.add(Arc::new(windowstations::WindowStations));
    registry.add(Arc::new(windowstations::Desktops));
    registry.add(Arc::new(windowstations::Windows));
    registry.add(Arc::new(vadyarascan::VadYaraScan));
}

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};

/// Resolve the kernel module a plugin was configured with.
///
/// Every Windows plugin needs this, and the failure mode, no symbols loaded,
/// deserves a message that says what to do about it.
pub fn kernel_module(context: &Arc<Context>, config: &Configuration) -> Result<Arc<Module>> {
    let name = config
        .get_string("kernel")
        .unwrap_or_else(|| "kernel".to_string());
    context.module(&name).map_err(|_| {
        VolatilityError::Other(
            "No kernel symbols are loaded for this image. Windows analysis needs a symbol \
             file matching the kernel; install one and point at it with --symbol-dirs."
                .to_string(),
        )
    })
}

/// The layer holding physical memory, for plugins that build process layers.
pub fn physical_layer(config: &Configuration) -> String {
    config
        .get_string("physical_layer")
        .unwrap_or_else(|| "base".to_string())
}

/// Name of the offset column, which says which address space it refers to.
pub fn offset_column_name(physical: bool) -> &'static str {
    if physical {
        "Offset(P)"
    } else {
        "Offset(V)"
    }
}

/// The offset to report for a process.
///
/// Translating to a physical offset can fail if the page is not resident, in
/// which case the virtual offset is reported rather than losing the row.
pub fn process_offset(
    context: &Arc<Context>,
    process: &crate::framework::symbols::windows::Process,
    physical: bool,
) -> u64 {
    let virtual_offset = process.object.offset();
    if !physical {
        return virtual_offset;
    }
    context
        .layers
        .get(process.object.layer_name())
        .ok()
        .and_then(|layer| {
            layer
                .mapping(&context.layers, virtual_offset, 0, false)
                .ok()
                .and_then(|entries| entries.first().map(|entry| entry.mapped_offset))
        })
        .unwrap_or(virtual_offset)
}

/// Load a symbol table beside the kernel's, and register a module for it.
///
/// The GUI subsystem's structures live in `win32k`, whose symbols are a
/// separate ISF file from the kernel's. Loading one lazily keeps every other
/// plugin from paying for it.
pub fn load_companion_module(
    context: &Arc<Context>,
    kernel: &Module,
    file_stem: &str,
    module_name: &str,
) -> Result<Option<Arc<Module>>> {
    // Reuse the module if a previous plugin in this run already loaded it.
    if let Ok(existing) = context.module(module_name) {
        return Ok(Some(existing));
    }

    // The symbols this run was told about, which is where a companion file
    // would have been put.
    let finder = context.symbol_finder();
    let Some(location) = finder.find("windows", file_stem) else {
        // Without the file there is nothing to report, which is what upstream
        // produces when it cannot find one either.
        log::debug!("No '{file_stem}' symbol file is installed; its plugins have nothing to list");
        return Ok(None);
    };

    let table_name = context.symbol_space.free_table_name(file_stem);
    let table = crate::framework::symbols::intermed::create_table(&table_name, location.load()?);
    context.add_symbol_table(table);

    // The companion shares the kernel's layer and addressing mode, since it is
    // mapped into the same address space.
    Ok(Some(context.add_module(
        Module::new(module_name, &table_name, &kernel.layer_name, kernel.offset)
            .with_absolute_addresses(kernel.absolute_symbol_addresses),
    )))
}

/// The processes a listing should walk, given how the caller named them.
///
/// Naming a physical offset asks about one structure in the image, which is
/// found by scanning rather than by walking the kernel's list, so a process
/// the list no longer mentions can still be examined.
pub fn selected_processes(
    context: &std::sync::Arc<Context>,
    kernel: &Module,
    config: &Configuration,
) -> crate::error::Result<Vec<crate::framework::symbols::windows::Process>> {
    let filter = crate::framework::plugins::pid_filter(config);
    match config.get_int("offset").filter(|offset| *offset != 0) {
        Some(offset) => {
            let offset = offset as u64;
            Ok(
                crate::framework::plugins::windows::psscan::scan_processes(context, kernel)?
                    .into_iter()
                    .filter(|process| process_offset(context, process, true) == offset)
                    .collect(),
            )
        }
        None => Ok(
            crate::framework::symbols::windows::list_processes(context, kernel)?
                .into_iter()
                .filter(|process| {
                    process
                        .pid()
                        .map(|pid| crate::framework::plugins::pid_matches(&filter, pid))
                        .unwrap_or(false)
                })
                .collect(),
        ),
    }
}
