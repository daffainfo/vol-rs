//! Resolve named symbols, or named addresses, inside a loaded module.
//!
//! A module is asked for a symbol in two ways: its own debug database, which
//! describes far more than it exports, and its export table, which is present
//! in memory but only names what the module publishes. Both are tried, in that
//! order, in every copy of the module that was found, because a copy whose
//! pages have been reclaimed answers wrongly rather than not at all.
//!
//! Other analyses reach the same machinery through the functions below, which
//! is how a system-call check or a network scan finds the addresses it needs.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct PeSymbols;

impl Plugin for PeSymbols {
    fn name(&self) -> &'static str {
        "windows.pe_symbols.PESymbols"
    }

    fn description(&self) -> &'static str {
        "Prints symbols in PE files in process and kernel memory"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "source",
                "Where to resolve symbols.",
                RequirementKind::Choice(vec!["kernel".to_string(), "processes".to_string()]),
            )
            .required(),
            Requirement::new(
                "module",
                "Module in which to resolve symbols. Use \"ntoskrnl.exe\" to \
                 resolve in the base kernel executable.",
                RequirementKind::String,
            )
            .required(),
            Requirement::new(
                "symbols",
                "Symbol name to resolve",
                RequirementKind::List(Box::new(RequirementKind::String)),
            ),
            Requirement::new(
                "addresses",
                "Address of symbol to resolve",
                RequirementKind::List(Box::new(RequirementKind::Int)),
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Module"),
            Column::string("Symbol"),
            Column::new("Address", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        // The module names a single file. Everything else is asked of it.
        let module = config.get_string("module").unwrap_or_default().to_lowercase();
        let names = string_list(config, "symbols");
        let addresses = int_list(config, "addresses");

        let wanted = if !names.is_empty() {
            Wanted::Names(names)
        } else if !addresses.is_empty() {
            Wanted::Addresses(addresses)
        } else {
            log::error!("--address or --symbol must be specified");
            return Ok(grid);
        };

        let filter = [module.clone()];
        let collected = if config.get_string("source").as_deref() == Some("kernel") {
            kernel_module_instances(&context, &kernel, &physical, &filter)
        } else {
            process_module_instances(&context, &kernel, &physical, &filter)
        };

        let Some((name, instances)) = collected
            .iter()
            .find(|(found, _)| *found == module)
        else {
            return Ok(grid);
        };

        for (symbol, address) in resolve_wanted(&context, instances, name, &wanted) {
            grid.push(
                0,
                vec![
                    Value::string(name.clone()),
                    Value::string(symbol),
                    Value::hex(address),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// The strings given for a repeated option.
fn string_list(config: &Configuration, name: &str) -> Vec<String> {
    config
        .get(name)
        .and_then(|value| value.as_list().map(<[_]>::to_vec))
        .unwrap_or_default()
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

/// The integers given for a repeated option.
fn int_list(config: &Configuration, name: &str) -> Vec<u64> {
    config
        .get(name)
        .and_then(|value| value.as_list().map(<[_]>::to_vec))
        .unwrap_or_default()
        .iter()
        .filter_map(|value| value.as_int().map(|number| number as u64))
        .collect()
}

/// One mapped region of a process, and the file behind it.
pub type MappedRange = (u64, u64, String);

/// The regions of a process that map a file, with the path each maps.
///
/// A region with no file, or whose file has no path in it, says nothing about
/// what code is running there and is left out.
pub fn process_file_ranges(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    process: &crate::framework::symbols::windows::Process,
) -> Vec<MappedRange> {
    let mut ranges = Vec::new();
    for vad in crate::framework::plugins::windows::vadinfo::walk_vad_tree(context, kernel, process)
        .unwrap_or_default()
    {
        let Some(path) = crate::framework::plugins::windows::vadinfo::file_name_of(&vad) else {
            continue;
        };
        if !path.contains('\\') {
            continue;
        }
        let (Some(start), Some(end)) = (
            crate::framework::plugins::windows::vadinfo::start_vpn(&vad),
            crate::framework::plugins::windows::vadinfo::end_vpn(&vad),
        ) else {
            continue;
        };
        ranges.push((start, end - start + 1, path));
    }
    ranges
}

/// The file mapped over `address`, if any of the ranges covers it.
pub fn file_for_address(ranges: &[MappedRange], address: u64) -> Option<&str> {
    ranges
        .iter()
        .find(|(start, size, _)| *start <= address && address < start + size)
        .map(|(_, _, path)| path.as_str())
}

/// What a module says about the database describing it.
pub struct DebugInfo {
    /// The database's file name, as the module names it.
    pub name: String,
    /// The identifier that distinguishes one build from another.
    pub guid: String,
    /// How many times that build was revised.
    pub age: u32,
}

/// A module's symbols, however they were come by.
///
/// A description of the module may already be installed, in which case it is
/// used as it stands. Otherwise the module's database is fetched and the names
/// it publishes are read out of it.
pub enum ModuleSymbols {
    Installed(Arc<crate::framework::symbols::SymbolTable>),
    Published(crate::framework::symbols::windows::pdb::PublicSymbols),
}

impl ModuleSymbols {
    /// Where a name sits, relative to the module's base.
    pub fn address_of(&self, name: &str) -> Option<u64> {
        match self {
            ModuleSymbols::Installed(table) => {
                table.get_symbol(name).ok().map(|symbol| symbol.address)
            }
            ModuleSymbols::Published(symbols) => symbols.address_of(name).map(u64::from),
        }
    }

    /// The name at a place, relative to the module's base.
    ///
    /// Several names can share a place, and the first in name order is the one
    /// reported, which is what looking a location up in a symbol table gives.
    pub fn name_at(&self, address: u64) -> Option<String> {
        match self {
            ModuleSymbols::Installed(table) => table.symbols_at(address).first().cloned(),
            ModuleSymbols::Published(symbols) => {
                u32::try_from(address).ok().and_then(|address| {
                    symbols.name_at(address).map(str::to_string)
                })
            }
        }
    }
}

/// The symbols describing a module, preferring one already installed.
pub fn module_symbols(context: &Arc<Context>, info: &DebugInfo) -> Option<ModuleSymbols> {
    use crate::framework::symbols::intermed::create_table;
    use crate::framework::symbols::windows::pdb;

    let directory = format!("windows/{}", info.name.trim_end_matches('\0'));
    let identity = format!("{}-{}", info.guid.to_uppercase(), info.age);
    if let Some(location) = context.symbol_finder().find(&directory, &identity) {
        if let Ok(isf) = location.load() {
            return Some(ModuleSymbols::Installed(create_table(identity, isf)));
        }
    }

    let data = pdb::fetch(&info.name, &info.guid, info.age).ok()?;
    pdb::public_symbols(&data).ok().map(ModuleSymbols::Published)
}

/// Read the debug record a module carries, which names its database.
///
/// The record is searched for inside the module's own image rather than found
/// through its headers: the headers name a place that is often paged out,
/// while the record itself usually is not.
pub fn module_debug_info(
    context: &Arc<Context>,
    layer: &str,
    base: u64,
    size: u64,
    module_name: &str,
) -> Option<DebugInfo> {
    use crate::framework::automagic::pdbscan;

    // The kernel executable's database is not named after the file, so every
    // name a kernel build is known by is tried.
    let names = if module_name.eq_ignore_ascii_case(KERNEL_MODULE_NAME) {
        KERNEL_PDB_NAMES
            .iter()
            .map(|name| format!("{name}.pdb"))
            .collect()
    } else {
        // A database is named after the module, and some builds capitalise the
        // first letter of that name where the module itself does not.
        let stem = module_name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(module_name)
            .to_lowercase();
        let mut capitalised = stem.clone();
        if let Some(first) = capitalised.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        vec![format!("{stem}.pdb"), format!("{capitalised}.pdb")]
    };

    let record = pdbscan::scan_for_record(context, layer, base, base + size, &names)?;
    Some(DebugInfo {
        name: record.pdb_name.clone(),
        guid: record.guid.clone(),
        age: record.age,
    })
}

/// Where one copy of a module was found: the address space it is mapped in,
/// where it starts, and how much of it there is.
pub type ModuleInstance = (String, u64, u64);

/// What a caller wants out of a module: names to place, or places to name.
pub enum Wanted {
    Names(Vec<String>),
    Addresses(Vec<u64>),
}

/// Resolve names inside a module, looking in every copy of it that was found.
pub fn resolve_across_instances(
    context: &Arc<Context>,
    instances: &[ModuleInstance],
    module_name: &str,
    wanted: &[&str],
) -> Vec<(String, u64)> {
    let names = Wanted::Names(wanted.iter().map(|name| name.to_string()).collect());
    resolve_wanted(context, instances, module_name, &names)
}

/// Resolve what was asked of a module, in every copy of it that was found.
///
/// A module's own database is asked first, wherever a copy of the module still
/// names one, because it describes far more than the module exports and
/// because a copy whose export data has been paged out answers wrongly rather
/// than not at all. Only what the database cannot answer is looked up in the
/// export tables.
pub fn resolve_wanted(
    context: &Arc<Context>,
    instances: &[ModuleInstance],
    module_name: &str,
    wanted: &Wanted,
) -> Vec<(String, u64)> {
    use crate::framework::symbols::windows::pe;

    let mut found: Vec<(String, u64)> = Vec::new();

    // What is still outstanding, in the order it was asked for.
    let remaining = |found: &Vec<(String, u64)>| -> Wanted {
        match wanted {
            Wanted::Names(names) => Wanted::Names(
                names
                    .iter()
                    .filter(|name| !found.iter().any(|(resolved, _)| resolved == *name))
                    .cloned()
                    .collect(),
            ),
            Wanted::Addresses(addresses) => Wanted::Addresses(
                addresses
                    .iter()
                    .filter(|address| !found.iter().any(|(_, at)| at == *address))
                    .copied()
                    .collect(),
            ),
        }
    };
    let done = |found: &Vec<(String, u64)>| match remaining(found) {
        Wanted::Names(names) => names.is_empty(),
        Wanted::Addresses(addresses) => addresses.is_empty(),
    };

    for (layer, base, size) in instances {
        if done(&found) {
            break;
        }
        let Some(info) = module_debug_info(context, layer, *base, *size, module_name) else {
            continue;
        };
        let Some(symbols) = module_symbols(context, &info) else {
            continue;
        };
        match remaining(&found) {
            Wanted::Names(names) => {
                for name in names {
                    if let Some(address) = symbols.address_of(&name) {
                        found.push((name, base + address as u64));
                    }
                }
            }
            Wanted::Addresses(addresses) => {
                for address in addresses {
                    let Some(relative) = address.checked_sub(*base) else {
                        continue;
                    };
                    if let Some(name) = symbols.name_at(relative) {
                        found.push((name, address));
                    }
                }
            }
        }
    }

    for (layer, base, _) in instances {
        if done(&found) {
            break;
        }
        let Ok(headers) = context.layers.read(layer, *base, 0x1000, true) else {
            continue;
        };
        let Ok(header) = pe::parse(&headers) else {
            continue;
        };
        let Ok(image) = context
            .layers
            .read(layer, *base, header.size_of_image as usize, true)
        else {
            continue;
        };
        let Some(exports) = pe::exports(&image) else {
            continue;
        };
        match remaining(&found) {
            Wanted::Names(names) => {
                for name in names {
                    if let Some(export) = exports.iter().find(|export| export.name == name) {
                        found.push((name, base + export.address as u64));
                    }
                }
            }
            Wanted::Addresses(addresses) => {
                for address in addresses {
                    if let Some(export) = exports
                        .iter()
                        .find(|export| base + export.address as u64 == address)
                    {
                        found.push((export.name.clone(), address));
                    }
                }
            }
        }
    }
    found
}

/// Where each wanted kernel module was found, in the order the kernel lists
/// them.
///
/// A module is read through the address space of a session that can see it,
/// since a driver loaded into a session is not mapped anywhere else.
pub fn kernel_module_instances(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    physical: &str,
    filter: &[String],
) -> Vec<(String, Vec<ModuleInstance>)> {
    let sessions = crate::framework::plugins::windows::modules::session_layers(
        context, kernel, physical,
    );
    // The kernel executable is not named the way its module entry names it,
    // so it is recognised by being the list's first entry.
    let gather_kernel = filter.iter().any(|name| name == KERNEL_MODULE_NAME);

    let modules = context
        .object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))
        .and_then(|head| {
            walk_list(
                &head,
                &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
                "InLoadOrderLinks",
                true,
            )
        })
        .unwrap_or_default();

    let mut found: Vec<(String, Vec<ModuleInstance>)> = Vec::new();
    for (index, entry) in modules.iter().enumerate() {
        let Ok(name) = entry
            .member("BaseDllName")
            .and_then(|name| unicode_string(&name))
        else {
            continue;
        };
        let mut name = name.to_lowercase();

        if filter.is_empty() || (gather_kernel && index == 0) {
            name = KERNEL_MODULE_NAME.to_string();
        } else if !filter.iter().any(|wanted| name.ends_with(wanted)) {
            continue;
        }

        let Ok(base) = entry.member("DllBase").and_then(|base| base.pointer_value()) else {
            continue;
        };
        let size = entry
            .member("SizeOfImage")
            .and_then(|size| size.as_u64())
            .unwrap_or(0);
        let Some((_, layer)) = sessions
            .iter()
            .find(|(_, layer)| context.layers.is_valid(layer, base, 1))
        else {
            continue;
        };

        match found.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, instances)) => instances.push((layer.clone(), base, size)),
            None => found.push((name, vec![(layer.clone(), base, size)])),
        }
    }
    found
}

/// Where each wanted module was found across every process that maps it.
pub fn process_module_instances(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    physical: &str,
    filter: &[String],
) -> Vec<(String, Vec<ModuleInstance>)> {
    let mut found: Vec<(String, Vec<ModuleInstance>)> = Vec::new();

    for process in list_processes(context, kernel).unwrap_or_default() {
        let Ok(layer) = process.address_space(physical) else {
            continue;
        };
        for (start, size, path) in process_file_ranges(context, kernel, &process) {
            let name = file_name(&path);
            if !filter.is_empty() && !filter.iter().any(|wanted| name.ends_with(wanted)) {
                continue;
            }
            match found.iter_mut().find(|(existing, _)| *existing == name) {
                Some((_, instances)) => instances.push((layer.clone(), start, size)),
                None => found.push((name, vec![(layer.clone(), start, size)])),
            }
        }
    }
    found
}

/// The name the kernel executable is known by, whatever its module entry says.
pub const KERNEL_MODULE_NAME: &str = "ntoskrnl.exe";

/// The names a kernel build's database goes by.
const KERNEL_PDB_NAMES: &[&str] = &["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"];

/// The file name at the end of a Windows path, lowercased.
pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}
