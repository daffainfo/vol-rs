//! List the kernel modules loaded on the system.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, poolscanner};

pub struct Modules;

impl Plugin for Modules {
    fn name(&self) -> &'static str {
        "windows.modules.Modules"
    }

    fn description(&self) -> &'static str {
        "Lists the loaded kernel modules."
    }

    fn requirements(&self) -> Vec<Requirement> {
        module_requirements()
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        module_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        report_modules(&context, &kernel, config, list_modules(&context, &kernel)?)
    }
}

/// Scan the pools for module entries the kernel may no longer list.
pub struct ModScan;

impl Plugin for ModScan {
    fn name(&self) -> &'static str {
        "windows.modscan.ModScan"
    }

    fn description(&self) -> &'static str {
        "Scans for modules present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        module_requirements()
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        module_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // A module entry carries its own pool tag, so one that has been
        // unlinked from the kernel's list is still there to be found.
        let found = poolscanner::scan_for_tags(&context, &kernel, &[b"MmLd"])?;
        report_modules(&context, &kernel, config, found)
    }
}

/// The options both listings take.
fn module_requirements() -> Vec<Requirement> {
    vec![
        Requirement::kernel(),
        Requirement::new("dump", "Extract listed modules", RequirementKind::Bool)
            .with_default(ConfigValue::Bool(false)),
        Requirement::new(
            "base",
            "Extract a single module with BASE address",
            RequirementKind::Int,
        ),
        Requirement::new("name", "module name/sub string", RequirementKind::String),
    ]
}

/// The columns both listings report.
fn module_columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColumnType::UInt),
        Column::new("Base", ColumnType::UInt),
        Column::new("Size", ColumnType::UInt),
        Column::string("Name"),
        Column::string("Path"),
        Column::string("File output"),
    ]
}

/// The kernel's own module entries, in the order it links them.
pub fn list_modules(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Object>> {
    // PsLoadedModuleList links the kernel's own module entries, using the
    // same structure as a process's module list.
    let head = context.object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))?;
    walk_list(
        &head,
        &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
        "InLoadOrderLinks",
        true,
    )
}

/// Report a set of module entries, extracting each one if asked to.
fn report_modules(
    context: &Arc<Context>,
    kernel: &Module,
    config: &Configuration,
    entries: Vec<Object>,
) -> Result<TreeGrid> {
    let dump = config.get_bool("dump").unwrap_or(false);
    let wanted_base = config.get_int("base").map(|value| value as u64);
    let wanted_name = config.get_string("name");
    let physical = physical_layer(config);

    // The sessions are only needed to read a module out, so they are not
    // gathered for a plain listing.
    let sessions = if dump {
        session_layers(context, kernel, &physical)
    } else {
        Vec::new()
    };

    let mut grid = TreeGrid::new(module_columns());
    for entry in entries {
        let base = entry
            .member("DllBase")
            .and_then(|base| base.pointer_value());
        if let (Some(wanted), Ok(base)) = (wanted_base, &base) {
            if wanted != *base {
                continue;
            }
        }

        let name = entry
            .member("BaseDllName")
            .and_then(|value| unicode_string(&value));
        if let (Some(wanted), Ok(name)) = (&wanted_name, &name) {
            if !name.contains(wanted.as_str()) {
                continue;
            }
        }

        let file_output = if dump {
            match &base {
                Ok(base) => dump_module(context, &sessions, &entry, *base),
                Err(_) => "Error outputting file".to_string(),
            }
        } else {
            "Disabled".to_string()
        };

        grid.push(
            0,
            vec![
                Value::hex(entry.offset()),
                base.map(Value::hex).unwrap_or_else(|_| Value::unreadable()),
                entry
                    .member("SizeOfImage")
                    .and_then(|size| size.as_u64())
                    .map(Value::hex)
                    .unwrap_or_else(|_| Value::unreadable()),
                name.map(Value::string).unwrap_or_else(|_| Value::unreadable()),
                entry
                    .member("FullDllName")
                    .and_then(|value| unicode_string(&value))
                    .map(Value::string)
                    .unwrap_or_else(|_| Value::unreadable()),
                Value::string(file_output),
            ],
        )?;
    }
    Ok(grid)
}

/// Write one module's image out, through a session that can see it.
fn dump_module(
    context: &Arc<Context>,
    sessions: &[(u64, String)],
    entry: &Object,
    base: u64,
) -> String {
    let Some((_, layer)) = sessions
        .iter()
        .find(|(_, layer)| context.layers.is_valid(layer, base, 1))
    else {
        return format!("Cannot find a viable session layer for {base:#x}");
    };
    match crate::framework::plugins::windows::dlllist::dump_ldr_entry(
        context, layer, entry, base, "",
    ) {
        Some(name) => name,
        None => "Error outputting file".to_string(),
    }
}

/// One virtual layer per session, in the order the sessions were first seen.
///
/// Several plugins have to read memory that only exists inside a session, and
/// any process of that session will do to reach it.
pub fn session_layers(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> Vec<(u64, String)> {
    let mut seen: Vec<u64> = Vec::new();
    let mut found = Vec::new();

    for process in list_processes(context, kernel).unwrap_or_default() {
        let Ok(layer) = process.address_space(physical) else {
            continue;
        };
        // Not every process belongs to a session.
        let Ok(session) = process
            .object
            .member("Session")
            .and_then(|session| session.pointer_value())
        else {
            continue;
        };
        let Ok(space) = context.object(
            &kernel.qualified("_MM_SESSION_SPACE"),
            &kernel.layer_name,
            session,
        ) else {
            continue;
        };
        let Ok(id) = space.member("SessionId").and_then(|id| id.as_u64()) else {
            continue;
        };
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        found.push((id, layer));
    }
    found
}

/// Where kernel space begins, which is what tells a real pointer from a
/// smeared one.
pub fn kernel_space_start(context: &Arc<Context>, kernel: &Module) -> u64 {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let (type_name, default) = if sixty_four_bit {
        ("unsigned long long", 0xFFFF_8000_0000_0000u64)
    } else {
        ("unsigned long", 0x8000_0000)
    };
    // The kernel states where its own space starts. The architectural value
    // stands in when that word cannot be read.
    let mask = context.layers.address_mask(&kernel.layer_name);
    context
        .object_from_symbol(kernel, "MmSystemRangeStart", Some(type_name))
        .and_then(|value| value.as_u64())
        .unwrap_or(default)
        & mask
}
