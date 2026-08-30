//! List each module's imported functions.
//!
//! A module's import address table names every function it calls in another
//! module. Comparing the resolved addresses against where those modules
//! actually live is how import hooking becomes visible.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::pe;

pub struct Iat;

impl Plugin for Iat {
    fn name(&self) -> &'static str {
        "windows.iat.IAT"
    }

    fn description(&self) -> &'static str {
        "Extract Import Address Table to list API (functions) used by a program contained in external libraries"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Process ID to include (all other processes are excluded)")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Name"),
            Column::string("Library"),
            Column::bool("Bound"),
            Column::string("Function"),
            Column::new("Address", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };
            // Only the process's own image is examined: it is the one whose
            // imports say what the program itself calls.
            let Ok(base) = process
                .peb(&layer)
                .and_then(|peb| peb.member("ImageBaseAddress"))
                .and_then(|address| address.pointer_value())
            else {
                continue;
            };
            if base == 0 {
                continue;
            }

            let headers = match context.layers.read(&layer, base, 0x1000, true) {
                Ok(headers) => headers,
                Err(_) => continue,
            };
            let Ok(header) = pe::parse(&headers) else {
                continue;
            };
            let Ok(image) = context
                .layers
                .read(&layer, base, header.size_of_image as usize, true)
            else {
                continue;
            };
            let Some(imports) = pe::imports(&image) else {
                continue;
            };

            for import in imports {
                // The address reported is the slot's own, counted from the
                // image's base twice over: once by the reader of the import
                // table and once by the plugin itself.
                let address = base
                    .wrapping_mul(2)
                    .wrapping_add(import.slot as u64);

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::string(import.library.clone()),
                        Value::Bool(import.bound),
                        match import
                            .function
                            .or_else(|| ordinal_name(&import.library, import.ordinal))
                        {
                            Some(function) => Value::string(function),
                            // An import by ordinal from a library nobody keeps
                            // a list for has no name at all.
                            None => Value::not_available(),
                        },
                        Value::hex(address),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The name an ordinal stands for, in the few libraries whose ordinals are
/// commonly recorded.
///
/// A library on that list always yields a name: the recorded one where it is
/// known, and the ordinal spelled out where it is not.
fn ordinal_name(library: &str, ordinal: u16) -> Option<String> {
    let tables = ordinal_tables();
    let names = tables.get(&library.to_ascii_lowercase())?;
    Some(match names.get(&ordinal.to_string()) {
        Some(name) => name.clone(),
        None => format!("ord{ordinal}"),
    })
}

/// The ordinal-to-name tables, as they are commonly published.
fn ordinal_tables() -> &'static std::collections::HashMap<String, std::collections::HashMap<String, String>>
{
    static TABLES: std::sync::OnceLock<
        std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        serde_json::from_str(include_str!("../../../../data/pe_ordinals.json")).unwrap_or_default()
    })
}
