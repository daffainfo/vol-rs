//! Report each process's environment variables.
//!
//! The environment block is a run of `NAME=VALUE` strings in the process's own
//! address space, terminated by an empty string.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, Process};

pub struct Envars;

impl Plugin for Envars {
    fn name(&self) -> &'static str {
        "windows.envars.Envars"
    }

    fn description(&self) -> &'static str {
        "Display process environment variables"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            // The reference implementation looks this up under a different
            // spelling than the one it registers, so asking for it changes
            // nothing there and changes nothing here.
            Requirement::new(
                "silent",
                "Suppress common and non-persistent variables",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Block", ColumnType::UInt),
            Column::string("Variable"),
            Column::string("Value"),
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
            let Ok((reported, variables)) = read_environment(&process, &layer) else {
                continue;
            };

            for (variable, value) in variables {
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::hex(reported),
                        Value::string(variable),
                        Value::string(value),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Read and split a process's environment block.
///
/// Returns the block's address alongside the parsed variables, since the plugin
/// reports where the block was found.
pub fn read_environment(process: &Process, layer: &str) -> Result<(u64, Vec<(String, String)>)> {
    let peb = process.peb(layer)?;
    let parameters = peb.member("ProcessParameters")?.dereference()?;
    let environment = parameters.member("Environment")?;
    let block = environment.pointer_value()?;
    // The address reported is the field's own, which is what upstream shows.
    let reported = environment.offset();

    // The block is read whole, at the size the process itself records.
    let size = parameters
        .member("EnvironmentSize")
        .or_else(|_| parameters.member("Length"))
        .and_then(|value| value.as_u64())? as usize;

    let data = process
        .object
        .context()
        .layers
        .read(layer, block, size, false)?;

    // Decoded whole, then cut into entries at the NULs. The last piece is
    // whatever follows the final terminator, and is dropped.
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let decoded = String::from_utf16_lossy(&units);
    let mut entries: Vec<&str> = decoded.split('\0').collect();
    entries.pop();

    let mut variables = Vec::new();
    for entry in entries {
        // The name is what precedes the first '='. Upstream looks for that
        // separator without checking whether it found one, so an entry that
        // has none is split at minus one instead: the name loses its last
        // character and the value is the whole entry. Reproduced, because it
        // is visible in the output.
        let (name, value) = match entry.find('=') {
            Some(split) => (&entry[..split], &entry[split + 1..]),
            None => {
                let mut characters = entry.chars();
                characters.next_back();
                (characters.as_str(), entry)
            }
        };
        // An entry with either side empty is not a variable. The hidden
        // per-drive entries, which begin with '=', are among those.
        if name.is_empty() || value.is_empty() {
            continue;
        }
        variables.push((name.to_string(), value.to_string()));
    }
    Ok((reported, variables))
}
