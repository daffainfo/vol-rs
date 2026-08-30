//! Recover console command history from `conhost` memory.
//!
//! The console host keeps each window's typed commands in a history buffer:
//! an array of pointers to counted UTF-16 strings. Upstream locates that buffer
//! through symbols from the `conhost` PDB. This port has no PDB parser, so it
//! instead finds the history by its shape, a run of counted strings that read
//! as plausible command lines, and reports what it recovers.
//!
//! The consequence is that the `ConsoleInfo` address is the buffer that was
//! found rather than the console structure that owns it, and the structural
//! properties upstream reports alongside the commands are not available.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer, vadinfo};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

/// The processes that host consoles across Windows versions.
/// The console host, which is the only process that keeps console state.
const CONSOLE_HOSTS: &[&str] = &["conhost.exe"];

/// A command longer than this is not a console line.
const MAX_COMMAND_CHARS: usize = 512;

/// The shortest run of recovered commands worth reporting, which keeps
/// coincidental UTF-16 text out of the results.
const MIN_RUN: usize = 2;

pub struct Consoles;

impl Plugin for Consoles {
    fn name(&self) -> &'static str {
        "windows.consoles.Consoles"
    }

    fn description(&self) -> &'static str {
        "Looks for Windows console buffers"
    }

    fn requirements(&self) -> Vec<Requirement> {
        console_requirements(true)
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        console_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        run_console_scan(context, config, console_columns())
    }
}

/// Reports the same recovered history under the historical plugin name.
pub struct CmdScan;

impl Plugin for CmdScan {
    fn name(&self) -> &'static str {
        "windows.cmdscan.CmdScan"
    }

    fn description(&self) -> &'static str {
        "Looks for Windows Command History lists"
    }

    fn requirements(&self) -> Vec<Requirement> {
        console_requirements(false)
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        console_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        run_console_scan(context, config, console_columns())
    }
}

fn console_columns() -> Vec<Column> {
    vec![
        Column::int("PID"),
        Column::string("Process"),
        Column::new("ConsoleInfo", ColumnType::UInt),
        Column::string("Property"),
        Column::new("Address", ColumnType::UInt),
        Column::string("Data"),
    ]
}

/// The options both console plugins take.
///
/// The console host is searched for histories of the sizes the system was
/// configured for, which are either given here or read out of the registry.
/// Only the console listing reports the buffer count.
fn console_requirements(with_buffers: bool) -> Vec<Requirement> {
    let mut requirements = vec![
        Requirement::kernel(),
        Requirement::new(
            "no_registry",
            if with_buffers {
                "Don't search the registry for possible values of CommandHistorySize and \
                 HistoryBufferMax"
            } else {
                "Don't search the registry for possible values of CommandHistorySize"
            },
            RequirementKind::Bool,
        )
        .with_default(ConfigValue::Bool(false)),
        Requirement::new(
            "max_history",
            "CommandHistorySize values to search for.",
            RequirementKind::List(Box::new(RequirementKind::Int)),
        )
        .with_default(ConfigValue::List(vec![ConfigValue::Int(
            DEFAULT_HISTORY_SIZE,
        )])),
    ];
    if with_buffers {
        requirements.push(
            Requirement::new(
                "max_buffers",
                "HistoryBufferMax values to search for.",
                RequirementKind::List(Box::new(RequirementKind::Int)),
            )
            .with_default(ConfigValue::List(vec![ConfigValue::Int(
                DEFAULT_BUFFER_COUNT,
            )])),
        );
    }
    requirements
}

/// How many commands a console keeps by default.
const DEFAULT_HISTORY_SIZE: i64 = 50;

/// How many history buffers a console keeps by default.
const DEFAULT_BUFFER_COUNT: i64 = 4;

/// The console sizes to search for: those asked for, plus whatever the
/// registry says the system was configured with.
fn console_settings(
    context: &Arc<Context>,
    config: &Configuration,
    kernel: &crate::framework::context::Module,
) -> (u64, u64) {
    let read = |name: &str, fallback: i64| -> Vec<i64> {
        config
            .get(name)
            .and_then(|value| {
                value.as_list().map(|list| {
                    list.iter().filter_map(|entry| entry.as_int()).collect::<Vec<i64>>()
                })
            })
            .filter(|values: &Vec<i64>| !values.is_empty())
            .unwrap_or_else(|| vec![fallback])
    };
    let mut history = read("max_history", DEFAULT_HISTORY_SIZE);
    let mut buffers = read("max_buffers", DEFAULT_BUFFER_COUNT);

    if !config.get_bool("no_registry").unwrap_or(false) {
        // A user hive records the console sizes that user's shells were given.
        for (name, number) in console_key_values(context, kernel) {
            match name.as_str() {
                "HistoryBufferSize" => history.push(number),
                "NumberOfHistoryBuffers" => buffers.push(number),
                _ => {}
            }
        }
    }

    (
        history.into_iter().max().unwrap_or(DEFAULT_HISTORY_SIZE).max(0) as u64,
        buffers.into_iter().max().unwrap_or(DEFAULT_BUFFER_COUNT).max(0) as u64,
    )
}

/// The values under every hive's `Console` key.
fn console_key_values(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Vec<(String, i64)> {
    use crate::framework::symbols::windows::registry::{read_key, subkeys, values};

    let mut found = Vec::new();
    for hive_object in
        crate::framework::plugins::windows::registry::list_hives(context, kernel).unwrap_or_default()
    {
        let Ok(hive) =
            crate::framework::plugins::windows::registry::open_hive(context, kernel, hive_object)
        else {
            continue;
        };
        let table = kernel.symbol_table_name.clone();
        let Ok(root) = read_key(context, &hive, &table, hive.root_cell_offset(), String::new())
        else {
            continue;
        };
        for child in subkeys(context, &hive, &table, &root).unwrap_or_default() {
            if child.name().map(|name| name != "Console").unwrap_or(true) {
                continue;
            }
            for value in values(context, &hive, &table, &child).unwrap_or_default() {
                let Ok(name) = value.name() else { continue };
                let Ok(data) = value.data(&hive) else { continue };
                if data.len() >= 4 {
                    let number =
                        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64;
                    found.push((name, number));
                }
            }
        }
    }
    found
}

/// Search each console host's writable memory for command history.
fn run_console_scan(
    context: Arc<Context>,
    config: &Configuration,
    columns: Vec<Column>,
) -> Result<TreeGrid> {
    let kernel = kernel_module(&context, config)?;
    let physical = physical_layer(config);
    let filter = pid_filter(config);
    let (max_history, max_buffers) = console_settings(&context, config, &kernel);
    let mut grid = TreeGrid::new(columns);

    for process in list_processes(&context, &kernel)? {
        let Ok(pid) = process.pid() else { continue };
        if !pid_matches(&filter, pid) {
            continue;
        }
        let name = process.image_file_name().unwrap_or_default();
        if !CONSOLE_HOSTS
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&name))
        {
            continue;
        }

        let Ok(layer) = process.address_space(&physical) else {
            continue;
        };

        // The history lives in the host's private heap: writable, executable
        // nowhere, and backed by no file.
        for vad in vadinfo::walk_vad_tree(&context, &kernel, &process).unwrap_or_default() {
            let protection = vadinfo::protection(&vad).unwrap_or_default();
            if !protection.contains("READWRITE") || vadinfo::file_name_of(&vad).is_some() {
                continue;
            }
            let (Some(start), Some(end)) = (vadinfo::start_vpn(&vad), vadinfo::end_vpn(&vad))
            else {
                continue;
            };

            let length = (end.saturating_sub(start) + 1).min(0x400000) as usize;
            let Ok(data) = context.layers.read(&layer, start, length, true) else {
                continue;
            };

            // A console keeps a bounded number of buffers, each holding a
            // bounded number of commands.
            for (offset, commands) in find_history(&data).into_iter().take(max_buffers as usize) {
                for command in commands.into_iter().take(max_history as usize) {
                    grid.push(
                        0,
                        vec![
                            Value::int(pid as i64),
                            Value::string(name.clone()),
                            Value::hex(start + offset as u64),
                            Value::string("HistoryBuffer"),
                            Value::hex(start + offset as u64),
                            Value::string(command),
                        ],
                    )?;
                }
            }
        }
    }
    Ok(grid)
}

/// Find runs of counted UTF-16 strings that read as command lines.
///
/// Each entry is a byte count followed by the characters, which is how the
/// console host stores them. A run of consecutive valid entries is a history
/// buffer rather than coincidence.
fn find_history(data: &[u8]) -> Vec<(usize, Vec<String>)> {
    let mut results = Vec::new();
    let mut position = 0usize;

    while position + 4 < data.len() {
        let Some(first) = read_counted(data, position) else {
            position += 2;
            continue;
        };

        // Follow consecutive entries for as long as they keep parsing.
        let start = position;
        let mut commands = vec![first.0];
        let mut cursor = first.1;

        while let Some((command, next)) = read_counted(data, cursor) {
            commands.push(command);
            cursor = next;
            if commands.len() > 256 {
                break;
            }
        }

        if commands.len() >= MIN_RUN {
            results.push((start, commands));
            position = cursor;
        } else {
            position += 2;
        }
    }
    results
}

/// Read one counted UTF-16 string, returning it and the offset after it.
fn read_counted(data: &[u8], at: usize) -> Option<(String, usize)> {
    let length = u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?) as usize;
    // The count is in bytes and must be even, since the characters are UTF-16.
    if length == 0 || length % 2 != 0 || length > MAX_COMMAND_CHARS * 2 {
        return None;
    }

    // The count is followed by a capacity word before the characters begin.
    let start = at + 4;
    let bytes = data.get(start..start + length)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16(&units).ok()?;

    // A command line is printable text. Anything else is binary that happened
    // to carry a plausible length.
    if text.is_empty() || !text.chars().all(|c| !c.is_control()) {
        return None;
    }
    Some((text, start + length))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a buffer holding two consecutive counted commands.
    fn build_history(commands: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        for command in commands {
            let units: Vec<u8> = command
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            data.extend_from_slice(&units);
        }
        data.extend_from_slice(&[0u8; 8]);
        data
    }

    #[test]
    fn recovers_a_run_of_commands() {
        let data = build_history(&["whoami", "net user /add attacker"]);
        let found = find_history(&data);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, vec!["whoami", "net user /add attacker"]);
    }

    #[test]
    fn a_single_plausible_string_is_not_a_history() {
        // One match is far too weak a signal to report on its own.
        let data = build_history(&["dir"]);
        assert!(find_history(&data).is_empty());
    }

    #[test]
    fn binary_data_is_not_mistaken_for_commands() {
        let noise = vec![0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0, 0, 0, 0];
        assert!(find_history(&noise).is_empty());
    }
}
