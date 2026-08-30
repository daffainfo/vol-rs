//! Report each process's memory mappings.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::list_processes;

pub struct Maps;

impl Plugin for Maps {
    fn name(&self) -> &'static str {
        "mac.proc_maps.Maps"
    }

    fn description(&self) -> &'static str {
        "Lists process memory ranges that potentially contain injected code."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "dump",
                "Extract listed memory segments",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "address",
                "Process virtual memory addresses to include (all other VMA sections are \
                 excluded). This can be any virtual address within the VMA section. Virtual \
                 addresses must be separated by a space.",
                crate::framework::plugins::RequirementKind::List(Box::new(
                    crate::framework::plugins::RequirementKind::Int,
                )),
            ),
            Requirement::new(
                "maxsize",
                "Maximum size for dumped VMA sections (all the bigger sections will be ignored)",
                crate::framework::plugins::RequirementKind::Int,
            )
            .with_default(crate::framework::context::ConfigValue::Int(
                crate::framework::plugins::linux::proc::MAXSIZE_DEFAULT as i64,
            )),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
            Column::string("Protection"),
            Column::string("Map Name"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);
        let maxsize = config
            .get_int("maxsize")
            .map(|value| value as u64)
            .unwrap_or(crate::framework::plugins::linux::proc::MAXSIZE_DEFAULT);
        // An address selects the mapping that contains it.
        let wanted: Vec<u64> = config
            .get("address")
            .and_then(|value| {
                value.as_list().map(|list| {
                    list.iter()
                        .filter_map(|entry| entry.as_int().map(|address| address as u64))
                        .collect()
                })
            })
            .unwrap_or_default();
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.name().unwrap_or_default();
            // The mappings are dumped from the process's own address space, so
            // the layer that reads it is built once for the whole process.
            let layer = process.process_layer().ok().flatten();

            for entry in process.vm_map_entries().unwrap_or_default() {
                let (Ok(start), Ok(end)) = (entry.start(), entry.end()) else {
                    continue;
                };
                if !wanted.is_empty()
                    && !wanted.iter().any(|address| (start..=end).contains(address))
                {
                    continue;
                }
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        or_unreadable(entry.start(), Value::hex),
                        or_unreadable(entry.end(), Value::hex),
                        Value::string(entry.protection()),
                        // A mapping that no file backs is named for the part
                        // of the process it belongs to, if it is a named part.
                        Value::string(match entry.path(&kernel) {
                            path if path.is_empty() => entry.special_path(),
                            path => path,
                        }),
                        if dump {
                            dump_region(&context, layer.as_deref(), pid, start, end, maxsize)
                        } else {
                            Value::string("Disabled")
                        },
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Write one mapping's contents out, named for the process and the range.
fn dump_region(
    context: &Arc<Context>,
    layer: Option<&str>,
    pid: u64,
    start: u64,
    end: u64,
    maxsize: u64,
) -> Value {
    let Some(layer) = layer else {
        return Value::string("Error outputting file");
    };
    if end < start {
        log::warn!(
            "Skip virtual memory dump for pid {pid} between {start:#x}-{end:#x} as \
             {} is negative.",
            end as i64 - start as i64
        );
        return Value::string("Error outputting file");
    }
    let size = end - start;
    if maxsize <= size {
        log::warn!(
            "Skip virtual memory dump for pid {pid} between {start:#x}-{end:#x} as {size} is \
             larger than maxsize limit of {maxsize}"
        );
        return Value::string("Error outputting file");
    }

    let name = format!("pid.{pid}.vma.{start:#x}-{end:#x}.dmp");
    let Ok(data) = context.layers.read(layer, start, size as usize, true) else {
        return Value::string("Error outputting file");
    };
    match crate::framework::plugins::write_extracted(&name, &data) {
        Ok(_) => Value::string(name),
        Err(_) => Value::string("Error outputting file"),
    }
}
