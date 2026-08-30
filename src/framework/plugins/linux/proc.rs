//! Report each task's memory mappings, as `/proc/pid/maps` would.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct Maps;

/// Mappings larger than this are left alone rather than written out.
pub const MAXSIZE_DEFAULT: u64 = 1024 * 1024 * 1024;

impl Plugin for Maps {
    fn name(&self) -> &'static str {
        "linux.proc.Maps"
    }

    fn description(&self) -> &'static str {
        "Lists all memory maps for all processes."
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
                 excluded). This can be any virtual address within the VMA section.",
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
                MAXSIZE_DEFAULT as i64,
            )),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
            Column::string("Flags"),
            Column::new("PgOff", ColumnType::UInt),
            Column::int("Major"),
            Column::int("Minor"),
            Column::int("Inode"),
            Column::string("File Path"),
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
            .unwrap_or(MAXSIZE_DEFAULT);
        // An address selects the mapping that contains it, so only the parts of
        // a process the caller named are reported.
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

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let comm = task.comm().unwrap_or_default();

            let mapped = task.vmas().unwrap_or_default();
            for vma in &mapped.areas {
                if !wanted.is_empty() {
                    let (Ok(start), Ok(end)) = (vma.start(), vma.end()) else {
                        continue;
                    };
                    if !wanted.iter().any(|address| (start..=end).contains(address)) {
                        continue;
                    }
                }
                // An anonymous mapping has no backing file, so the device and
                // inode columns are zero rather than absent, matching /proc.
                let (major, minor, inode) = vma.device_and_inode().unwrap_or((0, 0, 0));

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        vma.start().map(Value::hex).unwrap_or_else(|_| Value::unreadable()),
                        vma.end().map(Value::hex).unwrap_or_else(|_| Value::unreadable()),
                        Value::string(vma.protection()),
                        vma.page_offset()
                            .map(Value::hex)
                            .unwrap_or_else(|_| Value::unreadable()),
                        Value::int(major as i64),
                        Value::int(minor as i64),
                        Value::int(inode as i64),
                        match vma.name(&task) {
                            Some(path) => Value::string(path),
                            None => Value::not_available(),
                        },
                        if dump {
                            dump_vma(&context, &task, pid, vma, maxsize)
                        } else {
                            Value::string("Disabled")
                        },
                    ],
                )?;
            }

            // The reference implementation reads the backing inode without
            // checking it resolved, and stops producing output where that
            // fails. Stopping here too keeps the two listings identical.
            if mapped.truncated {
                grid.mark_truncated();
                break;
            }
        }
        Ok(grid)
    }
}

/// Write one mapping's contents out, named for the process and the range.
///
/// Pages the capture does not hold are written as zeros, so the file keeps the
/// shape the mapping had.
fn dump_vma(
    context: &Arc<Context>,
    task: &crate::framework::symbols::linux::Task,
    pid: u64,
    vma: &crate::framework::symbols::linux::Vma,
    maxsize: u64,
) -> Value {
    let (Ok(start), Ok(end)) = (vma.start(), vma.end()) else {
        return Value::string("Error outputting file");
    };
    let Ok(Some(layer)) = task.process_layer() else {
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
    let Ok(data) = context.layers.read(&layer, start, size as usize, true) else {
        return Value::string("Error outputting file");
    };
    match crate::framework::plugins::write_extracted(&name, &data) {
        Ok(_) => Value::string(name),
        Err(_) => Value::string("Error outputting file"),
    }
}
