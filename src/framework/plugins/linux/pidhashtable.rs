//! Enumerate tasks through the process tree rather than the task list.
//!
//! A rootkit that hides a process unlinks it from the kernel's task list. The
//! parent/child pointers are a separate set of links, so walking those finds
//! tasks the ordinary listing misses.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{xarray_entries, Task};

pub struct PidHashTable;

impl Plugin for PidHashTable {
    fn name(&self) -> &'static str {
        "linux.pidhashtable.PIDHashTable"
    }

    fn description(&self) -> &'static str {
        "Enumerates processes through the PID hash table"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "decorate_comm",
                "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET", ColumnType::UInt),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("PPID"),
            Column::string("COMM"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let decorate = config.get_bool("decorate_comm").unwrap_or(false);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // The kernel indexes every pid in an IDR hanging off the initial pid
        // namespace, which reaches tasks through a different set of pointers
        // than the task list does.
        let namespace = context.object_from_symbol(&kernel, "init_pid_ns", Some("pid_namespace"))?;
        let entries = xarray_entries(
            &context,
            &kernel,
            &namespace.member("idr")?.member("idr_rt")?,
        )?;

        let pid_type = context.symbol_space.get_type(&kernel.qualified("pid"))?;
        let task_type = context.symbol_space.get_type(&kernel.qualified("task_struct"))?;
        let links_offset = context
            .symbol_space
            .find_member(&task_type, "pid_links")
            .or_else(|_| context.symbol_space.find_member(&task_type, "pids"))?
            .map(|(offset, _)| offset)
            .unwrap_or(0);

        // The whole listing is sorted before any of it is reported, so a read
        // that fails part-way through discards every row rather than truncating
        // the tail.
        let mut tasks = Vec::new();
        for entry in entries {
            let pid_object =
                context.object_from_template(pid_type.clone(), &kernel.layer_name, entry);
            let first = match pid_object
                .member("tasks")
                .and_then(|tasks| tasks.index(0))
                .and_then(|head| head.member("first"))
                .and_then(|first| first.pointer_value())
            {
                Ok(first) => first,
                Err(_) => {
                    grid.mark_truncated_reported();
                    return Ok(grid);
                }
            };
            if first == 0 {
                continue;
            }
            let task = Task::new(context.object_from_template(
                task_type.clone(),
                &kernel.layer_name,
                first.wrapping_sub(links_offset),
            ));
            // A pid with no readable task, or none with a parent, is skipped.
            if task.pid().map(|pid| pid == 0).unwrap_or(true) {
                continue;
            }
            tasks.push(task);
        }

        // Reported in process then thread order.
        tasks.sort_by_key(|task| (task.pid().unwrap_or(0), task.tid().unwrap_or(0)));

        for task in tasks {

            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            let comm = match task.comm() {
                Ok(name) if decorate => {
                    if task.is_kernel_thread() {
                        Value::string(format!("[{name}]"))
                    } else if task.is_thread() {
                        Value::string(format!("{{{name}}}"))
                    } else {
                        Value::string(name)
                    }
                }
                Ok(name) => Value::string(name),
                Err(_) => Value::unreadable(),
            };

            grid.push(
                0,
                vec![
                    Value::hex(task.offset()),
                    Value::int(pid as i64),
                    or_unreadable(task.tid(), |value| Value::int(value as i64)),
                    or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                    comm,
                ],
            )?;
        }
        Ok(grid)
    }
}
