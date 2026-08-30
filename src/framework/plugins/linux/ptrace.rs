//! Report which processes are tracing which others.
//!
//! `ptrace` gives one process complete control over another: reading its
//! memory, altering its registers, intercepting its system calls. An unexpected
//! tracing relationship is worth explaining.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{list_tasks_filtered, Task};

pub struct Ptrace;

/// The ptrace flags a traced task can carry.
fn flag_names(flags: u64) -> String {
    let mut names: Vec<&str> = Vec::new();
    if flags & 0x0001 != 0 {
        names.push("PT_PTRACED");
    }
    if flags & 0x0002 != 0 {
        names.push("PT_DTRACE");
    }
    if flags & 0x0004 != 0 {
        names.push("PT_SEIZED");
    }
    if flags & 0x0010 != 0 {
        names.push("PT_TRACESYSGOOD");
    }
    if names.is_empty() {
        return String::new();
    }
    names.join(",")
}

impl Plugin for Ptrace {
    fn name(&self) -> &'static str {
        "linux.ptrace.Ptrace"
    }

    fn description(&self) -> &'static str {
        "Enumerates ptrace's tracer and tracee tasks"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Process"),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("Tracer TID"),
            Column::int("Tracee TID"),
            Column::string("Flags"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let task_type = kernel.qualified("task_struct");
        let mut grid = TreeGrid::new(self.columns());

        // The filter selects processes. A selected process brings its
        // threads with it, whatever their own ids.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        for task in list_tasks_filtered(&context, &kernel, true, &selected)? {
            let Ok(pid) = task.pid() else { continue };

            let tracer = tracer_tid(&task);
            // Each task heads a list of the tasks it is tracing.
            let tracees: Vec<i64> = task
                .object
                .member("ptraced")
                .and_then(|head| walk_list(&head, &task_type, "ptrace_entry", true))
                .unwrap_or_default()
                .into_iter()
                .map(Task::new)
                .filter_map(|tracee| tracee.tid().ok())
                .map(|tid| tid as i64)
                .collect();

            // A task neither tracing nor traced is not part of any
            // relationship, so reporting it would only add noise.
            if tracer.is_none() && tracees.is_empty() {
                continue;
            }

            let flags = task
                .object
                .member("ptrace")
                .and_then(|flags| flags.as_u64())
                .unwrap_or(0);

            // One row per relationship, so a task tracing several others is
            // fully described.
            let tracee_cells: Vec<Value> = if tracees.is_empty() {
                vec![Value::not_applicable()]
            } else {
                tracees.into_iter().map(Value::int).collect()
            };

            for tracee in tracee_cells {
                grid.push(
                    0,
                    vec![
                        or_unreadable(task.comm(), Value::string),
                        Value::int(pid as i64),
                        or_unreadable(task.tid(), |value| Value::int(value as i64)),
                        match tracer {
                            Some(tid) => Value::int(tid as i64),
                            None => Value::not_applicable(),
                        },
                        tracee,
                        Value::string(flag_names(flags)),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The thread that is tracing this task, if one is.
fn tracer_tid(task: &Task) -> Option<u64> {
    let parent = task.object.member("parent").ok()?;
    let real_parent = task.object.member("real_parent").ok()?;

    // A traced task's parent is temporarily reassigned to its tracer, so the
    // two parent pointers differ exactly when tracing is in effect.
    let parent_address = parent.pointer_value().ok()?;
    let real_address = real_parent.pointer_value().ok()?;
    if parent_address == real_address || parent_address == 0 {
        return None;
    }

    parent.dereference().ok()?.member("pid").ok()?.as_u64().ok()
}
