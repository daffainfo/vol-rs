//! Report each process's command line arguments.
//!
//! The arguments live at the bottom of the process's stack, delimited by the
//! `arg_start` and `arg_end` pointers the kernel records in the memory
//! descriptor.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{list_tasks, Task};

pub struct PsAux;

/// Refuse to read an argument block larger than this. A bigger one means the
/// pointers were misread rather than that the command line is enormous.
const MAX_ARGUMENT_BYTES: u64 = 4096;

impl Plugin for PsAux {
    fn name(&self) -> &'static str {
        "linux.psaux.PsAux"
    }

    fn description(&self) -> &'static str {
        "Lists processes with their command line arguments"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::int("PPID"),
            Column::string("COMM"),
            Column::string("ARGS"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.tid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = task.comm().unwrap_or_default();

            grid.push(
                0,
                vec![
                    Value::int(pid as i64),
                    or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                    or_unreadable(task.comm(), Value::string),
                    read_arguments(&task, &name)
                        .map(Value::string)
                        .unwrap_or_else(Value::unreadable),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Read and join a task's NUL-separated argument vector.
///
/// Returns `None` when the arguments should be reported as unreadable.
fn read_arguments(task: &Task, name: &str) -> Option<String> {
    let mut args = match task.mm() {
        Ok(Some(mm)) => {
            // The argument vector lives in the process's own address space.
            let layer = task.process_layer().ok().flatten()?;
            let start = mm.member("arg_start").ok()?.as_u64().ok()?;
            let end = mm.member("arg_end").ok()?.as_u64().ok()?;

            // A block outside this range means the pointers were misread. A
            // partial read would be misleading, so report nothing instead.
            let size = end.checked_sub(start)?;
            if size == 0 || size > MAX_ARGUMENT_BYTES {
                return None;
            }

            let data = task
                .object
                .context()
                .layers
                .read(&layer, start, size as usize, false)
                .ok()?;

            // Every NUL is an argument boundary, including a trailing one, so
            // the empty trailing field contributes the space stripped below.
            data.split(|&byte| byte == 0)
                .map(|argument| String::from_utf8_lossy(argument).to_string())
                .collect::<Vec<String>>()
                .join(" ")
        }
        // A kernel thread has no user address space. Bracketing the name is what
        // `ps` shows, and makes malware posing as a kernel thread stand out.
        _ => format!("[{name}]"),
    };

    if args.len() > 1 && args.ends_with(' ') {
        args.pop();
    }
    Some(args)
}
