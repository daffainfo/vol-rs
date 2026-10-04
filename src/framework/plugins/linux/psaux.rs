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
use crate::framework::symbols::linux::{list_tasks_filtered, Task};

/// Lists processes with their command line arguments
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

        // Upstream filters on the kernel's own `pid`, which is the thread
        // identifier, and does it while walking the list, so a process that
        // matches brings its threads with it.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        // walk the process list and report the arguments
        for task in list_tasks_filtered(&context, &kernel, false, &selected)? {
            let Ok(pid) = task.tid() else { continue };
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

/// Reads the command line arguments of a process.
///
/// These are stored on the userland stack. Kernel threads re-use the process
/// data structure, but do not have a valid 'mm' pointer.
///
/// # Parameters
///
/// * `task` - task_struct object of the process
/// * `name` - string name of the process (from task.comm)
///
/// Returns `None` when the arguments should be reported as unreadable.
fn read_arguments(task: &Task, name: &str) -> Option<String> {
    // kernel threads never have an mm as they do not have userland mappings
    let mut args = match task.mm() {
        Ok(Some(mm)) => {
            // read argv from userland
            let layer = task.process_layer().ok().flatten()?;
            let start = mm.member("arg_start").ok()?.as_u64().ok()?;
            let end = mm.member("arg_end").ok()?.as_u64().ok()?;

            // get the size of the arguments with sanity checking
            let size = end.checked_sub(start)?;
            if size == 0 || size > MAX_ARGUMENT_BYTES {
                return None;
            }

            // attempt to read it all as partial values are invalid and misleading
            let data = task
                .object
                .context()
                .layers
                .read(&layer, start, size as usize, false)
                .ok()?;

            // the arguments are null byte terminated, replace the nulls with
            // spaces. Every NUL is an argument boundary, including a trailing
            // one, so the empty trailing field contributes the space stripped
            // below.
            data.split(|&byte| byte == 0)
                .map(|argument| String::from_utf8_lossy(argument).to_string())
                .collect::<Vec<String>>()
                .join(" ")
        }
        // kernel thread. [ ] mimics ps on a live system, and also helps identify
        // malware masquerading as a kernel thread, which is fairly common.
        _ => format!("[{name}]"),
    };

    // remove trailing space, if present
    if args.len() > 1 && args.ends_with(' ') {
        args.pop();
    }
    Some(args)
}
