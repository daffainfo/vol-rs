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

/// Lists processes with their environment variables
pub struct Envars;

impl Plugin for Envars {
    fn name(&self) -> &'static str {
        "linux.envars.Envars"
    }

    fn description(&self) -> &'static str {
        "Lists processes with their environment variables"
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
            Column::string("KEY"),
            Column::string("VALUE"),
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

        // walk the process list and return the envars
        for task in list_tasks_filtered(&context, &kernel, false, &selected)? {
            if task.is_kernel_thread() {
                continue;
            }
            let Ok(pid) = task.tid() else { continue };

            for entry in task.environment().unwrap_or_default() {
                // Some legitimate programs, like 'avahi-daemon', avoid reallocating the args
                // and instead exploit the fact that the environment variables area is contiguous
                // to the args. This allows them to include a longer process name in the listing,
                // causing overwrites and incorrect results. In such cases, it's better to abort
                // the current task rather than displaying misleading or incorrect output.
                let Some((key, value)) = entry.split_once('=') else {
                    break;
                };
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                        or_unreadable(task.comm(), Value::string),
                        Value::string(key),
                        Value::string(value),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
