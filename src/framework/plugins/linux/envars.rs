//! Report each task's environment variables.
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
use crate::framework::symbols::linux::list_tasks;

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

        for task in list_tasks(&context, &kernel, false)? {
            if task.is_kernel_thread() {
                continue;
            }
            let Ok(pid) = task.tid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            for entry in task.environment().unwrap_or_default() {
                // A program that reuses the environment area to hold a longer
                // argument vector overwrites it, so an entry without an '='
                // means everything after it is unreliable, not merely odd.
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
