//! List the files each process has open.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::list_processes;

pub struct Lsof;

impl Plugin for Lsof {
    fn name(&self) -> &'static str {
        "mac.lsof.Lsof"
    }

    fn description(&self) -> &'static str {
        "Lists all open file descriptors for all processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::int("File Descriptor"),
            Column::string("File Path"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            for (_, path, descriptor) in process.file_descriptors() {
                // A descriptor the kernel has not named is not reported.
                let Some(path) = path.filter(|path| !path.is_empty()) else {
                    continue;
                };
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::int(descriptor as i64),
                        Value::string(path),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
