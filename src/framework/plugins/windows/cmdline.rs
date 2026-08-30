//! Report each process's command line, read from its PEB.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct CmdLine;

impl Plugin for CmdLine {
    fn name(&self) -> &'static str {
        "windows.cmdline.CmdLine"
    }

    fn description(&self) -> &'static str {
        "Lists process command line arguments."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Process IDs to include (all other processes are excluded)")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::uint("PID"),
            Column::string("Process"),
            Column::string("Args"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // The command line lives in user space, so it can only be read
            // through the process's own page tables.
            let args = match process
                .address_space(&physical)
                .and_then(|layer| process.command_line(&layer))
            {
                Ok(line) => Value::string(line),
                Err(_) => Value::unreadable(),
            };

            grid.push(
                0,
                vec![
                    Value::uint(pid),
                    process
                        .image_file_name()
                        .map(Value::string)
                        .unwrap_or_else(|_| Value::unreadable()),
                    args,
                ],
            )?;
        }
        Ok(grid)
    }
}
