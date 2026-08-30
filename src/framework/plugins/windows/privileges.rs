//! Report the privileges held by each process's token.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::sid_data::privilege;

pub struct Privileges;

impl Plugin for Privileges {
    fn name(&self) -> &'static str {
        "windows.privileges.Privs"
    }

    fn description(&self) -> &'static str {
        "Lists process token privileges"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::int("Value"),
            Column::string("Privilege"),
            Column::string("Attributes"),
            Column::string("Description"),
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
            let name = process.image_file_name().unwrap_or_default();

            for (luid, present, enabled, default) in process.privileges().unwrap_or_default() {
                // A bit position the system gives no name to is not a
                // privilege, whatever the token says about it.
                let Some((privilege_name, description)) = privilege(luid) else {
                    continue;
                };

                let mut attributes = Vec::new();
                if present {
                    attributes.push("Present");
                }
                if enabled {
                    attributes.push("Enabled");
                }
                if default {
                    attributes.push("Default");
                }

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::int(luid as i64),
                        Value::string(privilege_name),
                        Value::string(attributes.join(",")),
                        Value::string(description),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
