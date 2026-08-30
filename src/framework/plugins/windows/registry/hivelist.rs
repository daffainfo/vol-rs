//! List the registry hives loaded on the system.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct HiveList;

impl Plugin for HiveList {
    fn name(&self) -> &'static str {
        "windows.registry.hivelist.HiveList"
    }

    fn description(&self) -> &'static str {
        "Lists the registry hives present in a particular memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "filter",
                "String to filter hive names returned",
                RequirementKind::String,
            ),
            Requirement::new("dump", "Extract listed registry hives", RequirementKind::Bool),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("FileFullPath"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = config.get_string("filter");
        let mut grid = TreeGrid::new(self.columns());

        for hive in super::list_hives(&context, &kernel)? {
            // The kernel records the path under different member names across
            // versions. Report whichever is readable.
            let path = ["FileFullPath", "FileUserName", "HiveRootPath"]
                .iter()
                .find_map(|member| {
                    hive.member(member)
                        .ok()
                        .and_then(|field| unicode_string(&field).ok())
                        .filter(|name| !name.is_empty())
                });

            if let (Some(filter), Some(path)) = (&filter, &path) {
                if !path.contains(filter.as_str()) {
                    continue;
                }
            }

            grid.push(
                0,
                vec![
                    Value::hex(hive.offset()),
                    // A hive with no recorded path is normal for the in-memory
                    // ones, so it is reported absent rather than skipped.
                    match path {
                        // A hive whose name cannot be read is reported with an
                        // empty one, as upstream does, rather than as absent.
                        Some(path) => Value::string(path),
                        None => Value::string(String::new()),
                    },
                    Value::string("Disabled"),
                ],
            )?;
        }
        Ok(grid)
    }
}
