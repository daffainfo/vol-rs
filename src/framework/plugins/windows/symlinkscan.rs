//! Scan physical memory for symbolic link objects.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::object_name;
use crate::framework::symbols::windows::poolscanner::scan_for_tag;

pub struct SymlinkScan;

impl Plugin for SymlinkScan {
    fn name(&self) -> &'static str {
        "windows.symlinkscan.SymlinkScan"
    }

    fn description(&self) -> &'static str {
        "Scans for links present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::datetime("CreateTime"),
            Column::string("From Name"),
            Column::string("To Name"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            let description =
                format!("Symlink: {} -> {}", text(&values[2]), text(&values[3]));
            timeline.push(description, TimeKind::Created, values[1].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let _layer = physical_layer(config);

        let objects = scan_for_tag(&context, &kernel, b"Symb")?;

        let mut grid = TreeGrid::new(self.columns());
        for object in objects {
            // A link with no name, or whose target cannot be read, is not
            // reported at all.
            let Some(name) = object_name(&object, &kernel) else {
                continue;
            };
            let Ok(target) = object
                .member("LinkTarget")
                .and_then(|target| unicode_string(&target))
            else {
                continue;
            };

            grid.push(
                0,
                vec![
                    Value::hex(object.offset()),
                    object
                        .member("CreationTime")
                        .and_then(|time| time.member("QuadPart"))
                        .and_then(|time| time.as_u64())
                        .map(wintime_value)
                        .unwrap_or_else(|_| Value::unreadable()),
                    // The link's own name comes from its object header.
                    Value::string(name),
                    Value::string(target),
                ],
            )?;
        }
        Ok(grid)
    }
}
