//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::scan_for_tags;

/// Scans for file objects present in a particular windows memory image.
pub struct FileScan;

impl Plugin for FileScan {
    fn name(&self) -> &'static str {
        "windows.filescan.FileScan"
    }

    fn description(&self) -> &'static str {
        "Scans for file objects present in a particular windows memory image."
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
            Column::string("Name"),
        ]
    }

    /// Scans for file objects using the poolscanner module and constraints.
    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let _layer = physical_layer(config);

        // The tag gained its high bit when the allocation moved into the
        // protected pool, so both spellings are searched for.
        let objects = scan_for_tags(&context, &kernel, &[b"Fil\xe5", b"File"])?;

        let mut grid = TreeGrid::new(self.columns());
        for object in objects {
            // A file whose name cannot be read is not reported at all.
            let Ok(name) = object
                .member("FileName")
                .and_then(|name| unicode_string(&name))
            else {
                continue;
            };
            grid.push(0, vec![Value::hex(object.offset()), Value::string(name)])?;
        }
        Ok(grid)
    }
}
