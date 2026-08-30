//! Scan physical memory for mutex objects.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::object_name;
use crate::framework::symbols::windows::poolscanner::scan_for_tag;

pub struct MutantScan;

impl Plugin for MutantScan {
    fn name(&self) -> &'static str {
        "windows.mutantscan.MutantScan"
    }

    fn description(&self) -> &'static str {
        "Scans for mutexes present in a particular windows memory image."
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

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let _layer = physical_layer(config);
        let _kernel_for_validate = kernel.clone();

        let objects = scan_for_tag(&context, &kernel, b"Muta")?;

        let mut grid = TreeGrid::new(self.columns());
        for object in objects {
            // An unnamed mutant is legitimate, so report it with an absent name
            // rather than dropping the row.
            let name = match object_name(&object, &kernel) {
                Some(name) => Value::string(name),
                // An object the kernel gives no name at all is reported as
                // not applicable. One whose name is empty keeps its emptiness.
                None => Value::not_applicable(),
            };
            grid.push(0, vec![Value::hex(object.offset()), name])?;
        }
        Ok(grid)
    }
}
