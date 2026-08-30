//! List the loaded kernel extensions on a Mac system.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::list_extensions;

pub struct Lsmod;

impl Plugin for Lsmod {
    fn name(&self) -> &'static str {
        "mac.lsmod.Lsmod"
    }

    fn description(&self) -> &'static str {
        "Lists loaded kernel modules."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Name"),
            Column::int("Size"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        for extension in list_extensions(&context, &kernel)? {
            grid.push(
                0,
                vec![
                    Value::hex(extension.offset()),
                    or_unreadable(extension.name(), Value::string),
                    // Upstream reports the size as a plain number, not as an
                    // address, so it prints in decimal.
                    or_unreadable(extension.size(), |size| Value::int(size as i64)),
                ],
            )?;
        }
        Ok(grid)
    }
}
