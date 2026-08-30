//! List the kernel modules loaded on a Linux system.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::linux::{kernel_module, module_columns, module_rows};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid};
use crate::framework::symbols::linux::list_modules;

pub struct Lsmod;

impl Plugin for Lsmod {
    fn name(&self) -> &'static str {
        "linux.lsmod.Lsmod"
    }

    fn description(&self) -> &'static str {
        "Lists loaded kernel modules."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new("dump", "Extract listed modules", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        module_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let dump = config.get_bool("dump").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        let modules = list_modules(&context, &kernel)?
            .into_iter()
            .map(|module| (module.offset(), module));
        for row in module_rows(&context, &kernel, modules, dump) {
            grid.push(0, row)?;
        }
        Ok(grid)
    }
}
