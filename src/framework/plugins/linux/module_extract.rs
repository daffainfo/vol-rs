//! Extract loaded kernel modules from memory.
//!
//! A module's code stays resident while it is loaded, so it can be written back
//! out and examined offline, which is the only way to inspect a module that was
//! never present on disk.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::plugins::windows::pslist::sanitize_filename;
use crate::framework::plugins::write_extracted;
use crate::framework::symbols::linux::module_elf::extract_module;
use crate::framework::symbols::linux::KernelModule;

pub struct ModuleExtract;

impl Plugin for ModuleExtract {
    fn name(&self) -> &'static str {
        "linux.module_extract.ModuleExtract"
    }

    fn description(&self) -> &'static str {
        "Recreates an ELF file from a specific address in the kernel"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "base",
                "Base virtual address to reconstruct an ELF file",
                RequirementKind::Int,
            )
            .required(),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Base", ColumnType::UInt),
            Column::int("File Size"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let base = config.get_int("base").unwrap_or(0) as u64;
        let mut grid = TreeGrid::new(self.columns());

        // The address must name a module structure that is actually present.
        if !context.layers.is_valid(&kernel.layer_name, base, 1) {
            log::error!(
                "Given base address ({base:#x}) is not valid in the kernel address space. \
                 Unable to extract file."
            );
            return Ok(grid);
        }

        let module = KernelModule::new(context.module_object(&kernel, "module", base)?);
        let Some(data) = extract_module(&context, &kernel, &module) else {
            log::error!("Unable to reconstruct the ELF for module struct at {base:#x}");
            return Ok(grid);
        };

        let name = module.name().unwrap_or_default();
        let file = sanitize_filename(&format!("kernel_module.{name}.{base:#x}.elf"));
        if write_extracted(&file, &data).is_err() {
            log::error!("Unable to write {file}");
            return Ok(grid);
        }

        grid.push(
            0,
            vec![
                Value::hex(base),
                Value::int(data.len() as i64),
                Value::string(file),
            ],
        )?;
        Ok(grid)
    }
}
