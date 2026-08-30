//! Write a mapped PE image back out as a file.
//!
//! A module's headers and sections stay resident while it is loaded, so the
//! image can be rebuilt into a file and analysed offline, which is the only way
//! to inspect a module that was never written to disk.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, pe};

pub struct PeDump;

impl Plugin for PeDump {
    fn name(&self) -> &'static str {
        "windows.pedump.PEDump"
    }

    fn description(&self) -> &'static str {
        "Allows extracting PE Files from a specific address in a specific address space"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process IDs to include (all other processes are excluded)"),
            Requirement::new(
                "base",
                "Base address to reconstruct a PE file",
                RequirementKind::Int,
            )
            .required(),
            Requirement::new(
                "kernel_module",
                "Extract from kernel address space.",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        let base = config.get_int("base").unwrap_or(0) as u64;
        let from_kernel = config.get_bool("kernel_module").unwrap_or(false);
        let filter = pid_filter(config);

        // The image is either the kernel's or a process's. Asking for both, or
        // for neither, says nothing about where to look.
        if from_kernel && filter.is_some() {
            log::error!("Only 'kernel-module' or 'pid' should be set, not both");
            return Ok(grid);
        }
        if !from_kernel && filter.is_none() {
            log::error!("Either 'kernel-module' or 'pid' argument must be set");
            return Ok(grid);
        }

        if from_kernel {
            // A driver loaded into a session is only mapped inside it, so the
            // image is read through a session that can see the address.
            let sessions = crate::framework::plugins::windows::modules::session_layers(
                &context, &kernel, &physical,
            );
            let Some((_, layer)) = sessions
                .iter()
                .find(|(_, layer)| context.layers.is_valid(layer, base, 1))
            else {
                log::warn!(
                    "Unable to find a session layer with the provided base address mapped in the kernel."
                );
                return Ok(grid);
            };

            // The kernel is reported against the System process, which is what
            // owns its address space.
            const SYSTEM_PID: i64 = 4;
            if let Some(name) = dump(&context, layer, base, 0, SYSTEM_PID as u64) {
                grid.push(
                    0,
                    vec![
                        Value::int(SYSTEM_PID),
                        Value::string("Kernel"),
                        Value::string(name),
                    ],
                )?;
            }
            return Ok(grid);
        }

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();
            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };

            if let Some(file) = dump(&context, &layer, base, process.object.offset(), pid) {
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name),
                        Value::string(file),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Rebuild the image at `base` and write it out, naming the file after where
/// it came from.
fn dump(
    context: &Arc<Context>,
    layer: &str,
    base: u64,
    process_offset: u64,
    pid: u64,
) -> Option<String> {
    let name = format!("PE.{process_offset:#x}.{pid}.{base:#x}.dmp");
    let data = match pe::reconstruct(context, layer, base) {
        Ok(data) => data,
        Err(error) => {
            log::debug!("Unable to dump PE file at offset {base}: {error}");
            return None;
        }
    };
    // The name reported is the one asked for, since it is reported as the file
    // is opened rather than after it is written.
    crate::framework::plugins::write_extracted(&name, &data).ok()?;
    Some(name)
}
