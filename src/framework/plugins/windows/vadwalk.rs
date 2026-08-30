//! Walk the VAD tree, reporting its structure rather than its contents.
//!
//! Where `vadinfo` describes what each region is, this shows how the tree is
//! shaped, useful when the tree itself is suspected of being corrupt.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

use super::vadinfo;

pub struct VadWalk;

impl Plugin for VadWalk {
    fn name(&self) -> &'static str {
        "windows.vadwalk.VadWalk"
    }

    fn description(&self) -> &'static str {
        "Walk the VAD tree."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Process IDs to include (all other processes are excluded)")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Offset", ColumnType::UInt),
            Column::new("Parent", ColumnType::UInt),
            Column::new("Left", ColumnType::UInt),
            Column::new("Right", ColumnType::UInt),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
            Column::string("Tag"),
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

            for vad in vadinfo::walk_vad_tree(&context, &kernel, &process).unwrap_or_default() {
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::hex(vad.offset()),
                        vadinfo::parent(&vad)
                            // Masked to the bits the layer addresses.
                            .map(|address| {
                                Value::hex(address & context.layers.address_mask(&kernel.layer_name))
                            })
                            .unwrap_or_else(Value::unreadable),
                        vadinfo::child(&vad, false)
                            .map(Value::hex)
                            .unwrap_or_else(Value::unreadable),
                        vadinfo::child(&vad, true)
                            .map(Value::hex)
                            .unwrap_or_else(Value::unreadable),
                        vadinfo::start_vpn(&vad)
                            .map(Value::hex)
                            .unwrap_or_else(Value::unreadable),
                        vadinfo::end_vpn(&vad)
                            .map(Value::hex)
                            .unwrap_or_else(Value::unreadable),
                        vadinfo::tag(&context, &vad)
                            .map(Value::string)
                            .unwrap_or_else(Value::unreadable),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
