//! Find tasks by scanning memory rather than walking the task list.
//!
//! A task unlinked from the list to hide it still occupies memory, so scanning
//! for structures that look like tasks recovers it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, MultiStringScanner};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::Task;

pub struct PsScan;


impl Plugin for PsScan {
    fn name(&self) -> &'static str {
        "linux.psscan.PsScan"
    }

    fn description(&self) -> &'static str {
        "Scans for processes present in a particular linux image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET (P)", ColumnType::UInt),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("PPID"),
            Column::string("COMM"),
            Column::string("EXIT_STATE"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // Every task points at one of the kernel's scheduling classes, and
        // those live at a handful of known addresses. Searching physical memory
        // for those pointers finds tasks whether or not they are still on the
        // task list.
        let space = context.symbol_space.table(&kernel.symbol_table_name)?;
        let task_type = context.symbol_space.get_type(&kernel.qualified("task_struct"))?;
        let sched_class_offset = context
            .symbol_space
            .find_member(&task_type, "sched_class")?
            .map(|(offset, _)| offset)
            .ok_or_else(|| {
                crate::error::VolatilityError::Other(
                    "task_struct has no sched_class member".to_string(),
                )
            })?;

        let mut needles: Vec<Vec<u8>> = Vec::new();
        for name in space.symbols() {
            if !name.contains("_sched_class") {
                continue;
            }
            let Ok(address) = context.symbol_offset(&kernel, name) else {
                continue;
            };
            needles.push(canonical(address).to_le_bytes().to_vec());
        }
        if needles.is_empty() {
            return Ok(TreeGrid::new(self.columns()));
        }

        // The scan runs over the machine's physical memory, beneath the kernel's
        // own address space.
        let physical = physical_layer(&context, &kernel);
        let kernel_mask = context.layers.address_mask(&kernel.layer_name);
        let layer = context.layers.get(&physical)?;
        let scanner = MultiStringScanner::new(needles)?;

        let mut hits: Vec<u64> = Vec::new();
        scan_layer(
            layer.as_ref(),
            &context.layers,
            &scanner,
            None,
            |offset| hits.push(offset),
        )?;

        let mut grid = TreeGrid::new(self.columns());
        for hit in hits {
            let Some(address) = hit.checked_sub(sched_class_offset) else {
                continue;
            };
            // The task itself is read from physical memory. The pointers inside
            // it still name addresses in the kernel's own space.
            let task = Task::new(context.object_from_template(
                task_type.clone(),
                &physical,
                address,
            ));

            let Ok(state) = task.object.member("exit_state").and_then(|s| s.as_u64()) else {
                continue;
            };
            let Some(state) = exit_state_name(state) else {
                continue;
            };
            // A plausible process id is the other half of the sanity check.
            let Ok(tid) = task.tid() else { continue };
            if tid == 0 || tid >= 65535 {
                continue;
            }

            grid.push(
                0,
                vec![
                    Value::hex(address),
                    or_unreadable(task.pid(), |value| Value::int(value as i64)),
                    Value::int(tid as i64),
                    // The parent pointer names a kernel address, so it is read
                    // raw, because the physical layer would mask it to its own
                    // width, and then followed in the kernel's address space.
                    match task
                        .object
                        .member("real_parent")
                        .and_then(|parent| parent.bytes())
                        .map(|bytes| {
                            let mut raw = [0u8; 8];
                            let take = bytes.len().min(8);
                            raw[..take].copy_from_slice(&bytes[..take]);
                            u64::from_le_bytes(raw) & kernel_mask
                        })
                        .and_then(|address| {
                            context
                                .object_from_template(
                                    task_type.clone(),
                                    &kernel.layer_name,
                                    address,
                                )
                                .member("tgid")?
                                .as_i64()
                        }) {
                        Ok(ppid) => Value::int(ppid),
                        // An unreadable parent is reported as no parent.
                        Err(_) => Value::int(0),
                    },
                    or_unreadable(task.comm(), Value::string),
                    Value::string(state),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Sign-extend a kernel address the way the layer canonicalises it.
fn canonical(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xFFFF_0000_0000_0000
    } else {
        address & 0x0000_FFFF_FFFF_FFFF
    }
}

/// The name of an exit state, or None if the value is not one.
fn exit_state_name(state: u64) -> Option<String> {
    match state {
        0x00 => Some("TASK_RUNNING".to_string()),
        0x10 => Some("EXIT_DEAD".to_string()),
        0x20 => Some("EXIT_ZOMBIE".to_string()),
        0x30 => Some("EXIT_TRACE".to_string()),
        _ => None,
    }
}

/// The layer holding the machine's physical memory.
fn physical_layer(context: &Arc<Context>, kernel: &crate::framework::context::Module) -> String {
    use crate::framework::layers::intel::IntelLayer;
    context
        .layers
        .get(&kernel.layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<IntelLayer>()
                .map(|intel| intel.base_layer_name().to_string())
        })
        .unwrap_or_else(|| kernel.layer_name.clone())
}

