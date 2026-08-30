//! Report each driver's IRP dispatch routines.
//!
//! A driver publishes a table of handlers, one per I/O request type. A rootkit
//! that hooks a driver replaces entries in this table, so a handler pointing
//! outside the owning driver's own image is worth attention.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::driverscan::scan_drivers;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::resolver::ModuleCollection;
use crate::framework::symbols::windows::{kernel_space_start, object_name};

pub struct DriverIrp;

/// The IRP major function codes, in table order.
const IRP_NAMES: &[&str] = &[
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];

impl Plugin for DriverIrp {
    fn name(&self) -> &'static str {
        "windows.driverirp.DriverIrp"
    }

    fn description(&self) -> &'static str {
        "List IRPs for drivers in a particular windows memory image."
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
            Column::string("Driver Name"),
            Column::string("IRP"),
            Column::new("Address", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // Attributing each handler to its owning module is what makes a hooked
        // driver visible, so the index is built once for the whole run.
        let collection = ModuleCollection::build(&context, &kernel)?;
        let kernel_start = kernel_space_start(&context, &kernel);

        let mut grid = TreeGrid::new(self.columns());
        for driver in scan_drivers(&context, &kernel)? {
            // The name on the driver's object header, which is the short one.
            let name = match object_name(&driver, &kernel) {
                Some(name) => Value::string(name),
                None => Value::not_applicable(),
            };

            let Ok(table) = driver.member("MajorFunction") else {
                continue;
            };

            for (index, irp_name) in IRP_NAMES.iter().enumerate() {
                let Ok(address) = table
                    .index(index as u64)
                    .and_then(|entry| entry.pointer_value())
                else {
                    continue;
                };
                // A handler below kernel space is smear rather than a hook.
                if address < kernel_start {
                    continue;
                }

                let owners = collection.modules_at(&context, address);
                if owners.is_empty() {
                    // A handler in no loaded module is exactly what this
                    // plugin exists to surface.
                    grid.push(
                        0,
                        vec![
                            Value::hex(driver.offset()),
                            name.clone(),
                            Value::string(*irp_name),
                            Value::hex(address),
                            Value::not_available(),
                            Value::not_available(),
                        ],
                    )?;
                    continue;
                }

                for (module, symbols) in owners {
                    if symbols.is_empty() {
                        grid.push(
                            0,
                            vec![
                                Value::hex(driver.offset()),
                                name.clone(),
                                Value::string(*irp_name),
                                Value::hex(address),
                                Value::string(module),
                                Value::not_available(),
                            ],
                        )?;
                        continue;
                    }
                    for symbol in symbols {
                        grid.push(
                            0,
                            vec![
                                Value::hex(driver.offset()),
                                name.clone(),
                                Value::string(*irp_name),
                                Value::hex(address),
                                Value::string(module.clone()),
                                Value::string(symbol),
                            ],
                        )?;
                    }
                }
            }
        }
        Ok(grid)
    }
}

