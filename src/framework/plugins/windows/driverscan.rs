//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::object_name;
use crate::framework::symbols::windows::kernel_space_start;
use crate::framework::symbols::windows::poolscanner::scan_for_tags;

/// Scans for drivers present in a particular windows memory image.
pub struct DriverScan;

impl Plugin for DriverScan {
    fn name(&self) -> &'static str {
        "windows.driverscan.DriverScan"
    }

    fn description(&self) -> &'static str {
        "Scans for drivers present in a particular windows memory image."
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
            Column::new("Start", ColumnType::UInt),
            Column::new("Size", ColumnType::UInt),
            Column::string("Service Key"),
            Column::string("Driver Name"),
            Column::string("Name"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let _layer = physical_layer(config);

        let objects = scan_drivers(&context, &kernel)?;

        let mut grid = TreeGrid::new(self.columns());
        for object in objects {
            let (driver_name, service_key, name) = driver_names(&object, &kernel);

            // A driver with none of the three names is one of the many
            // allocations that merely happen to carry the tag. Prior to #1481,
            // this plugin reported dozens to hundreds of junk drivers per
            // sample.
            if service_key.is_none() && driver_name.is_none() && name.is_none() {
                continue;
            }

            let text = |value: Option<String>| match value {
                Some(value) => Value::string(value),
                None => Value::not_available(),
            };
            grid.push(
                0,
                vec![
                    Value::hex(object.offset()),
                    object
                        .member("DriverStart")
                        .and_then(|start| start.pointer_value())
                        .map(Value::hex)
                        .unwrap_or_else(|_| Value::unreadable()),
                    object
                        .member("DriverSize")
                        .and_then(|size| size.as_u64())
                        .map(Value::hex)
                        .unwrap_or_else(|_| Value::unreadable()),
                    text(service_key),
                    text(driver_name),
                    text(name),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Scans for drivers using the poolscanner module and constraints.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
/// * `kernel` - The module for the kernel
///
/// # Returns
///
/// A list of Driver objects as found from the kernel's layer based on Driver
/// pool signatures.
///
/// *Many* `_DRIVER_OBJECT` instances were found at the end of a page leading to
/// member access causing backtraces across several plugins when members were
/// accessed as the next page was paged out. `DriverStart` is the first member
/// from the beginning of the structure of interest to plugins, so if it is not
/// accessible then this instance is not useful or usable during analysis. Eight
/// bytes covers this value on 32 and 64 bit systems.
///
/// Many/most rootkits zero out their DriverStart member for anti-forensics, so
/// we accept a driver start that is either 0 or points into kernel memory (the
/// current layer).
pub fn scan_drivers(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<Vec<crate::framework::objects::Object>> {
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("_DRIVER_OBJECT"))?;
    let start_offset = context
        .symbol_space
        .find_member(&template, "DriverStart")?
        .map(|(offset, _)| offset)
        .unwrap_or(0);
    let kernel_start = kernel_space_start(context, kernel);

    let mut drivers = Vec::new();
    for object in scan_for_tags(context, kernel, &[b"Dri\xf6", b"Driv"])? {
        if !context.layers.is_valid(
            object.layer_name(),
            object.offset() + start_offset,
            8,
        ) {
            continue;
        }
        let Ok(start) = object
            .member("DriverStart")
            .and_then(|start| start.pointer_value())
        else {
            continue;
        };
        if start == 0 || start > kernel_start {
            drivers.push(object);
        }
    }
    Ok(drivers)
}

/// Convenience method for getting the commonly used names associated with a
/// driver.
///
/// # Returns
///
/// A tuple of (driver name, service key, driver alt. name). A name that cannot
/// be read, or that is empty, is reported as absent.
pub fn driver_names(
    driver: &crate::framework::objects::Object,
    kernel: &Module,
) -> (Option<String>, Option<String>, Option<String>) {
    let driver_name = object_name(driver, kernel).filter(|name| !name.is_empty());
    let service_key = driver
        .member("DriverExtension")
        .and_then(|extension| extension.dereference())
        .and_then(|extension| extension.member("ServiceKeyName"))
        .and_then(|key| unicode_string(&key))
        .ok()
        .filter(|name| !name.is_empty());
    let name = driver
        .member("DriverName")
        .and_then(|name| unicode_string(&name))
        .ok()
        .filter(|name| !name.is_empty());
    (driver_name, service_key, name)
}
