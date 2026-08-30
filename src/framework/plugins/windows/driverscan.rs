//! Scan physical memory for driver objects.
//!
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
            // allocations that merely happen to carry the tag.
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

/// The driver objects the pools still hold.
///
/// A great many allocations end a page with the driver tag, so a candidate is
/// only a driver if the field every caller reads first can be read at all, and
/// if the image it names is either kernel memory or has been zeroed, which is
/// what a driver hiding itself does.
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

/// The three names a driver goes by: the name on its object header, the key
/// its service is registered under, and the name the driver object carries.
///
/// A name that cannot be read, or that is empty, is reported as absent.
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
