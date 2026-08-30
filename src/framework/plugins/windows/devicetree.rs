//! Report the device objects each driver owns, and what is attached to them.
//!
//! A driver owns a chain of devices, and devices may be stacked: a filter
//! driver attaches its own device above another's. An unexpected attachment is
//! how a rootkit interposes on I/O.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::unicode_string;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::object_name;
use crate::framework::plugins::windows::driverscan::scan_drivers;

pub struct DeviceTree;

/// The device type codes, by their numeric value.
fn device_type_name(code: u64) -> String {
    // These are the FILE_DEVICE_* constants. Only the common ones are named,
    // and anything else is reported numerically rather than guessed at.
    match code {
        0x1 => "FILE_DEVICE_BEEP",
        0x2 => "FILE_DEVICE_CD_ROM",
        0x3 => "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x4 => "FILE_DEVICE_CONTROLLER",
        0x5 => "FILE_DEVICE_DATALINK",
        0x6 => "FILE_DEVICE_DFS",
        0x7 => "FILE_DEVICE_DISK",
        0x8 => "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x9 => "FILE_DEVICE_FILE_SYSTEM",
        0xA => "FILE_DEVICE_INPORT_PORT",
        0xB => "FILE_DEVICE_KEYBOARD",
        0xC => "FILE_DEVICE_MAILSLOT",
        0xD => "FILE_DEVICE_MIDI_IN",
        0xE => "FILE_DEVICE_MIDI_OUT",
        0xF => "FILE_DEVICE_MOUSE",
        0x10 => "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x11 => "FILE_DEVICE_NAMED_PIPE",
        0x12 => "FILE_DEVICE_NETWORK",
        0x13 => "FILE_DEVICE_NETWORK_BROWSER",
        0x14 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x15 => "FILE_DEVICE_NULL",
        0x16 => "FILE_DEVICE_PARALLEL_PORT",
        0x17 => "FILE_DEVICE_PHYSICAL_NETCARD",
        0x18 => "FILE_DEVICE_PRINTER",
        0x19 => "FILE_DEVICE_SCANNER",
        0x1A => "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x1B => "FILE_DEVICE_SERIAL_PORT",
        0x1C => "FILE_DEVICE_SCREEN",
        0x1D => "FILE_DEVICE_SOUND",
        0x1E => "FILE_DEVICE_STREAMS",
        0x1F => "FILE_DEVICE_TAPE",
        0x20 => "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x21 => "FILE_DEVICE_TRANSPORT",
        0x22 => "FILE_DEVICE_UNKNOWN",
        0x23 => "FILE_DEVICE_VIDEO",
        0x24 => "FILE_DEVICE_VIRTUAL_DISK",
        0x25 => "FILE_DEVICE_WAVE_IN",
        0x26 => "FILE_DEVICE_WAVE_OUT",
        0x27 => "FILE_DEVICE_8042_PORT",
        0x28 => "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x29 => "FILE_DEVICE_BATTERY",
        0x2A => "FILE_DEVICE_BUS_EXTENDER",
        0x2B => "FILE_DEVICE_MODEM",
        0x2C => "FILE_DEVICE_VDM",
        0x2D => "FILE_DEVICE_MASS_STORAGE",
        0x2E => "FILE_DEVICE_SMB",
        0x2F => "FILE_DEVICE_KS",
        0x30 => "FILE_DEVICE_CHANGER",
        0x31 => "FILE_DEVICE_SMARTCARD",
        0x32 => "FILE_DEVICE_ACPI",
        0x33 => "FILE_DEVICE_DVD",
        0x34 => "FILE_DEVICE_FULLSCREEN_VIDEO",
        0x35 => "FILE_DEVICE_DFS_FILE_SYSTEM",
        0x36 => "FILE_DEVICE_DFS_VOLUME",
        0x37 => "FILE_DEVICE_SERENUM",
        0x38 => "FILE_DEVICE_TERMSRV",
        0x39 => "FILE_DEVICE_KSEC",
        // A code the table does not name is reported plainly, without the
        // number: the reference implementation's lookup has no fallback that
        // carries one.
        _ => "UNKNOWN",
    }
    .to_string()
}

impl Plugin for DeviceTree {
    fn name(&self) -> &'static str {
        "windows.devicetree.DeviceTree"
    }

    fn description(&self) -> &'static str {
        "Listing tree based on drivers and attached devices in a particular windows memory image."
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
            Column::string("Type"),
            Column::string("DriverName"),
            Column::string("DeviceName"),
            Column::string("DriverNameOfAttDevice"),
            Column::string("DeviceType"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        'drivers: for driver in scan_drivers(&context, &kernel)? {
            // The name on the object header, which is the short one: `ACPI`
            // rather than `\Driver\ACPI`.
            let driver_name = match object_name(&driver, &kernel) {
                Some(name) => Value::string(name),
                None => Value::unparsable(),
            };

            // Every row of a driver's subtree reports the driver's own address.
            let offset = driver.offset();
            grid.push(
                0,
                vec![
                    Value::hex(offset),
                    Value::string("DRV"),
                    driver_name.clone(),
                    Value::not_applicable(),
                    Value::not_applicable(),
                    Value::not_applicable(),
                ],
            )?;

            for device in device_chain(&driver) {
                let Ok(device_type) = device.member("DeviceType").and_then(|kind| kind.as_u64())
                else {
                    // A read that fails abandons the rest of this driver, not
                    // just the device it failed on.
                    continue 'drivers;
                };
                grid.push(
                    1,
                    vec![
                        Value::hex(offset),
                        Value::string("DEV"),
                        driver_name.clone(),
                        match object_name(&device, &kernel) {
                            Some(name) => Value::string(name),
                            None => Value::unparsable(),
                        },
                        Value::not_applicable(),
                        Value::string(device_type_name(device_type)),
                    ],
                )?;

                // Each device attached above this one sits a level deeper: a
                // stack of filters in the same I/O path.
                for (depth, attached) in attached_chain(&device).into_iter().enumerate() {
                    let Ok(attached_driver) = attached
                        .member("DriverObject")
                        .and_then(|driver| driver.dereference())
                        .and_then(|driver| driver.member("DriverName"))
                        .and_then(|name| unicode_string(&name))
                    else {
                        continue 'drivers;
                    };
                    let Ok(attached_type) =
                        attached.member("DeviceType").and_then(|kind| kind.as_u64())
                    else {
                        continue 'drivers;
                    };
                    grid.push(
                        depth + 2,
                        vec![
                            Value::hex(offset),
                            Value::string("ATT"),
                            driver_name.clone(),
                            match object_name(&attached, &kernel) {
                                Some(name) => Value::string(name),
                                None => Value::unparsable(),
                            },
                            Value::string(attached_driver),
                            Value::string(device_type_name(attached_type)),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// The devices a driver owns, linked through `NextDevice`.
fn device_chain(driver: &Object) -> Vec<Object> {
    let mut results = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    let Ok(first) = driver
        .member("DeviceObject")
        .and_then(|device| device.dereference())
    else {
        return results;
    };

    let mut current = first;
    while results.len() < 4096 {
        if !seen.insert(current.offset()) {
            break;
        }
        let next = current
            .member("NextDevice")
            .and_then(|next| next.pointer_value());
        results.push(current.clone());
        match next {
            // Following a null pointer costs nothing until something is read
            // through it, so the walk ends on one more device, at address zero,
            // whose fields cannot be read. Upstream lets that failure end the
            // whole driver, and the output shows it.
            Ok(0) => {
                results.push(current.at_offset(0));
                break;
            }
            Err(_) => break,
            Ok(address) => current = current.at_offset(address),
        }
    }
    results
}

fn attached_chain(device: &Object) -> Vec<Object> {
    let mut results = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut current = device.clone();

    while results.len() < 64 {
        let next = current
            .member("AttachedDevice")
            .and_then(|next| next.pointer_value());
        match next {
            // As above: the chain ends with a device at address zero, which is
            // where reading stops being possible.
            Ok(0) => {
                results.push(current.at_offset(0));
                break;
            }
            Err(_) => break,
            Ok(address) => {
                if !seen.insert(address) {
                    break;
                }
                current = current.at_offset(address);
                results.push(current.clone());
            }
        }
    }
    results
}
