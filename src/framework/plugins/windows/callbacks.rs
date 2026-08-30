//! List the kernel's notification callbacks.
//!
//! The kernel lets drivers register for events, process creation, image
//! loading, registry access, shutdown, a bug check. Each registration is a
//! function pointer in a kernel array, a list, or a pool allocation. Malware
//! registers here to gain execution on events it cares about, so a callback
//! owned by no loaded module is worth attention.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{
    generate_pool_scan, header_cookie, object_type_map, object_type_of, PoolConstraint, FREE,
    NONPAGED, PAGED,
};
use crate::framework::symbols::windows::resolver::ModuleCollection;
use crate::framework::symbols::windows::object_header;

pub struct Callbacks;

/// Where a callback's detail comes from, since the three kinds are reported
/// differently.
enum Detail {
    /// Nothing of the sort applies to this callback.
    NotApplicable,
    /// The detail exists but could not be read.
    Unreadable,
    Text(String),
}

impl Detail {
    fn value(self) -> Value {
        match self {
            Detail::NotApplicable => Value::not_applicable(),
            Detail::Unreadable => Value::unreadable(),
            Detail::Text(text) => Value::string(text),
        }
    }
}

/// One callback, before its address is attributed to a module.
struct Callback {
    kind: Value,
    address: u64,
    detail: Detail,
}

/// The notification arrays, and whether later kernels made each one longer.
const NOTIFY_ARRAYS: &[(&str, bool)] = &[
    ("PspLoadImageNotifyRoutine", false),
    ("PspCreateThreadNotifyRoutine", true),
    ("PspCreateProcessNotifyRoutine", true),
];

/// Where the shutdown handler sits in a driver's dispatch table.
const IRP_MJ_SHUTDOWN: u64 = 0x10;

impl Plugin for Callbacks {
    fn name(&self) -> &'static str {
        "windows.callbacks.Callbacks"
    }

    fn description(&self) -> &'static str {
        "Lists kernel callbacks and notification routines."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Type"),
            Column::new("Callback", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
            Column::string("Detail"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // The callback structures are not in the kernel's own symbols. They
        // ship as a small file of their own that refers back to it.
        let table = callback_table(&context, &kernel)?;
        let collection = ModuleCollection::build(&context, &kernel)?;

        let mut callbacks = Vec::new();
        callbacks.extend(notify_routines(&context, &kernel, &table));
        callbacks.extend(bugcheck_callbacks(&context, &kernel, &table));
        callbacks.extend(bugcheck_reason_callbacks(&context, &kernel, &table));
        callbacks.extend(registry_callbacks(&context, &kernel, &table));
        callbacks.extend(scan(&context, &kernel, &table));

        let mut grid = TreeGrid::new(self.columns());
        for callback in callbacks {
            let detail = callback.detail.value();
            let owners = collection.modules_at(&context, callback.address);
            if owners.is_empty() {
                // A callback in no loaded module is precisely the finding.
                grid.push(
                    0,
                    vec![
                        callback.kind,
                        Value::hex(callback.address),
                        Value::not_available(),
                        Value::not_available(),
                        detail,
                    ],
                )?;
                continue;
            }
            for (module, symbols) in owners {
                if symbols.is_empty() {
                    grid.push(
                        0,
                        vec![
                            callback.kind.clone(),
                            Value::hex(callback.address),
                            Value::string(module),
                            Value::not_available(),
                            detail.clone(),
                        ],
                    )?;
                    continue;
                }
                // Several symbols can name the same address.
                for symbol in symbols {
                    grid.push(
                        0,
                        vec![
                            callback.kind.clone(),
                            Value::hex(callback.address),
                            Value::string(module.clone()),
                            Value::string(symbol),
                            detail.clone(),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// Load the table describing the callback structures.
fn callback_table(context: &Arc<Context>, kernel: &Module) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let name = if sixty_four_bit {
        "callbacks-x64"
    } else {
        "callbacks-x86"
    };
    context.ensure_table(name, "windows", name)?;
    context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;
    Ok(name.to_string())
}

/// The routines the kernel calls when a process, thread, or image appears.
fn notify_routines(context: &Arc<Context>, kernel: &Module, table: &str) -> Vec<Callback> {
    let generic = format!("{table}!_GENERIC_CALLBACK");
    let mut found = Vec::new();

    for (symbol, extended) in NOTIFY_ARRAYS {
        // A kernel that does not name the array simply has none.
        let Ok(base) = context.symbol_offset(kernel, symbol) else {
            continue;
        };
        // Vista lengthened the process and thread arrays.
        let count = if *extended { 64 } else { 8 };

        for index in 0..count {
            let Ok(reference) = context.object(
                &kernel.qualified("_EX_FAST_REF"),
                &kernel.layer_name,
                base + index * 8,
            ) else {
                continue;
            };
            let Ok(block) = fast_reference(&reference) else {
                continue;
            };
            let Ok(callback) = context.object(&generic, &kernel.layer_name, block) else {
                continue;
            };
            let Ok(routine) = callback
                .member("Callback")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };
            if routine != 0 {
                found.push(Callback {
                    kind: Value::string(*symbol),
                    address: routine,
                    detail: Detail::NotApplicable,
                });
            }
        }
    }
    found
}

/// What an `_EX_FAST_REF` points at, with the reference count masked off.
fn fast_reference(reference: &Object) -> Result<u64> {
    let raw = reference
        .member("Object")
        .and_then(|object| object.pointer_value())
        .or_else(|_| reference.pointer_value())?;
    Ok(raw & !0xF)
}

/// The routines called when the machine stops with a bug check.
fn bugcheck_callbacks(context: &Arc<Context>, kernel: &Module, table: &str) -> Vec<Callback> {
    let record_type = format!("{table}!_KBUGCHECK_CALLBACK_RECORD");
    let Ok(head) = context.symbol_offset(kernel, "KeBugCheckCallbackListHead") else {
        return Vec::new();
    };
    let Ok(record) = context.object(&record_type, &kernel.layer_name, head) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for callback in list_of(&record, &record_type) {
        let Ok(routine) = callback
            .member("CallbackRoutine")
            .and_then(|routine| routine.pointer_value())
        else {
            continue;
        };
        if !context.layers.is_valid(&kernel.layer_name, routine, 64) {
            continue;
        }

        // The component name is read as though it sat inside the kernel image
        // rather than where the record points, which is what upstream does and
        // why it is usually unreadable.
        let component = callback
            .member("Component")
            .and_then(|component| component.pointer_value())
            .ok()
            .map(|address| kernel.offset.wrapping_add(address));
        found.push(Callback {
            kind: Value::string("KeBugCheckCallbackListHead"),
            address: routine,
            detail: component
                .and_then(|address| read_string(context, &kernel.layer_name, address, 64))
                .map(Detail::Text)
                .unwrap_or(Detail::Unreadable),
        });
    }
    found
}

/// The routines called to add data to a crash dump.
fn bugcheck_reason_callbacks(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
) -> Vec<Callback> {
    let record_type = format!("{table}!_KBUGCHECK_REASON_CALLBACK_RECORD");
    let Ok(head) = context.symbol_offset(kernel, "KeBugCheckReasonCallbackListHead") else {
        return Vec::new();
    };
    let Ok(record) = context.object(&record_type, &kernel.layer_name, head) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for callback in list_of(&record, &record_type) {
        let Ok(routine) = callback
            .member("CallbackRoutine")
            .and_then(|routine| routine.pointer_value())
        else {
            continue;
        };
        if !context.layers.is_valid(&kernel.layer_name, routine, 64) {
            continue;
        }
        let component = callback
            .member("Component")
            .and_then(|component| component.pointer_value())
            .ok();
        found.push(Callback {
            kind: Value::string("KeBugCheckReasonCallbackListHead"),
            address: routine,
            detail: component
                .and_then(|address| read_string(context, &kernel.layer_name, address, 64))
                .map(Detail::Text)
                .unwrap_or(Detail::Unreadable),
        });
    }
    found
}

/// The routines called on every registry access.
fn registry_callbacks(context: &Arc<Context>, kernel: &Module, table: &str) -> Vec<Callback> {
    let count = context
        .symbol_offset(kernel, "CmpCallBackCount")
        .and_then(|address| {
            context.object(&kernel.qualified("unsigned int"), &kernel.layer_name, address)
        })
        .and_then(|value| value.as_u64());

    let has_vector = context
        .symbol_space
        .has_symbol(&kernel.qualified("CmpCallBackVector"));
    let has_list = context
        .symbol_space
        .has_symbol(&kernel.qualified("CallbackListHead"));

    let Ok(count) = count else {
        return Vec::new();
    };
    if count == 0 {
        return Vec::new();
    }

    let mut found = Vec::new();
    if has_vector {
        // The older kernels keep a vector of registrations.
        let block_type = format!("{table}!_EX_CALLBACK_ROUTINE_BLOCK");
        let Ok(base) = context.symbol_offset(kernel, "CmpCallBackVector") else {
            return found;
        };
        for index in 0..count {
            let Ok(reference) = context.object(
                &kernel.qualified("_EX_FAST_REF"),
                &kernel.layer_name,
                base + index * 8,
            ) else {
                continue;
            };
            let Ok(block) = fast_reference(&reference) else {
                continue;
            };
            let Ok(callback) = context.object(&block_type, &kernel.layer_name, block) else {
                continue;
            };
            let Ok(function) = callback
                .member("Function")
                .and_then(|function| function.pointer_value())
            else {
                continue;
            };
            if function != 0 {
                found.push(Callback {
                    kind: Value::string("CmRegisterCallback"),
                    address: function,
                    detail: Detail::NotApplicable,
                });
            }
        }
    } else if has_list {
        // Later kernels link them, and each carries the altitude it registered
        // itself at.
        let entry_type = format!("{table}!_CM_CALLBACK_ENTRY");
        let Ok(head) = context.object_from_symbol(kernel, "CallbackListHead", Some("_LIST_ENTRY"))
        else {
            return found;
        };
        for callback in walk_list(&head, &entry_type, "Link", true).unwrap_or_default() {
            let Ok(function) = callback
                .member("Function")
                .and_then(|function| function.pointer_value())
            else {
                continue;
            };
            // An altitude that cannot be read is still reported, as the word
            // "None" in the detail.
            let altitude = callback
                .member("Altitude")
                .and_then(|altitude| unicode_string(&altitude))
                .ok();
            found.push(Callback {
                kind: Value::string("CmRegisterCallbackEx"),
                address: function,
                detail: Detail::Text(match altitude {
                    Some(altitude) => format!("Altitude: {altitude}"),
                    None => "Altitude: None".to_string(),
                }),
            });
        }
    }
    found
}

/// The callbacks that are only found by searching the pools for them.
fn scan(context: &Arc<Context>, kernel: &Module, table: &str) -> Vec<Callback> {
    let type_map = object_type_map(context, kernel);
    let cookie = header_cookie(context, kernel);
    let constraints = scan_constraints(context, table);

    let mut found = Vec::new();
    for hit in generate_pool_scan(context, kernel, &constraints).unwrap_or_default() {
        let object = hit.object;
        let type_name = object.type_name().to_string();

        if type_name.ends_with("_SHUTDOWN_PACKET") {
            // The routine is the driver's own shutdown handler, and the detail
            // is the driver's name.
            let (address, detail) = shutdown_packet(context, kernel, &object)
                .unwrap_or((object.offset(), Detail::NotApplicable));
            found.push(Callback {
                kind: Value::string("IoRegisterShutdownNotification"),
                address,
                detail,
            });
        } else if type_name.ends_with("_NOTIFICATION_PACKET") {
            let Ok(routine) = object
                .member("NotificationRoutine")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };
            found.push(Callback {
                kind: Value::string("IoRegisterFsRegistrationChange"),
                address: routine,
                detail: Detail::NotApplicable,
            });
        } else if type_name.ends_with("_NOTIFY_ENTRY_HEADER") {
            // The driver that registered names the callback, and the event it
            // registered for is its kind.
            let detail = match object
                .member("DriverObject")
                .and_then(|driver| driver.dereference())
            {
                Ok(driver) if driver.is_readable() => driver_name(context, kernel, &driver, &type_map, cookie),
                _ => Detail::Unreadable,
            };
            let Ok(category) = object.member("EventCategory") else {
                continue;
            };
            let kind = match category.enum_name() {
                Ok(name) => Value::string(name),
                Err(_) => Value::unparsable(),
            };
            let Ok(routine) = object
                .member("CallbackRoutine")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };
            found.push(Callback {
                kind,
                address: routine,
                detail,
            });
        } else if type_name.ends_with("_GENERIC_CALLBACK") {
            let Ok(routine) = object
                .member("Callback")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };
            found.push(Callback {
                kind: Value::string("GenericKernelCallback"),
                address: routine,
                detail: Detail::NotApplicable,
            });
        } else if type_name.ends_with("_DBGPRINT_CALLBACK") {
            let Ok(routine) = object
                .member("Function")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };
            found.push(Callback {
                kind: Value::string("DbgSetDebugPrintCallback"),
                address: routine,
                detail: Detail::NotApplicable,
            });
        }
    }
    found
}

/// The shutdown handler a packet registers, and the driver it belongs to.
fn shutdown_packet(
    context: &Arc<Context>,
    kernel: &Module,
    packet: &Object,
) -> Option<(u64, Detail)> {
    let driver = packet
        .member("DeviceObject")
        .and_then(|device| device.dereference_as(&kernel.qualified("_DEVICE_OBJECT")))
        .and_then(|device| device.member("DriverObject"))
        .and_then(|driver| driver.dereference())
        .ok()?;
    let address = driver
        .member("MajorFunction")
        .and_then(|table| table.index(IRP_MJ_SHUTDOWN))
        .and_then(|entry| entry.pointer_value())
        .ok()?;
    let name = driver
        .member("DriverName")
        .and_then(|name| unicode_string(&name))
        .ok();
    let _ = context;
    Some((
        address,
        match name {
            Some(name) if !name.is_empty() => Detail::Text(name),
            // A driver with no name of its own is reported as unparsable.
            _ => Detail::Unreadable,
        },
    ))
}

/// The name of the driver that registered a device notification.
fn driver_name(
    context: &Arc<Context>,
    kernel: &Module,
    driver: &Object,
    type_map: &HashMap<u64, String>,
    cookie: Option<u64>,
) -> Detail {
    let Ok(header) = object_header(driver, kernel) else {
        return Detail::Unreadable;
    };
    match object_type_of(context, kernel, driver, type_map, cookie).as_deref() {
        Some("Driver") => header
            .member("NameInfo")
            .and_then(|info| info.member("Name"))
            .and_then(|name| unicode_string(&name))
            .map(Detail::Text)
            .unwrap_or(Detail::Unreadable),
        Some(_) => Detail::NotApplicable,
        None => Detail::Unreadable,
    }
}

/// The pool allocations that hold callbacks.
fn scan_constraints(context: &Arc<Context>, table: &str) -> Vec<PoolConstraint> {
    let size_of = |name: &str| {
        context
            .symbol_space
            .get_type(&format!("{table}!{name}"))
            .and_then(|template| context.symbol_space.size_of(&template))
            .unwrap_or(0)
    };
    let anywhere = NONPAGED | PAGED | FREE;

    vec![
        PoolConstraint::new(b"IoFs", "_NOTIFICATION_PACKET", anywhere)
            .in_table(table)
            .with_size(size_of("_NOTIFICATION_PACKET"), None),
        PoolConstraint::new(b"IoSh", "_SHUTDOWN_PACKET", anywhere)
            .in_table(table)
            .with_size(size_of("_SHUTDOWN_PACKET"), None)
            .with_index(0, 0),
        PoolConstraint::new(b"Cbrb", "_GENERIC_CALLBACK", anywhere)
            .in_table(table)
            .with_size(size_of("_GENERIC_CALLBACK"), None),
        PoolConstraint::new(b"DbCb", "_DBGPRINT_CALLBACK", anywhere)
            .in_table(table)
            .with_size(0x20, Some(0x40)),
        PoolConstraint::new(b"Pnp9", "_NOTIFY_ENTRY_HEADER", anywhere)
            .in_table(table)
            .with_size(0x30, None)
            .with_index(1, 1),
        PoolConstraint::new(b"PnpD", "_NOTIFY_ENTRY_HEADER", anywhere)
            .in_table(table)
            .with_size(0x40, None)
            .with_index(1, 1),
        PoolConstraint::new(b"PnpC", "_NOTIFY_ENTRY_HEADER", anywhere)
            .in_table(table)
            .with_size(0x38, None)
            .with_index(1, 1),
    ]
}

/// Walk a list whose head is the record's own link member.
fn list_of(record: &Object, type_name: &str) -> Vec<Object> {
    record
        .member("Entry")
        .and_then(|head| walk_list(&head, type_name, "Entry", true))
        .unwrap_or_default()
}

/// Read a NUL-terminated string of at most `length` bytes.
fn read_string(
    context: &Arc<Context>,
    layer: &str,
    address: u64,
    length: usize,
) -> Option<String> {
    let data = context.layers.read(layer, address, length, false).ok()?;
    let end = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).to_string())
}
