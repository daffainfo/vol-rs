//! List the handles each process holds.
//!
//! The handle table is a sparse, multi-level array of `_HANDLE_TABLE_ENTRY`.
//! Each entry encodes a pointer to the kernel object it refers to, with the low
//! bits used as flags.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{header_cookie, object_type_map};
use crate::framework::symbols::windows::{header_name, Process};
use std::collections::HashMap;

pub struct Handles;

/// The table's low bits record its depth rather than forming part of the
/// address.
const LEVEL_MASK: u64 = 7;

/// A handle table is one page wide at every level.
const TABLE_PAGE: u64 = 0x1000;

/// Handle values count in fours, one per pointer-sized slot.
const HANDLE_MULTIPLIER: u64 = 4;

impl Plugin for Handles {
    fn name(&self) -> &'static str {
        "windows.handles.Handles"
    }

    fn description(&self) -> &'static str {
        "Lists process open handles."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process IDs to include (all other processes are excluded)"),
            Requirement::new(
                "offset",
                "Process offset in the physical address space",
                crate::framework::plugins::RequirementKind::Int,
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Offset", ColumnType::UInt),
            Column::new("HandleValue", ColumnType::UInt),
            Column::string("Type"),
            Column::new("GrantedAccess", ColumnType::UInt),
            Column::string("Name"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let type_map = object_type_map(&context, &kernel);
        let cookie = header_cookie(&context, &kernel);
        let mut grid = TreeGrid::new(self.columns());

        for process in
            crate::framework::plugins::windows::selected_processes(&context, &kernel, config)?
        {
            let Ok(pid) = process.pid() else { continue };
            let Ok(object_table) = process.object.member("ObjectTable") else {
                continue;
            };
            let Ok(name) = process.image_file_name() else {
                continue;
            };

            for handle in handles(&context, &kernel, &object_table) {
                // An object whose kind the kernel's own table does not name is
                // not reported at all.
                let Some(kind) = object_type_of_header(&handle.header, &type_map, cookie) else {
                    continue;
                };
                let Ok(body) = body_of(&context, &kernel, &handle.header) else {
                    continue;
                };

                let object_name = match kind.as_str() {
                    "File" => file_name_with_device(&context, &kernel, &body),
                    "Process" => body
                        .cast(&kernel.qualified("_EPROCESS"))
                        .ok()
                        .and_then(|process| {
                            let process = Process::new(process);
                            let name = process.image_file_name().ok()?;
                            let pid = process.pid().ok()?;
                            Some(format!("{name} Pid {pid}"))
                        }),
                    "Thread" => body
                        .cast(&kernel.qualified("_ETHREAD"))
                        .ok()
                        .and_then(|thread| {
                            let cid = thread.member("Cid").ok()?;
                            let tid = cid.member("UniqueThread").ok()?.pointer_value().ok()?;
                            let pid = cid.member("UniqueProcess").ok()?.pointer_value().ok()?;
                            Some(format!("Tid {tid} Pid {pid}"))
                        }),
                    "Key" => {
                        let Ok(key) = body.cast(&kernel.qualified("_CM_KEY_BODY")) else {
                            continue;
                        };
                        // A key whose path cannot be followed is not reported.
                        match full_key_name(&key) {
                            Ok(name) => name,
                            Err(_) => continue,
                        }
                    }
                    _ => header_name(&handle.header, &kernel),
                };

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::hex(body.offset()),
                        Value::hex(handle.value),
                        Value::string(kind),
                        Value::hex(handle.granted_access),
                        object_name
                            .filter(|name| !name.is_empty())
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// One entry of a process's handle table.
pub struct Handle {
    /// The object header the handle refers to.
    pub header: Object,
    /// The value the process knows the handle by.
    pub value: u64,
    /// The rights the handle was opened with.
    pub granted_access: u64,
}

/// Every handle a table holds, descending through however many levels it has.
pub fn handles(context: &Arc<Context>, kernel: &Module, object_table: &Object) -> Vec<Handle> {
    let Ok(table) = object_table.dereference() else {
        return Vec::new();
    };
    let Ok(code) = table.member("TableCode").and_then(|code| code.as_u64()) else {
        return Vec::new();
    };

    // The bottom bits give the number of levels. The rest is the address, in
    // the form the layer addresses it.
    let mut found = Vec::new();
    let mut depth = 0;
    let base = (code & !LEVEL_MASK) & context.layers.address_mask(&kernel.layer_name);
    collect(
        context,
        kernel,
        base,
        code & LEVEL_MASK,
        &mut depth,
        &mut found,
    );
    found
}

/// Walk one level of a handle table.
fn collect(
    context: &Arc<Context>,
    kernel: &Module,
    address: u64,
    level: u64,
    depth: &mut u64,
    found: &mut Vec<Handle>,
) {
    let layer = kernel.layer_name.clone();
    if !context.layers.is_valid(&layer, address, 1) {
        return;
    }

    let entry_type = if level > 0 {
        kernel.qualified("pointer")
    } else {
        kernel.qualified("_HANDLE_TABLE_ENTRY")
    };
    let Ok(template) = context.symbol_space.get_type(&entry_type) else {
        return;
    };
    let Ok(entry_size) = context.symbol_space.size_of(&template) else {
        return;
    };
    if entry_size == 0 {
        return;
    }
    let count = TABLE_PAGE / entry_size;
    let masked = address & context.layers.address_mask(&layer);

    for index in 0..count {
        let at = address + index * entry_size;
        if !context.layers.is_valid(&layer, at, 1) {
            continue;
        }
        let entry = context.object_from_template(template.clone(), &layer, at);

        if level > 0 {
            // A pointer to the level below, which numbers its handles from
            // where this level left off.
            // The pointer names a table in this layer, so only the bits the
            // layer addresses are part of it.
            let Ok(next) = entry
                .as_u64()
                .map(|value| value & context.layers.address_mask(&layer))
            else {
                continue;
            };
            collect(context, kernel, next, level - 1, depth, found);
            *depth += 1;
            continue;
        }

        // The value a process knows a handle by is its position in the table.
        let base = *depth * count * HANDLE_MULTIPLIER;
        let value = (at - masked) / (entry_size / HANDLE_MULTIPLIER) + base;
        let Some(handle) = item(context, kernel, &entry, value) else {
            continue;
        };
        // A slot naming no kind of object was never used.
        if handle
            .header
            .member("TypeIndex")
            .and_then(|index| index.as_u64())
            .map(|index| index == 0)
            .unwrap_or(true)
        {
            continue;
        }
        found.push(handle);
    }
}

/// Turn a table entry into the object header it refers to.
fn item(context: &Arc<Context>, kernel: &Module, entry: &Object, value: u64) -> Option<Handle> {
    let header_type = kernel.qualified("_OBJECT_HEADER");
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    // Before Windows 8 the entry holds the pointer itself, packed as a fast
    // reference. From Windows 8 it holds only the bits of the address that
    // vary.
    if entry.has_member("Object") {
        let raw = entry.member("Object").ok()?.pointer_value().ok()?;
        if !context.layers.is_valid(&kernel.layer_name, raw, 1) {
            return None;
        }
        let header = context
            .object(&header_type, &kernel.layer_name, raw & !0xF)
            .ok()?;
        let granted_access = entry
            .member("GrantedAccess")
            .and_then(|access| access.as_u64())
            .unwrap_or(0);
        return Some(Handle {
            header,
            value,
            granted_access,
        });
    }

    let address = if sixty_four_bit {
        let bits = entry.member("ObjectPointerBits").ok()?.as_u64().ok()?;
        if bits == 0 {
            return None;
        }
        bits << 4
    } else {
        let table = entry.member("InfoTable").ok()?.as_u64().ok()?;
        if table == 0 {
            return None;
        }
        table & !7
    };

    let header = context.object(&header_type, &kernel.layer_name, address).ok()?;
    let granted_access = entry
        .member("GrantedAccessBits")
        .and_then(|access| access.as_u64())
        .ok()?;
    Some(Handle {
        header,
        value,
        granted_access,
    })
}

/// The object an object header precedes.
fn body_of(context: &Arc<Context>, kernel: &Module, header: &Object) -> Result<Object> {
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER"))?;
    let body = context
        .symbol_space
        .find_member(&template, "Body")?
        .map(|(offset, _)| offset)
        .unwrap_or(0);
    Ok(context.object_from_template(
        context.symbol_space.get_type(&kernel.qualified("_OBJECT_HEADER"))?,
        header.layer_name(),
        header.offset() + body,
    ))
}

/// What the kernel's own table says an object header describes.
pub fn object_type_of_header(
    header: &Object,
    type_map: &HashMap<u64, String>,
    cookie: Option<u64>,
) -> Option<String> {
    // Vista and earlier point straight at the type object.
    if let Ok(kind) = header.member("Type").and_then(|kind| kind.dereference()) {
        if let Ok(name) = kind.member("Name").and_then(|name| unicode_string(&name)) {
            if !name.is_empty() && name.len() <= 128 {
                return Some(name);
            }
        }
    }

    let index = header.member("TypeIndex").and_then(|index| index.as_u64()).ok()?;
    // Windows 10 obfuscates the index with the header's own address and a
    // per-boot cookie.
    let index = match cookie {
        Some(cookie) => ((header.offset() >> 8) ^ cookie ^ index) & 0xFF,
        None => index,
    };
    type_map.get(&index).cloned()
}

/// A file object's name, prefixed by the device it lives on.
fn file_name_with_device(
    context: &Arc<Context>,
    kernel: &Module,
    body: &Object,
) -> Option<String> {
    let file = body.cast(&kernel.qualified("_FILE_OBJECT")).ok()?;
    let mut name = String::new();

    // The device's own name comes from its object header, and a device that
    // cannot be read leaves the file named by its path alone.
    if let Ok(device) = file.member("DeviceObject").and_then(|device| device.pointer_value()) {
        if context.layers.is_valid(file.native_layer_name(), device, 1) {
            if let Ok(device) = file
                .member("DeviceObject")
                .and_then(|device| device.dereference())
            {
                if let Some(device_name) = crate::framework::symbols::windows::object_name(&device, kernel) {
                    name = format!("\\Device\\{device_name}");
                }
            }
        }
    }
    if let Ok(path) = file.member("FileName").and_then(|path| unicode_string(&path)) {
        name.push_str(&path);
    }
    Some(name)
}

/// The whole path of an open registry key, built from its control blocks.
///
/// Each block names one component and points at its parent, so the path is
/// read from the key upwards. A block that stands for a hive's own entry
/// carries the name of the hive rather than a component, and is stepped over.
///
/// A read that fails abandons the handle altogether, since a key whose path
/// cannot be followed is not reported at all. `None` marks a path that ran in
/// a circle or ran too deep.
fn full_key_name(key: &Object) -> Result<Option<String>> {
    /// The flag a control block carries when it stands for a hive's entry.
    const KEY_HIVE_ENTRY: u64 = 0x04;
    // Only kernels new enough to have this member have the extra element.
    let hive_entries = key.has_member("Trans");

    let mut parts: Vec<String> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut block = key.member("KeyControlBlock")?.dereference()?;

    while block.member("ParentKcb")?.pointer_value()? != 0 {
        let parent = block.member("ParentKcb")?.dereference()?;
        if seen.contains(&parent.offset()) || parts.len() > 128 {
            return Ok(None);
        }
        seen.push(parent.offset());

        // Reaching the name at all is what says the chain is still real.
        block.member("NameBlock")?.dereference()?.member("Name")?;

        if hive_entries && block.member("Flags")?.as_u64()? & KEY_HIVE_ENTRY == KEY_HIVE_ENTRY {
            block = parent;
            if block.offset() == 0 {
                break;
            }
        }

        let name_block = block.member("NameBlock")?.dereference()?;
        let length = name_block.member("NameLength")?.as_u64()?;
        let name = name_block.member("Name")?;
        let data = context_read(&name, length as usize)?;
        parts.push(String::from_utf8_lossy(&data).to_string());

        block = block.member("ParentKcb")?.dereference()?;
    }

    parts.reverse();
    Ok(Some(parts.join("\\")))
}

/// Read a fixed number of bytes from where an object sits.
fn context_read(object: &Object, length: usize) -> Result<Vec<u8>> {
    object
        .context()
        .layers
        .read(object.layer_name(), object.offset(), length, false)
}
