//! List the services the service controller knows about.
//!
//! The controller keeps a record for every service in its own memory, so the
//! records are found by searching that process rather than the kernel. Each
//! record is paired with what the registry says the service runs, which is how
//! a service whose registry entry and memory record disagree becomes visible.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::layers::scanners::{scan_layer, BytesScanner};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::registry::{read_key, subkeys, values, RegistryKey};
use crate::framework::symbols::windows::versions;

pub struct SvcScan;

/// What the registry says a service runs.
#[derive(Clone)]
pub struct BinaryInfo {
    binary: Value,
    dll: Value,
}

/// The kinds a service can be, as flags in one word.
const SERVICE_TYPES: &[(&str, u64)] = &[
    ("SERVICE_KERNEL_DRIVER", 1),
    ("SERVICE_FILE_SYSTEM_DRIVER", 2),
    ("SERVICE_ADAPTOR", 4),
    ("SERVICE_RECOGNIZER_DRIVER", 8),
    ("SERVICE_WIN32_OWN_PROCESS", 16),
    ("SERVICE_WIN32_SHARE_PROCESS", 32),
    ("SERVICE_INTERACTIVE_PROCESS", 256),
];

impl Plugin for SvcScan {
    fn name(&self) -> &'static str {
        "windows.svcscan.SvcScan"
    }

    fn description(&self) -> &'static str {
        "Scans for windows services."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        service_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let (table, registry) = prerequisites(&context, &kernel)?;
        let mut grid = TreeGrid::new(self.columns());
        for row in service_scan(&context, &kernel, &physical, &table, &registry)? {
            grid.push(0, row)?;
        }
        Ok(grid)
    }
}

/// The record layout and the registry's view of every service.
///
/// The layout belongs to the service controller rather than to the kernel, and
/// ships as a file of its own for each release it changed in.
pub fn prerequisites(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<(String, HashMap<String, BinaryInfo>)> {
    let table = service_table(context, kernel)?;
    let registry = registry_services(context, kernel);
    Ok((table, registry))
}

/// The columns every service listing reports.
pub fn service_columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColumnType::UInt),
        Column::int("Order"),
        Column::int("PID"),
        Column::string("Start"),
        Column::string("State"),
        Column::string("Type"),
        Column::string("Name"),
        Column::string("Display"),
        Column::string("Binary"),
        Column::string("Binary (Registry)"),
        Column::string("Dll"),
    ]
}

/// Find every service by searching the controller's memory for its records.
pub fn service_scan(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
    table: &str,
    registry: &HashMap<String, BinaryInfo>,
) -> Result<Vec<Vec<Value>>> {
    let record_type = format!("{table}!_SERVICE_RECORD");
    let header_type = format!("{table}!_SERVICE_HEADER");
    let vista_or_later = versions::matches(context, kernel, versions::IS_VISTA_OR_LATER);
    // The tag the controller marks its records with changed with Vista.
    let tag: &[u8] = if vista_or_later { b"serH" } else { b"sErv" };

    let tag_offset = context
        .symbol_space
        .get_type(&record_type)
        .and_then(|template| {
            context
                .symbol_space
                .find_member(&template, "Tag")
                .map(|found| found.map(|(offset, _)| offset).unwrap_or(0))
        })
        .unwrap_or(0);

    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut seen: Vec<(u64, u64)> = Vec::new();

    for (_, layer_name, sections) in controller_processes(context, kernel, physical)? {
        let layer = context.layers.get(&layer_name)?;
        let scanner = BytesScanner::new(tag.to_vec());
        let mut hits: Vec<u64> = Vec::new();
        scan_layer(
            layer.as_ref(),
            &context.layers,
            &scanner,
            Some(&sections),
            |offset| hits.push(offset),
        )?;

        for hit in hits {
            if !vista_or_later {
                let Some(address) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                let Ok(record) = context.object(&record_type, &layer_name, address) else {
                    continue;
                };
                if !record_is_valid(&record) {
                    continue;
                }
                rows.push(row(record.offset(), &record, registry));
                continue;
            }

            for (offset, record) in
                enumerate_header(context, &header_type, &layer_name, hit)
            {
                let built = row(offset, &record, registry);
                // Chains overlap, so reaching a record already reported ends
                // this one. A row that could not report a process or a running
                // image is never recognised as one already seen, so it is
                // reported once per chain that reaches it.
                let comparable = !matches!(built[2], Value::Absent(_))
                    && !matches!(built[8], Value::Absent(_));
                if comparable && seen.contains(&(offset, record.offset())) {
                    break;
                }
                seen.push((offset, record.offset()));
                rows.push(built);
            }
        }
    }
    Ok(rows)
}

/// Find every service by walking the list the controller itself keeps.
///
/// The list runs from a marker inside the controller's own executable, so only
/// that one region is searched rather than everything the process maps.
pub fn service_list(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
    table: &str,
    registry: &HashMap<String, BinaryInfo>,
) -> Result<Vec<Vec<Value>>> {
    if !supports_service_list(context, kernel) {
        log::warn!(
            "This plugin only supports Windows 10 version 15063+ 64bit Windows memory samples"
        );
        return Ok(Vec::new());
    }
    let header_type = format!("{table}!_SERVICE_HEADER");

    let mut rows: Vec<Vec<Value>> = Vec::new();
    for (process, layer_name, _) in controller_processes(context, kernel, physical)? {
        let Some(range) = executable_range(context, kernel, &process) else {
            log::warn!(
                "Could not find the application executable VAD for services.exe. Unable to proceed."
            );
            continue;
        };
        let layer = context.layers.get(&layer_name)?;
        let scanner = BytesScanner::new(b"Sc27".to_vec());
        let mut hits: Vec<u64> = Vec::new();
        scan_layer(
            layer.as_ref(),
            &context.layers,
            &scanner,
            Some(&[range]),
            |offset| hits.push(offset),
        )?;

        for hit in hits {
            for (offset, record) in enumerate_header(context, &header_type, &layer_name, hit)
            {
                rows.push(row(offset, &record, registry));
            }
        }
    }
    Ok(rows)
}

/// Whether the list the controller keeps has the shape this walk expects.
pub fn supports_service_list(context: &Arc<Context>, kernel: &Module) -> bool {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    sixty_four_bit && versions::matches(context, kernel, versions::IS_WIN10_15063_OR_LATER)
}

/// Every record a header names, newest first.
fn enumerate_header(
    context: &Arc<Context>,
    header_type: &str,
    layer_name: &str,
    offset: u64,
) -> Vec<(u64, Object)> {
    // A header is aligned, and names the newest record of a chain that runs
    // backwards through every service.
    if offset % 8 != 0 {
        return Vec::new();
    }
    let Ok(header) = context.object(header_type, layer_name, offset) else {
        return Vec::new();
    };
    let Ok(first) = header
        .member("ServiceRecord")
        .and_then(|record| record.dereference())
    else {
        return Vec::new();
    };
    if !record_is_valid(&first) {
        return Vec::new();
    }
    traverse(&first)
}

/// The service controller's processes, with the memory each has mapped.
fn controller_processes(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> Result<Vec<(crate::framework::symbols::windows::Process, String, Vec<(u64, u64)>)>> {
    let mut found = Vec::new();
    for process in list_processes(context, kernel)? {
        if process.image_file_name().unwrap_or_default() != "services.exe" {
            continue;
        }
        let Ok(layer_name) = process.address_space(physical) else {
            continue;
        };

        // Only the memory the process itself has mapped is searched.
        let mut sections: Vec<(u64, u64)> = Vec::new();
        for vad in
            crate::framework::plugins::windows::vadinfo::walk_vad_tree(context, kernel, &process)
                .unwrap_or_default()
        {
            let (Some(start), Some(end)) = (
                crate::framework::plugins::windows::vadinfo::start_vpn(&vad),
                crate::framework::plugins::windows::vadinfo::end_vpn(&vad),
            ) else {
                continue;
            };
            let size = end - start + 1;
            if size > 0 {
                sections.push((start, size));
            }
        }
        found.push((process, layer_name, sections));
    }
    Ok(found)
}

/// Where the controller's own executable is mapped.
fn executable_range(
    context: &Arc<Context>,
    kernel: &Module,
    process: &crate::framework::symbols::windows::Process,
) -> Option<(u64, u64)> {
    for vad in
        crate::framework::plugins::windows::vadinfo::walk_vad_tree(context, kernel, process)
            .unwrap_or_default()
    {
        let Some(name) = crate::framework::plugins::windows::vadinfo::file_name_of(&vad) else {
            continue;
        };
        if !name.to_lowercase().ends_with("\\services.exe") {
            continue;
        }
        let (Some(start), Some(end)) = (
            crate::framework::plugins::windows::vadinfo::start_vpn(&vad),
            crate::framework::plugins::windows::vadinfo::end_vpn(&vad),
        ) else {
            continue;
        };
        return Some((start, end - start + 1));
    }
    None
}

/// One service record, as a row.
fn row(offset: u64, record: &Object, registry: &HashMap<String, BinaryInfo>) -> Vec<Value> {
    let name = wide_string(record, "ServiceName");
    let kind = service_type(record);
    let state = enum_description(record, "State");
    let running = matches!(&state, Value::Str(text) if text == "SERVICE_RUNNING");
    let for_process = kind.contains("PROCESS");

    // What the registry says this service runs, where the registry knows it.
    let info = match &name {
        Value::Str(name) => registry.get(name).cloned(),
        _ => None,
    }
    .unwrap_or(BinaryInfo {
        binary: Value::unreadable(),
        dll: Value::unreadable(),
    });

    vec![
        Value::hex(offset),
        record
            .member("Order")
            .and_then(|order| order.as_i64())
            .map(Value::int)
            .unwrap_or_else(|_| Value::unreadable()),
        // Only a running service of a kind that has a process has one.
        if !running || !for_process {
            Value::not_applicable()
        } else {
            record
                .member("ServiceProcess")
                .and_then(|process| process.dereference())
                .and_then(|process| process.member("ProcessId"))
                .and_then(|pid| pid.as_i64())
                .map(Value::int)
                .unwrap_or_else(|_| Value::unreadable())
        },
        enum_description(record, "Start"),
        state,
        Value::string(kind.clone()),
        name,
        wide_string(record, "DisplayName"),
        if !running {
            Value::not_applicable()
        } else if for_process {
            record
                .member("ServiceProcess")
                .and_then(|process| process.dereference())
                .map(|process| wide_string(&process, "BinaryPath"))
                .unwrap_or_else(|_| Value::unreadable())
        } else {
            wide_string(record, "DriverName")
        },
        info.binary,
        info.dll,
    ]
}

/// Follow a record's chain back through the services registered before it.
///
/// Each record but the first is reached through the link that names it, and the
/// address reported for it is that link's own. The reader hands the link itself
/// onward rather than what it points at, and the reported offsets are those of
/// the links.
fn traverse(record: &Object) -> Vec<(u64, Object)> {
    let mut found = vec![(record.offset(), record.clone())];
    let mut current = record.clone();

    // Later releases link each record to the one before it. Earlier ones use
    // the backward link of the list they all sit on.
    let link_member = if record.has_member("PrevEntry") {
        "PrevEntry"
    } else {
        "ServiceList"
    };

    loop {
        let link = if link_member == "PrevEntry" {
            current.member("PrevEntry")
        } else {
            current
                .member("ServiceList")
                .and_then(|list| list.member("Blink"))
        };
        let Ok(link) = link else { break };
        let Ok(address) = link.pointer_value() else {
            break;
        };
        if address == 0 {
            break;
        }
        let Ok(next) = link.dereference() else { break };
        if !record_is_valid(&next) {
            break;
        }
        found.push((link.offset(), next.clone()));
        current = next;
    }
    found
}

/// Whether a record holds together well enough to report.
fn record_is_valid(record: &Object) -> bool {
    let Ok(order) = record.member("Order").and_then(|order| order.as_i64()) else {
        return false;
    };
    if !(0..=0xFFFF).contains(&order) {
        return false;
    }
    // A state or start kind the controller does not define means this was
    // never a record.
    for member in ["State", "Start"] {
        let Ok(field) = record.member(member) else {
            return false;
        };
        if !matches!(enum_description_of(&field), Value::Str(_)) {
            return false;
        }
    }
    true
}

/// The name an enumeration gives one of its values.
fn enum_description(record: &Object, member: &str) -> Value {
    match record.member(member) {
        Ok(field) => enum_description_of(&field),
        Err(_) => Value::unreadable(),
    }
}

fn enum_description_of(field: &Object) -> Value {
    let Ok(value) = field.as_i64() else {
        return Value::unreadable();
    };
    let known = field
        .resolved_template()
        .ok()
        .and_then(|template| template.as_enum().map(|kind| kind.is_valid_choice(value)))
        .unwrap_or(false);
    if !known {
        return Value::unreadable();
    }
    field
        .enum_name()
        .map(Value::string)
        .unwrap_or_else(|_| Value::unreadable())
}

/// The kinds a service claims to be, as one name per flag.
fn service_type(record: &Object) -> String {
    let value = record
        .member("Type")
        .and_then(|kind| kind.as_u64())
        .unwrap_or(0);
    SERVICE_TYPES
        .iter()
        .filter(|(_, flag)| value & flag != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

/// A wide string a record points at.
fn wide_string(record: &Object, member: &str) -> Value {
    let Ok(address) = record
        .member(member)
        .and_then(|pointer| pointer.pointer_value())
    else {
        return Value::unreadable();
    };
    if address == 0 {
        return Value::unreadable();
    }
    let context = record.context();
    let Ok(data) = context
        .layers
        .read(record.layer_name(), address, 512, false)
    else {
        return Value::unreadable();
    };
    Value::string(decode_wide(&data))
}

/// Decode wide text, stopping at its terminator.
fn decode_wide(data: &[u8]) -> String {
    let mut units = Vec::new();
    for pair in data.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// What the registry records for each service.
fn registry_services(context: &Arc<Context>, kernel: &Module) -> HashMap<String, BinaryInfo> {
    let mut found = HashMap::new();
    let table = kernel.symbol_table_name.clone();

    for hive_object in
        crate::framework::plugins::windows::registry::list_hives(context, kernel).unwrap_or_default()
    {
        let Ok(hive) =
            crate::framework::plugins::windows::registry::open_hive(context, kernel, hive_object)
        else {
            continue;
        };
        if !hive
            .hive_name()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("machine\\system")
        {
            continue;
        }
        let Ok(root) = read_key(context, &hive, &table, hive.root_cell_offset(), String::new())
        else {
            continue;
        };

        let services = ["CurrentControlSet", "Services"]
            .iter()
            .try_fold(root.clone(), |current, component| {
                descend(context, &hive, &table, &current, component, false)
            })
            .or_else(|| {
                ["ControlSet001", "Services"]
                    .iter()
                    .try_fold(root.clone(), |current, component| {
                        descend(context, &hive, &table, &current, component, false)
                    })
            });
        let Some(services) = services else {
            continue;
        };

        for service in subkeys(context, &hive, &table, &services).unwrap_or_default() {
            let Ok(name) = service.name() else { continue };
            found.insert(
                name,
                BinaryInfo {
                    binary: registry_string(context, &hive, &table, &service, "ImagePath"),
                    dll: service_dll(context, &hive, &table, &service),
                },
            );
        }
        break;
    }
    found
}

/// One named subkey of a key.
fn descend(
    context: &Arc<Context>,
    hive: &crate::framework::layers::registry::RegistryHive,
    table: &str,
    key: &RegistryKey,
    name: &str,
    exact: bool,
) -> Option<RegistryKey> {
    subkeys(context, hive, table, key)
        .ok()?
        .into_iter()
        .find(|child| {
            child
                .name()
                .map(|found| {
                    if exact {
                        found == name
                    } else {
                        found.to_lowercase() == name.to_lowercase()
                    }
                })
                .unwrap_or(false)
        })
}

/// A named value of a key, as text.
fn registry_string(
    context: &Arc<Context>,
    hive: &crate::framework::layers::registry::RegistryHive,
    table: &str,
    key: &RegistryKey,
    name: &str,
) -> Value {
    let Some(value) = values(context, hive, table, key)
        .unwrap_or_default()
        .into_iter()
        .find(|value| value.name().map(|found| found == name).unwrap_or(false))
    else {
        // A service that names no such value has none to report.
        return Value::unreadable();
    };
    match value.data(hive) {
        Ok(data) => Value::string(decode_wide(&data)),
        Err(_) => Value::unparsable(),
    }
}

/// The library a service runs inside, where it runs inside one.
fn service_dll(
    context: &Arc<Context>,
    hive: &crate::framework::layers::registry::RegistryHive,
    table: &str,
    service: &RegistryKey,
) -> Value {
    // The name is compared as it is written, so a key spelled any other way
    // is not found at all.
    match descend(context, hive, table, service, "Parameters", true) {
        Some(parameters) => registry_string(context, hive, table, &parameters, "ServiceDll"),
        None => Value::unreadable(),
    }
}

/// Load the description of the controller's records for this release.
fn service_table(context: &Arc<Context>, kernel: &Module) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    // Newest first: the first release whose marks are all present is the one.
    let candidates: &[(&[versions::Check], bool, &str)] = &[
        (versions::IS_WIN10_25398_OR_LATER, true, "services-win10-25398-x64"),
        (versions::IS_WIN10_19041_OR_LATER, true, "services-win10-19041-x64"),
        (versions::IS_WIN10_19041_OR_LATER, false, "services-win10-19041-x86"),
        (versions::IS_WIN10_18362_OR_LATER, true, "services-win10-18362-x64"),
        (versions::IS_WIN10_18362_OR_LATER, false, "services-win10-18362-x86"),
        (versions::IS_WIN10_17763_OR_LATER, false, "services-win10-17763-x86"),
        (versions::IS_WIN10_16299_OR_LATER, true, "services-win10-16299-x64"),
        (versions::IS_WIN10_16299_OR_LATER, false, "services-win10-16299-x86"),
        (versions::IS_WIN10_15063, true, "services-win10-15063-x64"),
        (versions::IS_WIN10_15063, false, "services-win10-15063-x86"),
        (versions::IS_WIN10_UP_TO_15063, true, "services-win8-x64"),
        (versions::IS_WIN10_UP_TO_15063, false, "services-win8-x86"),
        (versions::IS_WINDOWS_8_OR_LATER, true, "services-win8-x64"),
        (versions::IS_WINDOWS_8_OR_LATER, true, "services-win8-x86"),
        (versions::IS_VISTA_OR_LATER, true, "services-vista-x64"),
        (versions::IS_VISTA_OR_LATER, false, "services-vista-x86"),
    ];

    let table = candidates
        .iter()
        .find(|(checks, for_64_bit, _)| {
            *for_64_bit == sixty_four_bit && versions::matches(context, kernel, checks)
        })
        .map(|(_, _, name)| *name)
        .ok_or_else(|| {
            VolatilityError::Other("This version of Windows is not supported".to_string())
        })?;

    context.ensure_table(table, "windows/services", table)?;
    Ok(table.to_string())
}
