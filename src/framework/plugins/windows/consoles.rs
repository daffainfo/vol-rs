//! The console host keeps a `_CONSOLE_INFORMATION` structure for each window,
//! holding the title, the processes attached to it, the aliases registered for
//! each executable, the command histories and the screen buffers. Its layout is
//! not described by any public symbol file, so it is read through symbol files
//! of their own, chosen by the release of Windows and the build of
//! `conhost.exe`.
//!
//! This module attempts to locate windows console histories. The structures are
//! found by scanning the host's own image for the configured history size,
//! which sits at a known offset inside the structure.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{ConfigValue, Configuration, Context, Module};
use crate::framework::layers::scanners::{scan_layer, BytesScanner};
use crate::framework::objects::utility::{decode_utf16, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::{kernel_module, physical_layer, vadinfo};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, Process};

/// Looks for Windows console buffers
pub struct Consoles;

impl Plugin for Consoles {
    fn name(&self) -> &'static str {
        "windows.consoles.Consoles"
    }

    fn description(&self) -> &'static str {
        "Looks for Windows console buffers"
    }

    fn requirements(&self) -> Vec<Requirement> {
        console_requirements(true)
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        console_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let (history_sizes, buffer_counts) = console_settings(&context, config, &kernel, true);
        let mut grid = TreeGrid::new(console_columns());

        for (process, layer, table, base, size) in console_hosts(&context, &kernel, &physical) {
            let mut found = false;
            let mut last: Option<Object> = None;
            for history in &history_sizes {
                for console in
                    scan_console_information(&context, &layer, &table, (base, size), *history)
                {
                    // Every candidate is remembered, whether or not it holds
                    // anything: where a host turns out to have no console at
                    // all, the last candidate's address is the one reported.
                    last = Some(console.clone());
                    if !buffer_counts
                        .iter()
                        .any(|count| console_is_valid(&console, *count))
                    {
                        continue;
                    }
                    let properties = console_properties(&context, &table, &console);
                    if !properties.is_empty() {
                        found = true;
                        emit(&mut grid, &process, console.offset(), &properties, false)?;
                    }
                }
            }
            if !found {
                emit_nothing(
                    &mut grid,
                    &process,
                    last.as_ref().map(|console| console.offset()),
                    "_CONSOLE_INFORMATION",
                    "Console Information Not Found",
                )?;
            }
        }
        Ok(grid)
    }
}

/// Looks for Windows Command History lists
pub struct CmdScan;

impl Plugin for CmdScan {
    fn name(&self) -> &'static str {
        "windows.cmdscan.CmdScan"
    }

    fn description(&self) -> &'static str {
        "Looks for Windows Command History lists"
    }

    fn requirements(&self) -> Vec<Requirement> {
        console_requirements(false)
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        console_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let (history_sizes, _) = console_settings(&context, config, &kernel, false);
        let mut grid = TreeGrid::new(console_columns());

        for (process, layer, table, _base, _size) in console_hosts(&context, &kernel, &physical) {
            // Returns vads of a process with size smaller than the size
            // filter: the history is looked for anywhere in the host's own
            // mappings, rather than only in its image as the console structure
            // is.
            let sections: Vec<(u64, u64)> =
                vadinfo::walk_vad_tree(&context, &kernel, &process)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|vad| {
                        let start = vadinfo::start_vpn(vad)?;
                        let end = vadinfo::end_vpn(vad)?;
                        let size = end - start + 1;
                        (size < 0x4000_0000).then_some((start, size))
                    })
                    .collect();

            let Ok(history_type) = context
                .symbol_space
                .get_type(&format!("{table}!_COMMAND_HISTORY"))
            else {
                continue;
            };
            let offset = member_offset(&context, &history_type, "CommandCountMax");

            let mut found = false;
            let mut last: Option<Object> = None;
            // scan for potential _COMMAND_HISTORY structures by using the
            // CommandHistorySize
            for size in &history_sizes {
                let needle = BytesScanner::new((*size as u16).to_le_bytes().to_vec());
                let Ok(reader) = context.layers.get(&layer) else {
                    continue;
                };
                let mut hits = Vec::new();
                let _ = scan_layer(
                    reader.as_ref(),
                    &context.layers,
                    &needle,
                    Some(&sections),
                    |hit| hits.push(hit),
                );
                for hit in hits {
                    let Some(address) = hit.checked_sub(offset) else {
                        continue;
                    };
                    let history = context.object_from_template(
                        history_type.clone(),
                        &layer,
                        address,
                    );
                    // As above: the last candidate is what a host with no
                    // history is reported against.
                    last = Some(history.clone());
                    if !history_is_valid(&context, &table, &history, *size) {
                        continue;
                    }
                    let properties = history_properties(&context, &table, &history);
                    if !properties.is_empty() {
                        found = true;
                        emit(&mut grid, &process, history.offset(), &properties, true)?;
                    }
                }
            }
            // if found is still false, then none of the scanned locations
            // found a valid _COMMAND_HISTORY for the process, so report the
            // process and some empty data so the process can at least be
            // reported that it was found with no history
            if !found {
                emit_nothing(
                    &mut grid,
                    &process,
                    last.as_ref().map(|history| history.offset()),
                    "_COMMAND_HISTORY",
                    "History Not Found",
                )?;
            }
        }
        Ok(grid)
    }
}

fn console_columns() -> Vec<Column> {
    vec![
        Column::int("PID"),
        Column::string("Process"),
        Column::new("ConsoleInfo", ColumnType::UInt),
        Column::string("Property"),
        Column::new("Address", ColumnType::UInt),
        Column::string("Data"),
    ]
}

/// How many commands a console keeps by default.
const DEFAULT_HISTORY_SIZE: i64 = 50;

/// How many history buffers a console keeps by default.
const DEFAULT_BUFFER_COUNT: i64 = 4;

/// The options both console plugins take.
fn console_requirements(with_buffers: bool) -> Vec<Requirement> {
    let mut requirements = vec![
        Requirement::kernel(),
        Requirement::new(
            "no_registry",
            if with_buffers {
                "Don't search the registry for possible values of CommandHistorySize and \
                 HistoryBufferMax"
            } else {
                "Don't search the registry for possible values of CommandHistorySize"
            },
            RequirementKind::Bool,
        )
        .with_default(ConfigValue::Bool(false)),
        Requirement::new(
            "max_history",
            "CommandHistorySize values to search for.",
            RequirementKind::List(Box::new(RequirementKind::Int)),
        )
        .with_default(ConfigValue::List(vec![ConfigValue::Int(
            DEFAULT_HISTORY_SIZE,
        )])),
    ];
    if with_buffers {
        requirements.push(
            Requirement::new(
                "max_buffers",
                "HistoryBufferMax values to search for.",
                RequirementKind::List(Box::new(RequirementKind::Int)),
            )
            .with_default(ConfigValue::List(vec![ConfigValue::Int(
                DEFAULT_BUFFER_COUNT,
            )])),
        );
    }
    requirements
}

/// The console sizes to search for, in the order the reference implementation
/// searches them.
///
/// The values asked for are gathered into a set along with whatever the
/// registry records, and the order a set is walked in is the order of the slots
/// it fills, which is reproduced here.
fn console_settings(
    context: &Arc<Context>,
    config: &Configuration,
    kernel: &Module,
    with_buffers: bool,
) -> (Vec<i64>, Vec<i64>) {
    let read = |name: &str, fallback: i64| -> Vec<i64> {
        config
            .get(name)
            .and_then(|value| {
                value.as_list().map(|list| {
                    list.iter()
                        .filter_map(|entry| entry.as_int())
                        .collect::<Vec<i64>>()
                })
            })
            .filter(|values: &Vec<i64>| !values.is_empty())
            .unwrap_or_else(|| vec![fallback])
    };
    let mut history = read("max_history", DEFAULT_HISTORY_SIZE);
    let mut buffers = if with_buffers {
        read("max_buffers", DEFAULT_BUFFER_COUNT)
    } else {
        Vec::new()
    };

    if !config.get_bool("no_registry").unwrap_or(false) {
        // A user hive records the console sizes that user's shells were given.
        for (name, number) in console_key_values(context, kernel) {
            match name.as_str() {
                "HistoryBufferSize" => history.push(number),
                "NumberOfHistoryBuffers" if with_buffers => buffers.push(number),
                _ => {}
            }
        }
    }

    (set_order(&history), set_order(&buffers))
}

/// The order a set of small whole numbers is walked in.
///
/// The reference implementation collects these in a set, and a set is walked in
/// the order of the slots its members landed in rather than the order they were
/// added or their value. The table doubles in size as it fills, and a member
/// lands at its own value modulo the table size, moving along to the next free
/// slot when that one is taken.
fn set_order(values: &[i64]) -> Vec<i64> {
    let mut unique: Vec<i64> = Vec::new();
    for value in values {
        if !unique.contains(value) {
            unique.push(*value);
        }
    }
    // The table starts at eight slots and grows to four times the number of
    // members once it is three fifths full.
    let mut size = 8usize;
    while unique.len() * 5 >= (size - 1) * 3 {
        size = (unique.len() * 4).next_power_of_two().max(16);
    }
    let mut table: Vec<Option<i64>> = vec![None; size];
    for value in &unique {
        let mut index = (*value as usize) & (size - 1);
        while table[index].is_some() {
            index = (index + 1) & (size - 1);
        }
        table[index] = Some(*value);
    }
    table.into_iter().flatten().collect()
}

/// The values under every hive's `Console` key.
fn console_key_values(context: &Arc<Context>, kernel: &Module) -> Vec<(String, i64)> {
    use crate::framework::symbols::windows::registry::{read_key, subkeys, values};

    let mut found = Vec::new();
    for hive_object in
        crate::framework::plugins::windows::registry::list_hives(context, kernel).unwrap_or_default()
    {
        let Ok(hive) =
            crate::framework::plugins::windows::registry::open_hive(context, kernel, hive_object)
        else {
            continue;
        };
        let table = kernel.symbol_table_name.clone();
        let Ok(root) = read_key(context, &hive, &table, hive.root_cell_offset(), String::new())
        else {
            continue;
        };
        for child in subkeys(context, &hive, &table, &root).unwrap_or_default() {
            if child.name().map(|name| name != "Console").unwrap_or(true) {
                continue;
            }
            for value in values(context, &hive, &table, &child).unwrap_or_default() {
                let Ok(name) = value.name() else { continue };
                let Ok(data) = value.data(&hive) else { continue };
                if data.len() >= 4 {
                    let number = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64;
                    found.push((name, number));
                }
            }
        }
    }
    found
}

/// One property of a console or history structure, as it is reported.
struct Property {
    level: usize,
    name: String,
    /// Absent where the value has no address of its own.
    address: Option<u64>,
    data: String,
}

impl Property {
    fn new(level: usize, name: impl Into<String>, address: Option<u64>, data: impl Into<String>) -> Self {
        Self {
            level,
            name: name.into(),
            address,
            data: data.into(),
        }
    }
}

/// Write one structure's properties as rows.
///
/// The two plugins differ in how they report a property with nothing in it: the
/// console listing reports it as unavailable, the history listing writes the
/// value out whatever it is.
fn emit(
    grid: &mut TreeGrid,
    process: &Process,
    owner: u64,
    properties: &[Property],
    verbatim: bool,
) -> Result<()> {
    let pid = process.pid().unwrap_or(0) as i64;
    let name = process.image_file_name().unwrap_or_default();
    for property in properties {
        grid.push(
            property.level,
            vec![
                Value::int(pid),
                Value::string(name.clone()),
                Value::hex(owner),
                Value::string(property.name.clone()),
                match property.address {
                    Some(address) => Value::hex(address),
                    None => Value::not_applicable(),
                },
                if verbatim || !property.data.is_empty() {
                    Value::string(property.data.clone())
                } else {
                    Value::not_available()
                },
            ],
        )?;
    }
    Ok(())
}

/// Report that a console host held nothing worth listing.
fn emit_nothing(
    grid: &mut TreeGrid,
    process: &Process,
    owner: Option<u64>,
    property: &str,
    note: &str,
) -> Result<()> {
    grid.push(
        0,
        vec![
            Value::int(process.pid().unwrap_or(0) as i64),
            Value::string(process.image_file_name().unwrap_or_default()),
            match owner {
                Some(address) => Value::hex(address),
                None => Value::not_applicable(),
            },
            Value::string(property),
            Value::not_applicable(),
            Value::string(note),
        ],
    )
}

/// Walks the process list and returns the conhost instances, with the layer to
/// read each through, the symbol table describing its structures and where its
/// image sits.
fn console_hosts(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> Vec<(Process, String, String, u64, u64)> {
    let mut found = Vec::new();
    let mut table: Option<String> = None;
    for process in list_processes(context, kernel).unwrap_or_default() {
        if process
            .image_file_name()
            .map(|name| !name.eq_ignore_ascii_case("conhost.exe"))
            .unwrap_or(true)
        {
            continue;
        }
        let Ok(layer) = process.address_space(physical) else {
            continue;
        };
        let Some((base, size)) = host_image(context, kernel, &process) else {
            continue;
        };
        // The table is worked out from the first host found and reused, which
        // is what upstream does, so a later host of a different build is read
        // with the first one's symbols.
        if table.is_none() {
            match conhost_table(context, kernel, &layer, base) {
                Ok(name) => table = Some(name),
                Err(_) => continue,
            }
        }
        let Some(name) = table.clone() else { continue };
        found.push((process, layer, name, base, size));
    }
    found
}

/// Finds the base address of conhost.exe, and the size of the VAD for it.
fn host_image(context: &Arc<Context>, kernel: &Module, process: &Process) -> Option<(u64, u64)> {
    for vad in vadinfo::walk_vad_tree(context, kernel, process).unwrap_or_default() {
        let Some(name) = vadinfo::file_name_of(&vad) else {
            continue;
        };
        if !name.to_lowercase().ends_with("conhost.exe") {
            continue;
        }
        let start = vadinfo::start_vpn(&vad)?;
        let end = vadinfo::end_vpn(&vad)?;
        return Some((start, end - start + 1));
    }
    None
}

/// Tries to determine which symbol filename to use for the image's console
/// information. This is similar to the netstat plugin.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
/// * `kernel` - The module for the kernel
/// * `layer` - The name of the conhost process memory layer
/// * `base` - the base address of conhost.exe
///
/// # Returns
///
/// The filename of the symbol table to use.
fn conhost_table(
    context: &Arc<Context>,
    kernel: &Module,
    layer: &str,
    base: u64,
) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    let debug_minor = context
        .object_from_symbol(kernel, "KdVersionBlock", Some("_DBGKD_GET_VERSION64"))
        .and_then(|version| version.member("MinorVersion"))
        .and_then(|value| value.as_u64())
        .map_err(|_| {
            VolatilityError::Other(
                "Kernel Debug Structure missing VERSION/KUSER structure, unable to determine \
                 Windows version!"
                    .to_string(),
            )
        })?;
    let (major, minor) =
        crate::framework::plugins::windows::info::windows_version(context, kernel).ok_or_else(
            || {
                VolatilityError::Other(
                    "Kernel Debug Structure missing VERSION/KUSER structure, unable to determine \
                     Windows version!"
                        .to_string(),
                )
            },
        )?;

    // these versions are listed explicitly because symbol files differ based on
    // version *and* architecture. this is currently the clearest way to show
    // the differences, even if it introduces a fair bit of redundancy.
    // furthermore, it is easy to append new versions.
    const VERSIONS: &[(u64, u64, u64, u64, &str)] = &[
        (10, 0, 17763, 1, "consoles-win10-17763-x64"),
        (10, 0, 17763, 3232, "consoles-win10-17763-3232-x64"),
        (10, 0, 18362, 0, "consoles-win10-18362-x64"),
        (10, 0, 19041, 0, "consoles-win10-19041-x64"),
        (10, 0, 20348, 1, "consoles-win10-20348-x64"),
        (10, 0, 20348, 1970, "consoles-win10-20348-1970-x64"),
        (10, 0, 20348, 2461, "consoles-win10-20348-2461-x64"),
        (10, 0, 20348, 2520, "consoles-win10-20348-2461-x64"),
        (10, 0, 22000, 0, "consoles-win10-22000-x64"),
        (10, 0, 22621, 1, "consoles-win10-22621-x64"),
        (10, 0, 22621, 3527, "consoles-win10-22621-3527-x64"),
        (10, 0, 25398, 0, "consoles-win10-22000-x64"),
    ];
    let candidates: &[(u64, u64, u64, u64, &str)] = if sixty_four_bit { VERSIONS } else { &[] };

    // we do not need to check for conhost's specific FileVersion in every case,
    // so keep it 0 as a default. We need to define additional version numbers
    // (which are then found via conhost.exe's FileVersion header) in case there
    // is ambiguity _within_ an OS version. If such a version number (last
    // number of the tuple) is defined for the current OS we need to inspect
    // conhost.exe's headers to see if we can grab the precise version.
    let mut build = 0u64;
    if candidates
        .iter()
        .any(|(a, b, c, d, _)| (*a, *b, *c) == (major, minor, debug_minor) && *d != 0)
    {
        const MAXIMUM_IMAGE: usize = 256 * 1024 * 1024;
        if let Some(version) = crate::framework::plugins::windows::verinfo::image_version(
            context,
            layer,
            base,
            MAXIMUM_IMAGE,
        ) {
            build = version.build as u64;
        } else if let Some((_, _, _, found)) =
            // the following is IntelLayer specific and might need to be adapted
            // to other architectures.
            crate::framework::plugins::windows::verinfo::search_version_info(
                context,
                &base_layer_of(context, &kernel.layer_name),
                "CONHOST.EXE",
            )
        {
            if let Value::Int(number, _) = found {
                build = number as u64;
            }
        }
    }

    // when determining the symbol file we have to consider the following cases:
    // the determined version's symbol file is found -> proceed
    // the determined version's symbol file is not found -> abort
    // the determined version has no mapped symbol file -> if win10 use latest,
    // otherwise throw exc
    // windows version cannot be determined -> throw exc
    let exact = candidates
        .iter()
        .find(|(a, b, c, d, _)| (*a, *b, *c, *d) == (major, minor, debug_minor, build))
        .map(|(_, _, _, _, name)| *name);
    let name = match exact {
        Some(name) => name,
        None => {
            // no match on filename means that we possibly have a version
            // newer than those listed here. try to grab the latest supported
            // version of the current image NT version. If that symbol version
            // does not work, support has to be added manually.
            let mut matching: Vec<&(u64, u64, u64, u64, &str)> = candidates
                .iter()
                .filter(|(a, b, c, d, _)| {
                    *a == major && *b == minor && *c <= debug_minor && *d <= build
                })
                .collect();
            matching.sort_by_key(|(a, b, c, d, _)| (*a, *b, *c, *d));
            match matching.last() {
                Some((_, _, _, _, name)) => *name,
                None => {
                    return Err(VolatilityError::Other(format!(
                        "This version of Windows is not supported: {major}.{minor} \
                         {debug_minor}!"
                    )))
                }
            }
        }
    };

    context.ensure_table(name, "windows/consoles", name)?;
    context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;
    Ok(name.to_string())
}

/// The layer the kernel's own layer is built over, which is where a search of
/// physical memory looks.
fn base_layer_of(context: &Arc<Context>, layer: &str) -> String {
    context
        .layers
        .get(layer)
        .ok()
        .and_then(|handle| handle.dependencies().into_iter().next())
        .unwrap_or_else(|| layer.to_string())
}

/// The offset of a member within a type, or zero where it has none.
fn member_offset(
    context: &Arc<Context>,
    template: &Arc<crate::framework::objects::template::Template>,
    name: &str,
) -> u64 {
    context
        .symbol_space
        .find_member(template, name)
        .ok()
        .flatten()
        .map(|(offset, _)| offset)
        .unwrap_or(0)
}

/// Every `_CONSOLE_INFORMATION` the host's image holds a candidate for.
///
/// The structure is found by its configured history size, which sits at a known
/// offset inside it.
fn scan_console_information(
    context: &Arc<Context>,
    layer: &str,
    table: &str,
    image: (u64, u64),
    size: i64,
) -> Vec<Object> {
    let Ok(template) = context
        .symbol_space
        .get_type(&format!("{table}!_CONSOLE_INFORMATION"))
    else {
        return Vec::new();
    };
    let offset = member_offset(context, &template, "CommandHistorySize");
    let needle = BytesScanner::new((size as u16).to_le_bytes().to_vec());
    let Ok(reader) = context.layers.get(layer) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let _ = scan_layer(
        reader.as_ref(),
        &context.layers,
        &needle,
        Some(&[image]),
        |hit| hits.push(hit),
    );
    hits.into_iter()
        .filter_map(|hit| hit.checked_sub(offset))
        .map(|address| context.object_from_template(template.clone(), layer, address))
        .collect()
}

/// Whether a candidate console structure holds plausible values.
///
/// The history buffer count must be between one and the maximum, and the last
/// displayed index between -1 and the maximum.
fn console_is_valid(console: &Object, max_buffers: i64) -> bool {
    let count = console
        .member("HistoryBufferCount")
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    if count < 1 || count > max_buffers {
        return false;
    }
    !console_title(console, "Title").is_empty() || !console_title(console, "OriginalTitle").is_empty()
}

/// One of the console's two titles.
fn console_title(console: &Object, member: &str) -> String {
    console
        .member(member)
        .and_then(|pointer| pointer.pointer_value())
        .ok()
        .filter(|address| *address != 0)
        .and_then(|address| {
            let context = console.context();
            context
                .layers
                .read(console.layer_name(), address, 512, false)
                .ok()
        })
        .map(|data| {
            let text = decode_utf16(&data);
            text.split('\0').next().unwrap_or("").to_string()
        })
        .unwrap_or_default()
}

/// A counted wide string, as the console structures hold commands and names.
///
/// A short one is held inline; a longer one is held behind a pointer.
fn command_string(command: &Object) -> Option<String> {
    let length = command.member("Length").and_then(|value| value.as_u64()).ok()?;
    let context = command.context();
    if length < 8 {
        let chars = command.member("Chars").ok()?;
        let data = context
            .layers
            .read(command.layer_name(), chars.offset(), (length * 2) as usize, false)
            .ok()?;
        return Some(cut_at_nul(&decode_utf16(&data)));
    }
    if length < 1024 {
        let address = command
            .member("Pointer")
            .and_then(|pointer| pointer.pointer_value())
            .ok()?;
        let data = context
            .layers
            .read(command.layer_name(), address, (length * 2) as usize, false)
            .ok()?;
        return Some(cut_at_nul(&decode_utf16(&data)));
    }
    None
}

/// Text up to its first terminator, which is where a cast to a string stops.
fn cut_at_nul(text: &str) -> String {
    text.split('\0').next().unwrap_or("").to_string()
}

/// Whether a counted string looks like one.
fn command_is_valid(command: &Object) -> bool {
    let read = |name: &str| command.member(name).and_then(|value| value.as_i64()).unwrap_or(0);
    let length = read("Length");
    let allocated = read("Allocated");
    length >= 1 && allocated >= 1 && length <= 1024 && allocated <= 1024
}

/// How many commands a history holds, which is the extent of its bucket.
fn command_count(context: &Arc<Context>, table: &str, history: &Object) -> i64 {
    let Ok(command) = context.symbol_space.get_type(&format!("{table}!_COMMAND")) else {
        return 0;
    };
    let Ok(size) = context.symbol_space.size_of(&command) else {
        return 0;
    };
    if size == 0 {
        return 0;
    }
    let bucket = |name: &str| -> i64 {
        history
            .member("CommandBucket")
            .and_then(|bucket| bucket.member(name))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
    };
    (bucket("End") - bucket("Begin")) / size as i64
}

/// The handle of the process a history belongs to.
fn history_handle(history: &Object) -> i64 {
    history
        .member("ConsoleProcessHandle")
        .and_then(|handle| handle.member("ProcessHandle"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0)
}

/// Whether a candidate history structure holds plausible values.
///
/// The count must be between zero and max, the last displayed must be between
/// -1 and max, and the process handle must be a valid pid.
fn history_is_valid(
    context: &Arc<Context>,
    table: &str,
    history: &Object,
    max_history: i64,
) -> bool {
    let count = command_count(context, table, history);
    if count < 0 || count > max_history {
        return false;
    }
    let last = history
        .member("LastDisplayed")
        .and_then(|value| value.as_i64())
        .unwrap_or(-2);
    if last < -1 || last > max_history {
        return false;
    }
    let handle = history_handle(history);
    handle > 0 && handle <= 0xFFFF && handle % 4 == 0
}

/// The commands a history's bucket holds, with their indices.
///
/// The bucket is an array of counted strings. Where no end is given the search
/// runs to whichever is further: the end of the allocation, or room for as many
/// commands as the history was configured to keep.
fn bucket_commands(
    context: &Arc<Context>,
    table: &str,
    history: &Object,
    end: Option<i64>,
) -> Vec<(usize, Object)> {
    let Ok(command_type) = context.symbol_space.get_type(&format!("{table}!_COMMAND")) else {
        return Vec::new();
    };
    let Ok(command_size) = context.symbol_space.size_of(&command_type) else {
        return Vec::new();
    };
    if command_size == 0 {
        return Vec::new();
    }
    let Ok(history_size) = context
        .symbol_space
        .get_type(history.type_name())
        .and_then(|template| context.symbol_space.size_of(&template))
    else {
        return Vec::new();
    };
    let bucket = |name: &str| -> i64 {
        history
            .member("CommandBucket")
            .and_then(|bucket| bucket.member(name))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
    };
    let begin = bucket("Begin");
    let end = end.unwrap_or_else(|| {
        let maximum = history
            .member("CommandCountMax")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        bucket("EndCapacity").max(begin + history_size as i64 * maximum)
    });

    let mut found = Vec::new();
    let mut address = begin;
    let mut index = 0usize;
    while address < end {
        let command =
            context.object_from_template(command_type.clone(), history.layer_name(), address as u64);
        if command_is_valid(&command) {
            found.push((index, command));
        }
        address += command_size as i64;
        index += 1;
    }
    found
}

/// The properties of one command history, in the order they are reported.
fn history_properties(context: &Arc<Context>, table: &str, history: &Object) -> Vec<Property> {
    let mut properties = Vec::new();
    properties.push(Property::new(0, "_COMMAND_HISTORY", Some(history.offset()), "None"));

    let application = history.member("Application").ok();
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.Application",
        application.as_ref().map(|value| value.offset()),
        application
            .as_ref()
            .and_then(command_string)
            .unwrap_or_else(|| "None".to_string()),
    ));
    let handle_field = history
        .member("ConsoleProcessHandle")
        .and_then(|handle| handle.member("ProcessHandle"))
        .ok();
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.ProcessHandle",
        handle_field.as_ref().map(|value| value.offset()),
        format!("{:#x}", history_handle(history)),
    ));
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.CommandCount",
        None,
        command_count(context, table, history).to_string(),
    ));
    let last = history.member("LastDisplayed").ok();
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.LastDisplayed",
        last.as_ref().map(|value| value.offset()),
        last.as_ref()
            .and_then(|value| value.as_i64().ok())
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ));
    let maximum = history.member("CommandCountMax").ok();
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.CommandCountMax",
        maximum.as_ref().map(|value| value.offset()),
        maximum
            .as_ref()
            .and_then(|value| value.as_i64().ok())
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ));
    let bucket = history.member("CommandBucket").ok();
    properties.push(Property::new(
        1,
        "_COMMAND_HISTORY.CommandBucket",
        bucket.as_ref().map(|value| value.offset()),
        "",
    ));

    for (index, command) in bucket_commands(context, table, history, None) {
        if let Some(text) = command_string(&command) {
            properties.push(Property::new(
                2,
                format!("_COMMAND_HISTORY.CommandBucket_Command_{index}"),
                Some(command.offset()),
                text,
            ));
        }
    }
    properties
}

/// The properties of one console, in the order they are reported.
fn console_properties(context: &Arc<Context>, table: &str, console: &Object) -> Vec<Property> {
    let mut properties = Vec::new();
    let field = |name: &str| console.member(name).ok();
    let numbered = |name: &str| -> (Option<u64>, String) {
        match console.member(name) {
            Ok(value) => (
                Some(value.offset()),
                value
                    .as_i64()
                    .map(|number| number.to_string())
                    .unwrap_or_default(),
            ),
            Err(_) => (None, String::new()),
        }
    };

    properties.push(Property::new(0, "_CONSOLE_INFORMATION", Some(console.offset()), ""));
    for name in ["ScreenX", "ScreenY"] {
        let (address, data) = console_screen_field(console, name);
        properties.push(Property::new(
            1,
            format!("_CONSOLE_INFORMATION.{name}"),
            address,
            data,
        ));
    }
    for name in ["CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax"] {
        let (address, data) = numbered(name);
        properties.push(Property::new(
            1,
            format!("_CONSOLE_INFORMATION.{name}"),
            address,
            data,
        ));
    }
    for name in ["Title", "OriginalTitle"] {
        properties.push(Property::new(
            1,
            format!("_CONSOLE_INFORMATION.{name}"),
            field(name).map(|value| value.offset()),
            console_title(console, name),
        ));
    }

    let (address, data) = numbered("ProcessCount");
    properties.push(Property::new(1, "_CONSOLE_INFORMATION.ProcessCount", address, data));
    properties.push(Property::new(
        1,
        "_CONSOLE_INFORMATION.ConsoleProcessList",
        field("ConsoleProcessList").map(|value| value.offset()),
        "",
    ));
    if let Ok(head) = console.member("ConsoleProcessList") {
        for (index, entry) in walk_list(&head, &format!("{table}!_CONSOLE_PROCESS_LIST"), "ListEntry", true)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            let Ok(pointer) = entry.member("ConsoleProcess") else {
                continue;
            };
            let Ok(attached) = pointer.dereference() else {
                continue;
            };
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.ConsoleProcessList.ConsoleProcess_{index}"),
                Some(attached.offset()),
                "",
            ));
            let identifier = attached.member("ProcessId").ok();
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.ConsoleProcessList.ConsoleProcess_{index}_ProcessId"),
                identifier.as_ref().map(|value| value.offset()),
                identifier
                    .as_ref()
                    .and_then(|value| value.as_i64().ok())
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ));
            let handle = attached.member("ProcessHandle").ok();
            properties.push(Property::new(
                2,
                format!(
                    "_CONSOLE_INFORMATION.ConsoleProcessList.ConsoleProcess_{index}_ProcessHandle"
                ),
                handle.as_ref().map(|value| value.offset()),
                handle
                    .as_ref()
                    .and_then(|value| value.as_i64().ok())
                    .map(|value| format!("{value:#x}"))
                    .unwrap_or_default(),
            ));
        }
    }

    properties.push(Property::new(
        1,
        "_CONSOLE_INFORMATION.ExeAliasList",
        field("ExeAliasList").map(|value| value.offset()),
        "",
    ));
    for (index, list) in exe_alias_lists(table, console).into_iter().enumerate() {
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ExeAliasList.AliasList_{index}"),
            Some(list.offset()),
            "",
        ));
        let name = list.member("ExeName").ok();
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ExeAliasList.AliasList_{index}.ExeName"),
            name.as_ref().map(|value| value.offset()),
            exe_name(&list).unwrap_or_default(),
        ));
        if let Ok(head) = list.member("AliasList") {
            for (alias_index, alias) in
                walk_list(&head, &format!("{table}!_ALIAS"), "ListEntry", true)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
            {
                for (member, label) in [("Source", "Source"), ("Target", "Target")] {
                    let Ok(value) = alias.member(member) else {
                        continue;
                    };
                    properties.push(Property::new(
                        3,
                        format!(
                            "_CONSOLE_INFORMATION.ExeAliasList.AliasList_{index}.Alias_{alias_index}.{label}"
                        ),
                        Some(value.offset()),
                        command_string(&value).unwrap_or_default(),
                    ));
                }
            }
        }
    }

    properties.push(Property::new(
        1,
        "_CONSOLE_INFORMATION.HistoryList",
        field("HistoryList").map(|value| value.offset()),
        "",
    ));
    if let Ok(head) = console.member("HistoryList") {
        for (index, history) in
            walk_list(&head, &format!("{table}!_COMMAND_HISTORY"), "ListEntry", true)
                .unwrap_or_default()
                .into_iter()
                .enumerate()
        {
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}"),
                Some(history.offset()),
                "",
            ));
            let application = history.member("Application").ok();
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}_Application"),
                application.as_ref().map(|value| value.offset()),
                application
                    .as_ref()
                    .and_then(command_string)
                    .unwrap_or_default(),
            ));
            let handle = history
                .member("ConsoleProcessHandle")
                .and_then(|value| value.member("ProcessHandle"))
                .ok();
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}_ProcessHandle"),
                handle.as_ref().map(|value| value.offset()),
                format!("{:#x}", history_handle(&history)),
            ));
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}_CommandCount"),
                None,
                command_count(context, table, &history).to_string(),
            ));
            let last = history.member("LastDisplayed").ok();
            properties.push(Property::new(
                2,
                format!("_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}_LastDisplayed"),
                last.as_ref().map(|value| value.offset()),
                last.as_ref()
                    .and_then(|value| value.as_i64().ok())
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ));
            let end = history
                .member("CommandBucket")
                .and_then(|bucket| bucket.member("End"))
                .and_then(|value| value.as_i64())
                .ok();
            for (command_index, command) in bucket_commands(context, table, &history, end) {
                if let Some(text) = command_string(&command) {
                    properties.push(Property::new(
                        3,
                        format!(
                            "_CONSOLE_INFORMATION.HistoryList.CommandHistory_{index}_Command_{command_index}"
                        ),
                        Some(command.offset()),
                        text,
                    ));
                }
            }
        }
    }

    properties.push(Property::new(
        1,
        "_CONSOLE_INFORMATION.CurrentScreenBuffer",
        field("CurrentScreenBuffer").map(|value| value.offset()),
        "",
    ));
    for (index, screen) in console_screens(console).into_iter().enumerate() {
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ScreenBuffer_{index}"),
            Some(screen.offset()),
            "",
        ));
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ScreenBuffer_{index}.ScreenX"),
            None,
            screen_width(&screen)
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ));
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ScreenBuffer_{index}.ScreenY"),
            None,
            screen_height(&screen)
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ));
        properties.push(Property::new(
            2,
            format!("_CONSOLE_INFORMATION.ScreenBuffer_{index}.Dump"),
            None,
            screen_buffer(&screen).join("\n"),
        ));
    }

    properties
}

/// The screen's width or height, which the console reports from its own
/// current buffer rather than keeping as a member.
fn console_screen_field(console: &Object, name: &str) -> (Option<u64>, String) {
    let Ok(screen) = console
        .member("CurrentScreenBuffer")
        .and_then(|pointer| pointer.dereference())
    else {
        return (None, String::new());
    };
    let value = if name == "ScreenX" {
        screen_width(&screen)
    } else {
        screen_height(&screen)
    };
    // The reported address is the member the console would have held, which it
    // does not, so upstream reports the screen's own field.
    (
        None,
        value.map(|value| value.to_string()).unwrap_or_default(),
    )
}

/// A screen buffer's width, taken from the length its first row records.
fn screen_width(screen: &Object) -> Option<i64> {
    let row = screen_row(screen, 0)?;
    row.member("RowLength2").and_then(|value| value.as_i64()).ok()
}

/// A screen buffer's height, which is how many rows it holds.
fn screen_height(screen: &Object) -> Option<i64> {
    screen
        .member("TextBufferInfo")
        .and_then(|info| info.member("BufferCapacity"))
        .and_then(|value| value.as_i64())
        .ok()
}

/// One row of a screen buffer.
///
/// 22000 changed from an array of pointers to `_ROW` to an array of `_ROW`, and
/// wrapped each in a structure of its own. A row's string is created based on
/// the length in the `_ROW` structure, so it shouldn't have any bad data.
fn screen_row(screen: &Object, index: u64) -> Option<Object> {
    let rows = screen
        .member("TextBufferInfo")
        .and_then(|info| info.member("BufferRows"))
        .and_then(|rows| rows.member("Rows"))
        .ok()?;
    let row = array_element(&rows, index)?;
    let row = match row.resolved_template().ok()?.as_ref() {
        crate::framework::objects::template::Template::Pointer { .. } => row.dereference().ok()?,
        _ => row,
    };
    if row.has_member("Row") {
        row.member("Row").ok()
    } else {
        Some(row)
    }
}

/// One element of an array, whatever length the array declares.
///
/// The number of rows a screen buffer holds is recorded beside the array rather
/// than in it, so the declared length is not the one to read.
fn array_element(array: &Object, index: u64) -> Option<Object> {
    let template = array.resolved_template().ok()?;
    let crate::framework::objects::template::Template::Array { subtype, .. } = template.as_ref()
    else {
        return None;
    };
    let context = array.context();
    let size = context.symbol_space.size_of(subtype).ok()?;
    Some(
        context
            .object_from_template(
                subtype.clone(),
                array.layer_name(),
                array.offset() + index * size,
            )
            .with_native_layer(array.native_layer_name()),
    )
}

/// Every screen buffer a console owns.
///
/// A console can hold several at once, chained through each buffer's `Next`.
fn console_screens(console: &Object) -> Vec<Object> {
    let mut starts = Vec::new();
    if let Ok(current) = console
        .member("CurrentScreenBuffer")
        .and_then(|pointer| pointer.dereference())
    {
        starts.push(current);
    }
    if let Ok(other) = console
        .member("GetScreenBuffer")
        .and_then(|pointer| pointer.dereference())
    {
        if !starts.iter().any(|screen| screen.offset() == other.offset()) {
            starts.push(other);
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for start in starts {
        let mut current = Some(start);
        while let Some(screen) = current {
            if screen.offset() == 0 || !seen.insert(screen.offset()) {
                break;
            }
            found.push(screen.clone());
            current = screen
                .member("Next")
                .and_then(|pointer| pointer.dereference())
                .ok();
        }
    }
    found
}

/// The text a screen buffer holds, one line per row.
///
/// The rows form a ring, so reading starts wherever the buffer says it does.
/// Empty rows at the end are dropped.
fn screen_buffer(screen: &Object) -> Vec<String> {
    let Some(capacity) = screen_height(screen).filter(|value| *value > 0) else {
        return Vec::new();
    };
    let start = screen
        .member("TextBufferInfo")
        .and_then(|info| info.member("BufferStart"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0);

    let mut rows = Vec::new();
    for offset in 0..capacity {
        let index = (start + offset).rem_euclid(capacity) as u64;
        let Some(row) = screen_row(screen, index) else {
            break;
        };
        match row_text(&row) {
            Some(text) => rows.push(text),
            None => break,
        }
    }

    // Walking back from the end, the last row with anything on it is where the
    // buffer stops being worth showing.
    let mut trailing = 0usize;
    let mut traversed = false;
    for (index, row) in rows.iter().rev().enumerate() {
        if !row.trim_end().is_empty() {
            trailing = index;
            break;
        }
        traversed = true;
    }
    if trailing == 0 && traversed {
        Vec::new()
    } else {
        rows[..rows.len() - trailing].to_vec()
    }
}

/// The text of one row.
///
/// Each cell holds a wide character and an attribute byte. A cell whose
/// attributes are not one of the recognised combinations is left out.
fn row_text(row: &Object) -> Option<String> {
    const VALID: [u8; 29] = [
        0x00, 0x01, 0x02, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70,
        0x78, 0x80, 0x88, 0xA8, 0xB8, 0xC0, 0xC8, 0x98, 0xD8, 0xE0, 0xE8, 0xF8, 0xF0, 0xA0,
    ];
    let chars = row
        .member("CharRow")
        .and_then(|char_row| char_row.member("Chars"))
        .ok()?;
    let length = row.member("RowLength").and_then(|value| value.as_u64()).ok()?;
    let data = row
        .context()
        .layers
        .read(row.layer_name(), chars.offset(), (length * 3) as usize, false)
        .ok()?;

    let mut text = String::new();
    for cell in data.chunks(3) {
        if cell.len() < 3 {
            break;
        }
        if cell[1] == 0 && VALID.contains(&cell[2]) {
            text.push_str(&decode_utf16(&cell[..2]));
        }
    }
    Some(text.trim_end().to_string())
}

/// The alias lists a console holds, one per executable.
fn exe_alias_lists(table: &str, console: &Object) -> Vec<Object> {
    let Ok(field) = console.member("ExeAliasList") else {
        return Vec::new();
    };
    // Windows 10 22000 and Server 20348 made this a Pointer rather than the
    // list itself.
    let head = match field.resolved_template().map(|template| {
        matches!(
            template.as_ref(),
            crate::framework::objects::template::Template::Pointer { .. }
        )
    }) {
        Ok(true) => match field.dereference() {
            Ok(head) => head,
            Err(_) => return Vec::new(),
        },
        _ => field,
    };
    walk_list(&head, &format!("{table}!_EXE_ALIAS_LIST"), "ListEntry", true).unwrap_or_default()
}

/// The executable an alias list belongs to.
fn exe_name(list: &Object) -> Option<String> {
    let name = list.member("ExeName").ok()?;
    // Windows 10 22000 and Server 20348 hold the name directly rather than
    // behind a pointer, and a direct one is a counted string.
    let is_pointer = matches!(
        name.resolved_template().ok()?.as_ref(),
        crate::framework::objects::template::Template::Pointer { .. }
    );
    if is_pointer {
        let target = name.dereference().ok()?;
        let length = target.member("Length").and_then(|value| value.as_u64()).ok()?;
        let chars = target.member("Chars").ok()?;
        let data = target
            .context()
            .layers
            .read(target.layer_name(), chars.offset(), (length * 2) as usize, false)
            .ok()?;
        return Some(cut_at_nul(&decode_utf16(&data)));
    }
    command_string(&name)
}

#[cfg(test)]
mod tests {
    use super::set_order;

    /// A set of small whole numbers is walked in the order of the slots they
    /// land in, which for a table of eight slots is the value's own low bits.
    #[test]
    fn a_set_is_walked_in_slot_order() {
        assert_eq!(set_order(&[50]), vec![50]);
        // 32 lands in slot 0 and 50 in slot 2, so 32 comes first however they
        // were added.
        assert_eq!(set_order(&[50, 32]), vec![32, 50]);
        // A repeat is one member.
        assert_eq!(set_order(&[4, 4]), vec![4]);
        // Two members of the same slot keep the order they were added in, the
        // second moving along to the next free slot.
        assert_eq!(set_order(&[1, 9]), vec![1, 9]);
    }

    #[test]
    fn an_empty_set_is_walked_in_no_order_at_all() {
        assert!(set_order(&[]).is_empty());
    }
}
