//! Scan for the window stations the interactive subsystem keeps.
//!
//! Every interactive session has at least one window station, and each station
//! owns the desktops that windows are drawn on. The structures belong to the
//! graphics subsystem rather than the kernel, and live in each session's own
//! address space.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{
    generate_pool_scan, PoolConstraint, NONPAGED, PAGED,
};
use crate::framework::symbols::windows::{header_name, object_header, versions};

pub struct WindowStations;

/// How many stations a chain may name before it has stopped being one.
const MAXIMUM_STATIONS: usize = 15;

impl Plugin for WindowStations {
    fn name(&self) -> &'static str {
        "windows.windowstations.WindowStations"
    }

    fn description(&self) -> &'static str {
        "Scans for top level Windows Stations"
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
            Column::string("Name"),
            Column::int("SessionId"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);

        let mut grid = TreeGrid::new(self.columns());
        for (station, name, session) in scan_window_stations(&context, &kernel, &physical)? {
            grid.push(
                0,
                vec![
                    Value::hex(station.offset()),
                    Value::string(name),
                    Value::int(session as i64),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Every window station, with the name and session each reports.
pub fn scan_window_stations(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> Result<Vec<(Object, String, u64)>> {
    let table = gui_table(context, kernel)?;
    let sessions = session_map(context, kernel, physical);

    let mut found = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for station in scan_stations(context, kernel, &table, &sessions)? {
        // Each station names the next, so one found by scanning leads to the
        // rest of its session's stations.
        for candidate in traverse(&station) {
            if seen.contains(&candidate.offset()) {
                continue;
            }
            seen.push(candidate.offset());

            // A station is reported only once both its name and its session
            // read as something believable.
            if let Some((name, session)) = station_info(&candidate, kernel) {
                found.push((candidate, name, session));
            }
        }
    }
    Ok(found)
}

/// The desktops a station owns, each with its name.
///
/// The list is read from the station each time round, so a station reports the
/// first of its desktops and then stops.
pub fn desktops(station: &Object, kernel: &Module) -> Vec<(Object, String)> {
    let mut found = Vec::new();
    let mut seen: Vec<u64> = Vec::new();

    while seen.len() < 12 {
        let Ok(desktop) = station
            .member("rpdeskList")
            .and_then(|desktop| desktop.dereference())
        else {
            break;
        };
        let Some(name) = object_header(&desktop, kernel)
            .ok()
            .and_then(|header| header_name(&header, kernel))
        else {
            break;
        };
        if seen.contains(&desktop.offset()) {
            break;
        }
        seen.push(desktop.offset());
        found.push((desktop, name));
    }
    found
}

/// Whether a carved station is one at all.
///
/// A station records the session it belongs to, and a machine never has
/// anything like that many sessions.
fn station_is_valid(station: &Object) -> bool {
    matches!(session_id(station), Some(session) if session < 256)
}

/// The name and session of a station, where both are believable.
///
/// A station whose session is out of range, or whose name is a single
/// character, is smear rather than a station.
pub fn station_info(station: &Object, kernel: &Module) -> Option<(String, u64)> {
    let session = session_id(station)?;
    let header = object_header(station, kernel).ok()?;
    let name = header_name(&header, kernel)?;
    if session < 256 && name.chars().count() > 1 {
        Some((name, session))
    } else {
        None
    }
}

/// The session a station belongs to.
pub fn session_id(station: &Object) -> Option<u64> {
    station
        .member("dwSessionId")
        .and_then(|session| session.as_u64())
        .ok()
}

/// Follow the chain of stations from one of them.
pub fn traverse(station: &Object) -> Vec<Object> {
    let mut found = vec![station.clone()];
    let mut seen: Vec<u64> = Vec::new();

    while seen.len() < MAXIMUM_STATIONS {
        let Ok(next) = station
            .member("rpwinstaNext")
            .and_then(|next| next.dereference())
        else {
            break;
        };
        if seen.contains(&next.offset()) {
            break;
        }
        found.push(next.clone());
        seen.push(next.offset());
    }
    found
}

/// Scan for the stations, building each in the address space of the session it
/// belongs to.
pub fn scan_stations(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
    sessions: &HashMap<u64, String>,
) -> Result<Vec<Object>> {
    // The object is one the kernel's own type table names, but the tag is
    // trusted rather than that table, since the graphics subsystem's objects
    // are not always accounted for there.
    let constraints = vec![PoolConstraint::new(b"Wind", "tagWINDOWSTATION", PAGED | NONPAGED)
        .in_table(table)
        .of_type("WindowStation")
        .trusting_the_tag()
        .validated_by(station_is_valid)
        .with_size(0x90, None)];
    scan_gui_objects(context, kernel, sessions, &constraints)
}

/// Scan for objects the graphics subsystem allocates, and rebuild each where
/// its session can read it.
pub fn scan_gui_objects(
    context: &Arc<Context>,
    kernel: &Module,
    sessions: &HashMap<u64, String>,
    constraints: &[PoolConstraint],
) -> Result<Vec<Object>> {
    let mut found = Vec::new();
    for hit in generate_pool_scan(context, kernel, constraints)? {
        let object = hit.object;
        let type_name = hit.constraint.qualified_type(kernel);
        // Which session an object belongs to decides which address space its
        // pointers mean anything in.
        let Some(session) = session_of(&object) else {
            continue;
        };
        let Some(layer) = sessions.get(&session) else {
            continue;
        };
        let Ok(rebuilt) = context.object(&type_name, layer, object.offset()) else {
            continue;
        };
        found.push(rebuilt);
    }
    Ok(found)
}

/// The session an object records for itself, directly or through the station
/// that owns it.
fn session_of(object: &Object) -> Option<u64> {
    if object.has_member("dwSessionId") {
        return object
            .member("dwSessionId")
            .and_then(|session| session.as_u64())
            .ok();
    }
    object
        .member("rpwinstaParent")
        .and_then(|station| station.dereference())
        .ok()
        .and_then(|station| session_id(&station))
}

/// One layer per session, by session identifier.
pub fn session_map(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> HashMap<u64, String> {
    crate::framework::plugins::windows::modules::session_layers(context, kernel, physical)
        .into_iter()
        .collect()
}

/// Load the description of the graphics subsystem's structures for this
/// release.
pub fn gui_table(context: &Arc<Context>, kernel: &Module) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    if !sixty_four_bit {
        return Err(VolatilityError::Other(
            "This plugin only supports x64 versions of Windows".to_string(),
        ));
    }

    // Newest first: the first release whose marks are all present is the one.
    let candidates: &[(&[versions::Check], &str)] = &[
        (versions::IS_WIN10_19577_OR_LATER, "gui-win10-19577-x64"),
        (versions::IS_WIN10_19041_OR_LATER, "gui-win10-19041-x64"),
        (versions::IS_WIN10_18362_OR_LATER, "gui-win10-18362-x64"),
        (versions::IS_WIN10_17763_OR_LATER, "gui-win10-17763-x64"),
        (versions::IS_WIN10_17134_OR_LATER, "gui-win10-17134-x64"),
        (versions::IS_WIN10_16299_OR_LATER, "gui-win10-16299-x64"),
        (versions::IS_WIN10_15063_OR_LATER, "gui-win10-15063-x64"),
        (versions::IS_WIN10_10586_OR_LATER, "gui-win10-10586-x64"),
        (versions::IS_WINDOWS_8_OR_LATER, "gui-win8-x64"),
        (versions::IS_WINDOWS_7_SP1, "gui-win7sp1-x64"),
        (versions::IS_WINDOWS_7_SP0, "gui-win7sp0-x64"),
    ];

    let table = candidates
        .iter()
        .find(|(checks, _)| versions::matches(context, kernel, checks))
        .map(|(_, name)| *name)
        .ok_or_else(|| {
            VolatilityError::Other("This version of Windows is not supported".to_string())
        })?;

    context.ensure_table(table, "windows/gui", table)?;
    context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;
    Ok(table.to_string())
}

/// List the desktops of each window station, and the processes with threads on
/// them.
pub struct Desktops;

impl Plugin for Desktops {
    fn name(&self) -> &'static str {
        "windows.desktops.Desktops"
    }

    fn description(&self) -> &'static str {
        "Enumerates the Desktop instances of each Window Station"
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
            Column::string("Window Station"),
            Column::int("Session"),
            Column::string("Desktop"),
            Column::string("Process"),
            Column::int("PID"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let table = gui_table(&context, &kernel)?;
        let mut grid = TreeGrid::new(self.columns());

        for (station, station_name, session) in
            scan_window_stations(&context, &kernel, &physical)?
        {
            for (desktop, desktop_name) in desktops(&station, &kernel) {
                // A desktop's threads say which processes are drawing on it.
                for (process_name, pid) in desktop_threads(&table, &desktop, &kernel) {
                    grid.push(
                        0,
                        vec![
                            Value::hex(desktop.offset()),
                            Value::string(station_name.clone()),
                            Value::int(session as i64),
                            Value::string(desktop_name.clone()),
                            Value::string(process_name),
                            Value::int(pid as i64),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// The processes owning threads attached to a desktop.
fn desktop_threads(
    table: &str,
    desktop: &Object,
    kernel: &Module,
) -> Vec<(String, u64)> {
    let thread_type = crate::framework::symbols::join_name(table, "tagTHREADINFO");

    let Ok(head) = desktop.member("PtiList") else {
        return Vec::new();
    };
    let threads = crate::framework::objects::utility::walk_list(&head, &thread_type, "PtiLink", true)
        .unwrap_or_default();

    let mut found = Vec::new();
    for thread in threads {
        let Ok(process) = thread
            .member("ppi")
            .and_then(|info| info.dereference())
            .and_then(|info| info.member("Process"))
            .and_then(|process| process.dereference_as(&kernel.qualified("_EPROCESS")))
        else {
            continue;
        };
        let process = crate::framework::symbols::windows::Process::new(process);
        let (Ok(name), Ok(pid)) = (process.image_file_name(), process.pid()) else {
            continue;
        };
        found.push((name, pid));
    }
    found
}

/// Scan for the desktops themselves, rather than reaching them through the
/// stations that own them.
///
/// A desktop the station list no longer reaches is still an allocation in the
/// pools, so scanning finds desktops a walk cannot.
pub struct DeskScan;

impl Plugin for DeskScan {
    fn name(&self) -> &'static str {
        "windows.deskscan.DeskScan"
    }

    fn description(&self) -> &'static str {
        "Scans for the Desktop instances of each Window Station"
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
            Column::string("Window Station"),
            Column::int("Session"),
            Column::string("Desktop"),
            Column::string("Process"),
            Column::int("PID"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let table = gui_table(&context, &kernel)?;
        let sessions = session_map(&context, &kernel, &physical);

        // The tag is trusted rather than the kernel's type table, as it is for
        // the stations, and a desktop has no size worth bounding.
        let constraints = vec![PoolConstraint::new(b"Desk", "tagDESKTOP", PAGED | NONPAGED)
            .in_table(&table)
            .of_type("Desktop")
            .trusting_the_tag()];

        let mut grid = TreeGrid::new(self.columns());
        for desktop in scan_gui_objects(&context, &kernel, &sessions, &constraints)? {
            let Some(desktop_name) = object_header(&desktop, &kernel)
                .ok()
                .and_then(|header| header_name(&header, &kernel))
            else {
                continue;
            };
            let Ok(station) = desktop
                .member("rpwinstaParent")
                .and_then(|station| station.dereference())
            else {
                continue;
            };
            let Some((station_name, session)) = station_info(&station, &kernel) else {
                continue;
            };

            for (process_name, pid) in desktop_threads(&table, &desktop, &kernel) {
                grid.push(
                    0,
                    vec![
                        Value::hex(desktop.offset()),
                        Value::string(station_name.clone()),
                        Value::int(session as i64),
                        Value::string(desktop_name.clone()),
                        Value::string(process_name),
                        Value::int(pid as i64),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// List the windows of each desktop.
pub struct Windows;

impl Plugin for Windows {
    fn name(&self) -> &'static str {
        "windows.windows.Windows"
    }

    fn description(&self) -> &'static str {
        "Enumerates the Windows of Desktop instances"
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
            Column::string("Station"),
            Column::int("Session"),
            Column::string("Desktop"),
            Column::string("Window"),
            Column::new("Procedure", ColumnType::UInt),
            Column::string("Process"),
            Column::int("PID"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        for (station, station_name, _) in scan_window_stations(&context, &kernel, &physical)? {
            for (desktop, desktop_name) in desktops(&station, &kernel) {
                // The desktop's own window is the root of everything drawn on
                // it. A desktop that cannot name it has nothing to walk.
                let Ok(top) = desktop
                    .member("pDeskInfo")
                    .and_then(|info| info.dereference())
                    .and_then(|info| info.member("spwnd"))
                    .and_then(|window| window.dereference())
                else {
                    continue;
                };

                for window in walk_windows(&top) {
                    let Some((process_name, pid)) = window_process(&window, &kernel) else {
                        continue;
                    };
                    let Some(session) = window_session(&window) else {
                        continue;
                    };
                    let procedure = window
                        .member("lpfnWndProc")
                        .and_then(|procedure| procedure.as_u64())
                        .ok();
                    // A procedure is either absent or a real address.
                    let procedure = match procedure {
                        None => Value::not_available(),
                        Some(address) if address == 0 || address > 0x1000 => Value::hex(address),
                        Some(_) => continue,
                    };

                    grid.push(
                        0,
                        vec![
                            Value::hex(window.offset()),
                            Value::string(station_name.clone()),
                            Value::int(session as i64),
                            Value::string(desktop_name.clone()),
                            window_name(&window)
                                .map(Value::string)
                                .unwrap_or_else(Value::not_available),
                            procedure,
                            Value::string(process_name),
                            Value::int(pid as i64),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// Walk a window and those beside and below it.
fn walk_windows(window: &Object) -> Vec<Object> {
    /// How many windows a chain may name before it has stopped being one.
    const MAXIMUM: usize = 5000;

    let mut found = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut pending = vec![window.clone()];

    while let Some(current) = pending.pop() {
        if current.offset() == 0 || seen.contains(&current.offset()) || seen.len() >= MAXIMUM {
            continue;
        }
        seen.push(current.offset());
        found.push(current.clone());

        for member in ["spwndNext", "spwndChild"] {
            if let Ok(next) = current.member(member).and_then(|next| next.dereference()) {
                if next.offset() != 0 {
                    pending.push(next);
                }
            }
        }
    }
    found
}

/// The process a window belongs to.
fn window_process(window: &Object, kernel: &Module) -> Option<(String, u64)> {
    let process = window
        .member("head")
        .and_then(|head| head.member("pti"))
        .and_then(|thread| thread.dereference())
        .and_then(|thread| thread.member("ppi"))
        .and_then(|info| info.dereference())
        .and_then(|info| info.member("Process"))
        .and_then(|process| process.dereference_as(&kernel.qualified("_EPROCESS")))
        .ok()?;
    let process = crate::framework::symbols::windows::Process::new(process);
    Some((process.image_file_name().ok()?, process.pid().ok()?))
}

/// The session a window belongs to, through the desktop it is drawn on.
fn window_session(window: &Object) -> Option<u64> {
    window
        .member("head")
        .and_then(|head| head.member("rpdesk"))
        .and_then(|desktop| desktop.dereference())
        .and_then(|desktop| desktop.member("dwSessionId"))
        .and_then(|session| session.as_u64())
        .ok()
}

/// The text a window carries, where it carries any.
fn window_name(window: &Object) -> Option<String> {
    if window.has_member("directName") {
        if let Ok(address) = window
            .member("directName")
            .and_then(|name| name.pointer_value())
        {
            if address != 0 {
                let data = window
                    .context()
                    .layers
                    .read(window.layer_name(), address, 512, false)
                    .ok()?;
                return Some(decode_wide(&data));
            }
        }
    }
    window
        .member("strName")
        .ok()
        .and_then(|name| crate::framework::objects::utility::unicode_string(&name).ok())
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
