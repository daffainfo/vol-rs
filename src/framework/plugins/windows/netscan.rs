//! The network stack allocates its endpoint structures from the pools, so
//! searching for their tags finds connections that have already been torn down
//! as well as live ones.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{
    generate_pool_scan, PoolConstraint, FREE, NONPAGED,
};
use crate::framework::symbols::windows::Process;

/// Scans for network objects present in a particular windows memory image.
pub struct NetScan;

/// Address families, as the network stack records them.
///
/// Python's `socket.AF_INET6` is 0x1e but Microsoft defines it as a constant
/// value of 0x17 in their source code. Thus we need Microsoft's, since that's
/// what is found in memory.
const AF_INET: u64 = 2;
const AF_INET6: u64 = 0x17;

/// The years outside which a recorded time is not believable, so a timestamp
/// outside them is reported as absent.
const EARLIEST_YEAR: i32 = 1950;
const LATEST_YEAR: i32 = 2200;

impl Plugin for NetScan {
    fn name(&self) -> &'static str {
        "windows.netscan.NetScan"
    }

    fn description(&self) -> &'static str {
        "Scans for network objects present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "include-corrupt",
                "Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!",
                RequirementKind::Bool,
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Proto"),
            Column::string("LocalAddr"),
            Column::int("LocalPort"),
            Column::string("ForeignAddr"),
            Column::int("ForeignPort"),
            Column::string("State"),
            Column::int("PID"),
            Column::string("Owner"),
            Column::datetime("Created"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        let grid = self.run(context, config).ok()?;
        // An image these structures are not described for contributes nothing,
        // and the failure is what upstream reports rather than an empty list.
        if grid.aborted() {
            return None;
        }
        for row in grid.rows() {
            let values = &row.values;
            // Skip network connections without creation time
            if !is_time(&values[9]) {
                continue;
            }
            // A value that could not be read is named rather than left blank.
            let field = |index: usize| -> String {
                if values[index].is_absent() {
                    "N/A".to_string()
                } else {
                    number(&values[index])
                }
            };
            let description = format!(
                "Network connection: Process {} {} Local Address {}:{} Remote Address {}:{} \
                 State {} Protocol {} ",
                field(7),
                field(8),
                field(2),
                field(3),
                field(4),
                field(5),
                field(6),
                field(1)
            );
            timeline.push(description, TimeKind::Created, values[9].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let corrupt = config.get_bool("include-corrupt").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());
        // The network structures belong to the network driver, not the kernel,
        // and are described by a file chosen for this build of Windows. An
        // image no file covers leaves the header written and the run aborted.
        let table = match netscan_table(&context, &kernel) {
            Ok(table) => table,
            Err(error) => {
                eprintln!("NotImplementedError: {error}");
                grid.mark_aborted();
                return Ok(grid);
            }
        };
        for object in scan(&context, &kernel, &table)? {
            for row in rows_for(&context, &kernel, &object, corrupt) {
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The rows one network object produces, which is more than one for a socket
/// that is bound to both address families.
///
/// An object that does not hold together is reported only when the caller asks
/// for what could not be read as well.
pub fn rows_for(
    context: &Arc<Context>,
    kernel: &Module,
    object: &Object,
    corrupt: bool,
) -> Vec<Vec<Value>> {
    let mut rows = Vec::new();
    {
        let object = object;
        let kind = object
            .type_name()
            .rsplit('!')
            .next()
            .unwrap_or_default()
            .to_string();
        let mut grid = RowSink(&mut rows);

        match kind.as_str() {
                "_UDP_ENDPOINT" => {
                    // Objects passed pool header constraints. Check for
                    // additional constraints if the strict flag is set.
                    if !corrupt && !listener_is_valid(object) {
                        return rows;
                    }
                    // For UdpA, the state is always blank and the remote end
                    // is asterisks.
                    for (version, local, _) in dual_stack(object) {
                        grid.push(
                            row(
                                context,
                                kernel,
                                object,
                                format!("UDP{version}"),
                                local,
                                port(object, "Port"),
                                "*".to_string(),
                                0,
                                Value::string(""),
                            ),
                        );
                    }
                }
                "_TCP_ENDPOINT" => {
                    if !corrupt && !endpoint_is_valid(context, kernel, object) {
                        return rows;
                    }
                    let protocol = match address_family(object) {
                        Some(AF_INET) => "TCPv4",
                        Some(AF_INET6) => "TCPv6",
                        _ => "TCPv?",
                    };
                    let state = object
                        .member("State")
                        .and_then(|state| state.enum_name())
                        .map(Value::string)
                        .unwrap_or_else(|_| Value::unreadable());

                    grid.push(row(
                        context,
                        kernel,
                        object,
                        protocol.to_string(),
                        local_address(object).unwrap_or_default(),
                        port(object, "LocalPort"),
                        remote_address(object).unwrap_or_default(),
                        port(object, "RemotePort"),
                        state,
                    ));
                }
                "_TCP_LISTENER" => {
                    if !corrupt && !listener_is_valid(object) {
                        return rows;
                    }
                    // For TcpL, the state is always listening and the remote
                    // port is zero. This kind is checked for last, because
                    // every other object is inherited from it.
                    for (version, local, remote) in dual_stack(object) {
                        grid.push(
                            row(
                                context,
                                kernel,
                                object,
                                format!("TCP{version}"),
                                local,
                                port(object, "Port"),
                                remote,
                                0,
                                Value::string("LISTENING"),
                            ),
                        );
                    }
                }
            _ => {}
        }
    }
    rows
}

/// Somewhere to put rows as they are built.
struct RowSink<'a>(&'a mut Vec<Vec<Value>>);

impl RowSink<'_> {
    fn push(&mut self, row: Vec<Value>) {
        self.0.push(row);
    }
}

/// Build one row from an endpoint and the parts that differ between kinds.
fn row(
    context: &Arc<Context>,
    kernel: &Module,
    object: &Object,
    protocol: String,
    local: String,
    local_port: u64,
    remote: String,
    remote_port: u64,
    state: Value,
) -> Vec<Value> {
    let owner = owner(context, kernel, object);
    vec![
        Value::hex(object.offset()),
        Value::string(protocol),
        if local.is_empty() {
            Value::unreadable()
        } else {
            Value::string(local)
        },
        Value::int(local_port as i64),
        if remote.is_empty() {
            Value::unreadable()
        } else {
            Value::string(remote)
        },
        Value::int(remote_port as i64),
        state,
        owner
            .as_ref()
            .and_then(|owner| owner.pid().ok())
            .map(|pid| Value::int(pid as i64))
            .unwrap_or_else(Value::unreadable),
        owner
            .as_ref()
            .and_then(|owner| owner.image_file_name().ok())
            .map(Value::string)
            .unwrap_or_else(Value::unreadable),
        create_time(object),
    ]
}

/// A port, which the stack stores in network order.
fn port(object: &Object, member: &str) -> u64 {
    object
        .member(member)
        .and_then(|port| port.as_u64())
        .unwrap_or(0)
}

/// The process that opened a socket, where it can still be read.
fn owner(context: &Arc<Context>, kernel: &Module, object: &Object) -> Option<Process> {
    let owner = object.member("Owner").ok()?.dereference().ok()?;
    let process = Process::new(owner);
    // A process that no longer looks like one says nothing about the socket.
    if !crate::framework::symbols::windows::process_is_valid(context, kernel, &process.object) {
        return None;
    }
    Some(process)
}

/// When a socket was opened, where the recorded moment is believable.
fn create_time(object: &Object) -> Value {
    let Ok(raw) = object
        .member("CreateTime")
        .and_then(|time| time.member("QuadPart"))
        .and_then(|time| time.as_u64())
    else {
        return Value::unreadable();
    };
    match wintime_value(raw) {
        Value::DateTime(time) => {
            use chrono::Datelike;
            if (EARLIEST_YEAR..=LATEST_YEAR).contains(&time.year()) {
                Value::DateTime(time)
            } else {
                Value::unreadable()
            }
        }
        other => other,
    }
}

/// The address family a socket belongs to.
fn address_family(object: &Object) -> Option<u64> {
    object
        .member("InetAF")
        .and_then(|family| family.dereference())
        .and_then(|family| family.member("AddressFamily"))
        .and_then(|family| family.as_u64())
        .ok()
}

/// The address a listening socket is bound to, if it is bound to one at all.
fn bound_address(object: &Object) -> Option<Object> {
    let local = object.member("LocalAddr").ok()?.dereference().ok()?;
    let data = local.member("pData").ok()?;
    // The later structure points straight at the address. The earlier one
    // points at a pointer to it.
    let address = if local.type_name().ends_with("_LOCAL_ADDRESS_WIN10_UDP") {
        data.dereference().ok()?
    } else {
        data.dereference().ok()?.dereference().ok()?
    };
    // There is a rare edge case here we have to consider: if the struct has a
    // null pointer at the LocalAddr offset, this generally means this struct
    // has no associated local address. However, sometimes a pointer to the
    // offset of 0 can be valid because it points to a valid virtual memory
    // address of 0. That confuses the plugin, because trying to access the null
    // pointer does not raise any errors, leading to errors later down the line
    // when accessing the address itself.
    address.member("addr4").ok()?.index(0).ok()?.as_u64().ok()?;
    Some(address)
}

/// The addresses a socket reports, which for a dual-stack socket is one per
/// family.
fn dual_stack(object: &Object) -> Vec<(&'static str, String, String)> {
    let family = address_family(object);
    match bound_address(object) {
        Some(address) => match family {
            Some(AF_INET) => vec![("v4", ipv4(&address), "0.0.0.0".to_string())],
            Some(AF_INET6) => vec![("v6", ipv6(&address), "::".to_string())],
            _ => Vec::new(),
        },
        None => {
            let mut found = vec![("v4", "0.0.0.0".to_string(), "0.0.0.0".to_string())];
            if family == Some(AF_INET6) {
                found.push(("v6", "::".to_string(), "::".to_string()));
            }
            found
        }
    }
}

/// The address at both ends of a connection.
fn local_address(object: &Object) -> Option<String> {
    let address = object
        .member("AddrInfo")
        .and_then(|info| info.dereference())
        .and_then(|info| info.member("Local"))
        .and_then(|local| local.dereference())
        .and_then(|local| local.member("pData"))
        .and_then(|data| data.dereference())
        .and_then(|data| data.dereference())
        .ok()?;
    Some(family_address(object, &address))
}

fn remote_address(object: &Object) -> Option<String> {
    let address = object
        .member("AddrInfo")
        .and_then(|info| info.dereference())
        .and_then(|info| info.member("Remote"))
        .and_then(|remote| remote.dereference())
        .ok()?;
    Some(family_address(object, &address))
}

/// Render an address in the form its family calls for.
fn family_address(object: &Object, address: &Object) -> String {
    match address_family(object) {
        Some(AF_INET) => ipv4(address),
        _ => ipv6(address),
    }
}

/// The four bytes of a version four address.
fn ipv4(address: &Object) -> String {
    let bytes = address_bytes(address, "addr4", 4);
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// The sixteen bytes of a version six address, written the way the C library
/// writes one.
fn ipv6(address: &Object) -> String {
    let bytes = address_bytes(address, "addr6", 16);
    let groups: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| ((pair[0] as u16) << 8) | pair[1] as u16)
        .collect();
    std::net::Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    )
    .to_string()
}

/// Read an address's bytes, treating anything unreadable as zero.
fn address_bytes(address: &Object, member: &str, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    if let Ok(array) = address.member(member) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = array
                .index(index as u64)
                .and_then(|value| value.as_u64())
                .unwrap_or(0) as u8;
        }
    }
    bytes
}

/// Whether a socket is coherent enough to report.
fn listener_is_valid(object: &Object) -> bool {
    matches!(address_family(object), Some(AF_INET) | Some(AF_INET6))
}

/// Whether a connection is coherent enough to report.
fn endpoint_is_valid(context: &Arc<Context>, kernel: &Module, object: &Object) -> bool {
    let Ok(state) = object.member("State") else {
        return false;
    };
    // A state the stack does not define means this was never a connection.
    if state.enum_name().is_err() || !state_is_known(&state) {
        return false;
    }
    if !matches!(address_family(object), Some(AF_INET) | Some(AF_INET6)) {
        return false;
    }
    // Without a local address the owner has to be believable instead.
    if local_address(object).is_none() {
        let pid = owner(context, kernel, object)
            .and_then(|owner| owner.pid().ok())
            .unwrap_or(0);
        if pid == 0 || pid > 65535 {
            return false;
        }
    }
    true
}

/// Whether a state field holds one of the values the stack defines.
fn state_is_known(state: &Object) -> bool {
    let Ok(value) = state.as_i64() else {
        return false;
    };
    state
        .resolved_template()
        .ok()
        .and_then(|template| template.as_enum().map(|kind| kind.is_valid_choice(value)))
        .unwrap_or(false)
}

/// Scans for network objects using the poolscanner module and constraints.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
///
/// Scans for network objects using the poolscanner module and constraints.
///
/// Creates a list of Pool Tag Constraints for network objects.
fn scan(context: &Arc<Context>, kernel: &Module, table: &str) -> Result<Vec<Object>> {
    let size_of = |name: &str| {
        context
            .symbol_space
            .get_type(&format!("{table}!{name}"))
            .and_then(|template| context.symbol_space.size_of(&template))
            .unwrap_or(0)
    };

    let mut constraints = vec![
        // TCP listener
        PoolConstraint::new(b"TcpL", "_TCP_LISTENER", NONPAGED | FREE)
            .in_table(table)
            .with_size(size_of("_TCP_LISTENER"), None),
        // TCP Endpoint
        PoolConstraint::new(b"TcpE", "_TCP_ENDPOINT", NONPAGED | FREE)
            .in_table(table)
            .with_size(size_of("_TCP_ENDPOINT"), None),
        // UDP Endpoint
        PoolConstraint::new(b"UdpA", "_UDP_ENDPOINT", NONPAGED | FREE)
            .in_table(table)
            .with_size(size_of("_UDP_ENDPOINT"), None),
    ];
    // One build of Windows tags its connections differently.
    if table.starts_with("netscan-win10-20348") {
        constraints.push(
            PoolConstraint::new(b"TTcb", "_TCP_ENDPOINT", NONPAGED | FREE)
                .in_table(table)
                .with_size(size_of("_TCP_ENDPOINT"), None),
        );
    }

    Ok(generate_pool_scan(context, kernel, &constraints)?
        .into_iter()
        .map(|hit| hit.object)
        .collect())
}

/// Creates a symbol table for TCP Listeners and TCP/UDP Endpoints.
///
/// Tries to determine which symbol filename to use for the image's tcpip
/// driver. The logic is partially taken from the info plugin.
///
/// While the failsafe way to determine the version of tcpip.sys would be to
/// extract the driver and parse its PE header containing the versionstring,
/// unfortunately that header is not guaranteed to persist within memory.
/// Therefore we determine the version based on the kernel version as testing
/// with several windows versions has showed this to work out correctly.
pub fn netscan_table(context: &Arc<Context>, kernel: &Module) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    let version = context.object_from_symbol(kernel, "KdVersionBlock", Some("_DBGKD_GET_VERSION64"))?;
    let minor = version.member("MinorVersion")?.as_u64()?;

    // The shared page sits at a fixed address on every build.
    let kuser_address: u64 = if sixty_four_bit {
        0xFFFF_F780_0000_0000
    } else {
        0xFFDF_0000
    };
    let kuser = context.object(
        &kernel.qualified("_KUSER_SHARED_DATA"),
        &kernel.layer_name,
        kuser_address & context.layers.address_mask(&kernel.layer_name),
    )?;
    let major_nt = kuser.member("NtMajorVersion")?.as_u64()?;
    let minor_nt = kuser.member("NtMinorVersion")?.as_u64()?;

    let table = choose_table(sixty_four_bit, major_nt, minor_nt, minor).ok_or_else(|| {
        VolatilityError::Other(format!(
            "This version of Windows is not supported: {major_nt}.{minor_nt} {minor}"
        ))
    })?;
    context.ensure_table(table, "windows/netscan", table)?;
    context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;
    Ok(table.to_string())
}

/// The file describing the network structures of one build of Windows.
///
/// These versions are listed explicitly because symbol files differ based on
/// version *and* architecture. This is currently the clearest way to show the
/// differences, even if it introduces a fair bit of redundancy. Furthermore,
/// it is easy to append new versions.
///
/// No match on a name means that we possibly have a version newer than those
/// listed here, so the latest supported version of the current image's NT
/// version is taken. If that does not work, support has to be added manually.
fn choose_table(
    sixty_four_bit: bool,
    major: u64,
    minor: u64,
    build: u64,
) -> Option<&'static str> {
    let versions: &[(u64, u64, u64, &str)] = if sixty_four_bit {
        &[
            (6, 0, 6000, "netscan-vista-x64"),
            (6, 0, 6001, "netscan-vista-sp12-x64"),
            (6, 0, 6002, "netscan-vista-sp12-x64"),
            (6, 0, 6003, "netscan-vista-sp12-x64"),
            (6, 1, 7600, "netscan-win7-x64"),
            (6, 1, 7601, "netscan-win7-x64"),
            (6, 1, 8400, "netscan-win7-x64"),
            (6, 2, 9200, "netscan-win8-x64"),
            (6, 3, 9600, "netscan-win81-x64"),
            (10, 0, 10240, "netscan-win10-x64"),
            (10, 0, 10586, "netscan-win10-x64"),
            (10, 0, 14393, "netscan-win10-x64"),
            (10, 0, 15063, "netscan-win10-15063-x64"),
            (10, 0, 16299, "netscan-win10-16299-x64"),
            (10, 0, 17134, "netscan-win10-17134-x64"),
            (10, 0, 17763, "netscan-win10-17763-x64"),
            (10, 0, 18362, "netscan-win10-18362-x64"),
            (10, 0, 18363, "netscan-win10-18363-x64"),
            (10, 0, 19041, "netscan-win10-19041-x64"),
            (10, 0, 20348, "netscan-win10-20348-x64"),
        ]
    } else {
        &[
            (6, 0, 6000, "netscan-vista-x86"),
            (6, 0, 6001, "netscan-vista-x86"),
            (6, 0, 6002, "netscan-vista-x86"),
            (6, 0, 6003, "netscan-vista-x86"),
            (6, 1, 7600, "netscan-win7-x86"),
            (6, 1, 7601, "netscan-win7-x86"),
            (6, 1, 8400, "netscan-win7-x86"),
            (6, 2, 9200, "netscan-win8-x86"),
            (6, 3, 9600, "netscan-win81-x86"),
            (10, 0, 10240, "netscan-win10-10240-x86"),
            (10, 0, 10586, "netscan-win10-10586-x86"),
            (10, 0, 14393, "netscan-win10-14393-x86"),
            (10, 0, 15063, "netscan-win10-15063-x86"),
            (10, 0, 16299, "netscan-win10-15063-x86"),
            (10, 0, 17134, "netscan-win10-17134-x86"),
            (10, 0, 17763, "netscan-win10-17134-x86"),
            (10, 0, 18362, "netscan-win10-17134-x86"),
            (10, 0, 18363, "netscan-win10-17134-x86"),
        ]
    };

    if let Some((_, _, _, table)) = versions
        .iter()
        .find(|(a, b, c, _)| (*a, *b, *c) == (major, minor, build))
    {
        return Some(table);
    }
    // Nothing matched exactly, so the newest description for this release of
    // Windows stands in.
    versions
        .iter()
        .filter(|(a, b, _, _)| (*a, *b) == (major, minor))
        .next_back()
        .map(|(_, _, _, table)| *table)
}
