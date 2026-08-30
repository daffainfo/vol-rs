//! List the network connections open on the system.
//!
//! Sockets are reached through each process's file descriptors, so a connection
//! is reported alongside the process that owns it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::Object;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::{convert_ipv4, convert_ipv6};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::{descriptor_kind, list_processes};

pub struct NetStat;

/// Address families, as the socket layer records them.
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 30;

/// TCP connection states, indexed by the control block's state field.
const TCP_STATES: &[&str] = &[
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "FIN_WAIT1",
    "CLOSING",
    "LAST_ACK",
    "FIN_WAIT2",
    "TIME_WAIT",
];

impl Plugin for NetStat {
    fn name(&self) -> &'static str {
        "mac.netstat.Netstat"
    }

    fn description(&self) -> &'static str {
        "Lists all network connections for all processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Proto"),
            Column::string("Local IP"),
            Column::int("Local Port"),
            Column::string("Remote IP"),
            Column::int("Remote Port"),
            Column::string("State"),
            Column::string("Process"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.name().unwrap_or_default();
            let owner = format!("{name}/{pid}");

            for socket in process_sockets(&context, &kernel, &process) {
                let Some(row) = describe(&socket, &kernel, &owner) else {
                    continue;
                };
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The sockets a process holds open.
fn process_sockets(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    process: &crate::framework::symbols::mac::Proc,
) -> Vec<Object> {
    let mut sockets = Vec::new();
    for (file, _, _) in process.file_descriptors() {
        let Ok(glob) = file.member("f_fglob").and_then(|glob| glob.dereference()) else {
            continue;
        };
        // Only a descriptor that refers to a socket has a connection.
        if descriptor_kind(&glob).as_deref() != Some("SOCKET") {
            continue;
        }

        let Ok(address) = glob.member("fg_data").and_then(|data| data.pointer_value()) else {
            continue;
        };
        let Ok(socket) = process
            .object
            .at_offset(address)
            .cast(&kernel.qualified("socket"))
        else {
            continue;
        };
        // A socket that is not wholly in memory says nothing reliable.
        if !socket.is_readable() {
            continue;
        }
        let _ = context;
        sockets.push(socket);
    }
    sockets
}

/// Build a row for one socket, or `None` if it has no address to report.
fn describe(
    socket: &Object,
    kernel: &crate::framework::context::Module,
    owner: &str,
) -> Option<Vec<Value>> {
    let family = socket
        .member("so_proto")
        .and_then(|proto| proto.dereference())
        .and_then(|proto| proto.member("pr_domain"))
        .and_then(|domain| domain.dereference())
        .and_then(|domain| domain.member("dom_family"))
        .and_then(|family| family.as_u64())
        .ok()?;

    // A local socket is named by the path it was bound to rather than by an
    // address and port.
    if family == AF_UNIX {
        let path = socket
            .member("so_pcb")
            .and_then(|pcb| pcb.pointer_value())
            .ok()
            .map(|address| socket.at_offset(address))
            .and_then(|pcb| pcb.cast(&kernel.qualified("unpcb")).ok())
            .and_then(|pcb| pcb.member("unp_addr").ok())
            .and_then(|address| address.dereference().ok())
            .and_then(|address| address.member("sun_path").ok())
            .and_then(|path| path.as_string().ok())?;

        return Some(vec![
            Value::hex(socket.offset()),
            Value::string("UNIX"),
            Value::string(path),
            Value::int(0),
            Value::string(""),
            Value::int(0),
            Value::string(""),
            Value::string(owner),
        ]);
    }

    if family != AF_INET && family != AF_INET6 {
        return None;
    }

    let protocol_number = socket
        .member("so_proto")
        .and_then(|proto| proto.dereference())
        .and_then(|proto| proto.member("pr_protocol"))
        .and_then(|protocol| protocol.as_u64())
        .unwrap_or(0);
    // 6 is TCP and 17 is UDP, as the IP protocol numbers define. Anything else
    // has no name to give.
    let protocol = match protocol_number {
        6 => "TCP",
        17 => "UDP",
        _ => "",
    };

    // The protocol control block holds the addresses and the ports.
    let pcb = socket
        .member("so_pcb")
        .and_then(|pcb| pcb.pointer_value())
        .ok()
        .map(|address| socket.at_offset(address))
        .and_then(|pcb| pcb.cast(&kernel.qualified("inpcb")).ok())?;

    // Only a connection-based protocol has a state to be in.
    let state = if protocol_number == 6 {
        pcb.member("inp_ppcb")
            .and_then(|ppcb| ppcb.pointer_value())
            .ok()
            .map(|address| socket.at_offset(address))
            .and_then(|tcpcb| tcpcb.cast(&kernel.qualified("tcpcb")).ok())
            .and_then(|tcpcb| tcpcb.member("t_state").ok())
            .and_then(|state| state.as_u64().ok())
            // A socket in the first state is one that has none, and the
            // reference implementation leaves it unnamed.
            .filter(|state| *state != 0)
            .and_then(|state| TCP_STATES.get(state as usize).copied())
            .unwrap_or("")
    } else {
        ""
    };

    let is_v6 = family == AF_INET6;
    let local = address_of(&pcb, "inp_dependladdr", is_v6)?;
    let remote = address_of(&pcb, "inp_dependfaddr", is_v6)?;
    let local_port = port_of(&pcb, "inp_lport");
    let remote_port = port_of(&pcb, "inp_fport");

    Some(vec![
        Value::hex(socket.offset()),
        Value::string(protocol),
        Value::string(local),
        Value::int(local_port),
        Value::string(remote),
        Value::int(remote_port),
        Value::string(state),
        Value::string(owner),
    ])
}

/// Read and format one of the control block's addresses.
///
/// The control block holds a union able to carry either kind of address, so
/// which member to read depends on the socket's family.
fn address_of(pcb: &Object, member: &str, is_v6: bool) -> Option<String> {
    let field = pcb.member(member).ok()?;
    let (local, foreign) = if member == "inp_dependladdr" {
        ("inp6_local", "inp46_local")
    } else {
        ("inp6_foreign", "inp46_foreign")
    };

    if is_v6 {
        let address = field
            .member(local)
            .and_then(|address| address.member("__u6_addr"))
            .and_then(|address| address.member("__u6_addr32"))
            .ok()?;
        let raw = pcb
            .context()
            .layers
            .read(pcb.layer_name(), address.offset(), 16, false)
            .ok()?;
        Some(convert_ipv6(&raw))
    } else {
        let address = field
            .member(foreign)
            .and_then(|address| address.member("ia46_addr4"))
            .and_then(|address| address.member("s_addr"))
            .ok()?;
        Some(convert_ipv4(address.as_u64().ok()? as u32))
    }
}

/// A port, which is held the way it travels on the wire.
fn port_of(pcb: &Object, member: &str) -> i64 {
    let port = pcb
        .member(member)
        .and_then(|port| port.as_u64())
        .unwrap_or(0);
    ((port >> 8) | ((port & 0xFF) << 8)) as i64
}
