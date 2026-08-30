//! List the sockets each task holds open.
//!
//! Sockets are reached through the file-descriptor table, so every connection
//! is reported alongside the process and thread that owns it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::template::Encoding;
use crate::framework::objects::{decode_string, Object};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_matches, pids_filter, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::{convert_ipv4, convert_ipv6};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{
    list_net_devices, list_net_namespaces, list_tasks_filtered, path_for_file,
    task_root_readable, Task,
};

pub struct Sockstat;

/// Socket family names, indexed by the kernel's AF_ constants.
const FAMILIES: &[&str] = &[
    "AF_UNSPEC", "AF_UNIX", "AF_INET", "AF_AX25", "AF_IPX", "AF_APPLETALK",
    "AF_NETROM", "AF_BRIDGE", "AF_ATMPVC", "AF_X25", "AF_INET6", "AF_ROSE",
    "AF_DECnet", "AF_NETBEUI", "AF_SECURITY", "AF_KEY", "AF_NETLINK",
    "AF_PACKET", "AF_ASH", "AF_ECONET", "AF_ATMSVC", "AF_RDS", "AF_SNA",
    "AF_IRDA", "AF_PPPOX", "AF_WANPIPE", "AF_LLC", "AF_IB", "AF_MPLS", "AF_CAN",
    "AF_TIPC", "AF_BLUETOOTH", "AF_IUCV", "AF_RXRPC", "AF_ISDN", "AF_PHONET",
    "AF_IEEE802154", "AF_CAIF", "AF_ALG", "AF_NFC", "AF_VSOCK", "AF_KCM",
    "AF_QIPCRTR", "AF_SMC", "AF_XDP", "AF_MCTP",
];

/// Generic socket states, as `socket.state` records them.
/// Connection states a Bluetooth socket reports, indexed by the kernel's own
/// numbering.
const BLUETOOTH_STATES: &[&str] = &[
    "",
    "CONNECTED",
    "OPEN",
    "BOUND",
    "LISTEN",
    "CONNECT",
    "CONNECT2",
    "CONFIG",
    "DISCONN",
    "CLOSED",
];

const SOCKET_STATES: &[&str] = &[
    "FREE", "UNCONNECTED", "CONNECTING", "CONNECTED", "DISCONNECTING",
];

/// Connection states, used by TCP and by stream unix sockets alike.
const TCP_STATES: &[&str] = &[
    "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
    "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING",
    "TCP_NEW_SYN_RECV",
];

/// The name of a socket type, by its `sk_type`.
fn socket_type_name(value: u64) -> &'static str {
    match value {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        6 => "DCCP",
        10 => "PACKET",
        _ => "",
    }
}

impl Plugin for Sockstat {
    fn name(&self) -> &'static str {
        "linux.sockstat.Sockstat"
    }

    fn description(&self) -> &'static str {
        "Lists all network connections for all processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pids_filter("Filter results by process IDs. It takes the root PID namespace identifiers."),
            Requirement::new(
                "netns",
                "Filter results by network namespace. Otherwise, all of them are shown.",
                crate::framework::plugins::RequirementKind::Int,
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("NetNS"),
            Column::string("Process Name"),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("FD"),
            Column::new("Sock Offset", ColumnType::UInt),
            Column::string("Family"),
            Column::string("Type"),
            Column::string("Proto"),
            Column::string("Source Addr"),
            Column::string("Source Port"),
            Column::string("Destination Addr"),
            Column::string("Destination Port"),
            Column::string("State"),
            Column::string("Filter"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pids_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // A descriptor is a socket when its file operations are the ones sockfs
        // installs. Nothing else about the file says so reliably.
        let mask = context.layers.address_mask(&kernel.layer_name);
        let socket_ops = context
            .symbol_offset(&kernel, "socket_file_ops")
            .ok()
            .map(|address| address & mask);
        let dentry_ops = context
            .symbol_offset(&kernel, "sockfs_dentry_operations")
            .ok()
            .map(|address| address & mask);

        // The filter selects processes. A selected process brings its threads
        // with it, whatever their own ids.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        // Only sockets belonging to one network namespace, where one was named.
        let wanted_namespace = config.get_int("netns").map(|value| value as u64);

        'tasks: for task in list_tasks_filtered(&context, &kernel, true, &selected)? {
            let Ok(pid) = task.pid() else { continue };
            let comm = task.comm().unwrap_or_default();
            let namespace = task
                .object
                .member("nsproxy")
                .and_then(|proxy| proxy.dereference())
                .and_then(|proxy| proxy.member("net_ns"))
                .and_then(|net| net.dereference())
                .and_then(|net| net.member("ns"))
                .and_then(|ns| ns.member("inum"))
                .and_then(|inum| inum.as_u64())
                .ok();

            for open in task.open_files().unwrap_or_default() {
                // The descriptor listing this shares with lsof resolves each
                // path, and stops when a task's root cannot be read.
                if path_for_file(&task, &open.file).is_none() && !task_root_readable(&task) {
                    grid.mark_truncated_reported();
                    break 'tasks;
                }

                let operations = open
                    .file
                    .member("f_op")
                    .and_then(|ops| ops.pointer_value())
                    .unwrap_or(0);
                if !whole_struct_readable(&context, &kernel, &open.file, "file_operations", operations)
                    || (Some(operations) != socket_ops && Some(operations) != dentry_ops)
                {
                    continue;
                }

                // The chain from the descriptor to the socket is followed one
                // structure at a time, each checked in full: a dentry or inode
                // straddling a page that is no longer resident is skipped, not
                // read half-way and reported.
                let dentry_address = open
                    .file
                    .member("f_path")
                    .and_then(|path| path.member("dentry"))
                    .and_then(|dentry| dentry.pointer_value())
                    .unwrap_or(0);
                if !whole_struct_readable(&context, &kernel, &open.file, "dentry", dentry_address) {
                    continue;
                }
                let Ok(dentry) = open
                    .file
                    .member("f_path")
                    .and_then(|path| path.member("dentry"))
                    .and_then(|dentry| dentry.dereference())
                else {
                    continue;
                };

                let inode_address = dentry
                    .member("d_inode")
                    .and_then(|inode| inode.pointer_value())
                    .unwrap_or(0);
                if !whole_struct_readable(&context, &kernel, &open.file, "inode", inode_address) {
                    continue;
                }
                let Ok(inode) = dentry
                    .member("d_inode")
                    .and_then(|inode| inode.dereference())
                else {
                    continue;
                };

                let Some(socket) = socket_of(&inode, &kernel) else {
                    continue;
                };
                let Some(details) = describe(&context, &kernel, &socket) else {
                    continue;
                };

                // Rows are filtered by namespace here rather than by skipping
                // tasks, so a filter that matches nothing still walks the same
                // ground and ends the same way.
                if let Some(wanted) = wanted_namespace {
                    if namespace != Some(wanted) {
                        continue;
                    }
                }

                grid.push(
                    0,
                    vec![
                        match namespace {
                            Some(id) => Value::int(id as i64),
                            None => Value::not_available(),
                        },
                        Value::string(comm.clone()),
                        Value::int(pid as i64),
                        or_unreadable(task.tid(), |value| Value::int(value as i64)),
                        Value::int(open.descriptor as i64),
                        Value::hex(socket.offset()),
                        Value::string(details.family),
                        Value::string(details.socket_type),
                        text_or_absent(details.protocol),
                        text_or_absent(details.source_address),
                        text_or_absent(details.source_port),
                        text_or_absent(details.destination_address),
                        text_or_absent(details.destination_port),
                        text_or_absent(details.state),
                        text_or_absent(details.filter),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// A field the socket family did not supply is reported as unavailable.
pub fn text_or_absent(value: Option<String>) -> Value {
    value.map(Value::string).unwrap_or_else(Value::not_available)
}

/// Whether the whole of the structure a pointer refers to is present.
///
/// Upstream validates a pointer by mapping `sizeof(*pointer)` bytes rather
/// than a single byte, so a structure whose tail has been paged out fails the
/// check even though its first bytes are still resident.
fn whole_struct_readable(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    anchor: &Object,
    type_name: &str,
    address: u64,
) -> bool {
    if address == 0 {
        return false;
    }
    let Ok(template) = context.symbol_space.get_type(&kernel.qualified(type_name)) else {
        return false;
    };
    let Ok(size) = context.symbol_space.size_of(&template) else {
        return false;
    };
    context
        .layers
        .read(anchor.native_layer_name(), address, size as usize, false)
        .is_ok()
}

/// The socket behind an inode.
fn socket_of(inode: &Object, kernel: &crate::framework::context::Module) -> Option<Object> {
    // A socket's inode is embedded in a `socket_alloc`, so the socket sits at a
    // fixed distance before the inode.
    let context = inode.context().clone();

    let alloc_template = context
        .symbol_space
        .get_type(&kernel.qualified("socket_alloc"))
        .ok()?;
    let inode_offset = context
        .symbol_space
        .find_member(&alloc_template, "vfs_inode")
        .ok()
        .flatten()
        .map(|(offset, _)| offset)?;

    let alloc_address = inode.offset().checked_sub(inode_offset)?;
    let alloc = context
        .object_from_template(alloc_template, inode.native_layer_name(), alloc_address)
        .with_native_layer(inode.native_layer_name());

    let inner = alloc
        .member("socket")
        .ok()?
        .member("sk")
        .ok()?
        .pointer_value()
        .ok()?;
    // As with the dentry and the inode, the socket itself must be present in
    // full before any of its fields are trusted.
    if !whole_struct_readable(&context, kernel, inode, "sock", inner) {
        return None;
    }

    let sock_template = context.symbol_space.get_type(&kernel.qualified("sock")).ok()?;
    Some(
        context
            .object_from_template(sock_template, inode.native_layer_name(), inner)
            .with_native_layer(inode.native_layer_name()),
    )
}

/// The fields a socket contributes to its row.
pub struct SocketDetails {
    pub family: String,
    pub socket_type: String,
    pub protocol: Option<String>,
    pub source_address: Option<String>,
    pub source_port: Option<String>,
    pub destination_address: Option<String>,
    pub destination_port: Option<String>,
    pub state: Option<String>,
    pub filter: Option<String>,
}

/// The generic state of the socket a `sock` belongs to.
///
/// Reaching the owning socket means following a pointer, which fails for a
/// structure that is no longer fully resident. Upstream lets that failure
/// travel, so a socket it cannot read is dropped rather than described.
fn generic_state(socket: &Object) -> Option<String> {
    let index = socket
        .member("sk_socket")
        .and_then(|owner| owner.dereference())
        .and_then(|owner| owner.member("state"))
        .and_then(|state| state.as_u64())
        .ok()?;
    Some(
        SOCKET_STATES
            .get(index as usize)
            .copied()
            .unwrap_or("Unknown socket state")
            .to_string(),
    )
}

/// Read a socket's addresses and state, dispatching on its family.
///
/// A family whose specific type is missing from the symbol table falls back to
/// the generic socket: its state, no addresses, no protocol and no filter. That
/// is what the reference implementation does when the cast raises.
pub fn describe(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    socket: &Object,
) -> Option<SocketDetails> {
    let common = socket.member("__sk_common").ok()?;
    let family_index = common.member("skc_family").ok()?.as_u64().ok()?;
    let family = FAMILIES
        .get(family_index as usize)
        .copied()
        .unwrap_or("Unknown socket family")
        .to_string();
    let socket_type = socket
        .member("sk_type")
        .and_then(|value| value.as_u64())
        .map(socket_type_name)
        .unwrap_or("")
        .to_string();

    let mut details = SocketDetails {
        family: family.clone(),
        socket_type: socket_type.clone(),
        protocol: None,
        source_address: None,
        source_port: None,
        destination_address: None,
        destination_port: None,
        // Each family says where its state comes from. Only the ones that fall
        // back to the owning socket read it from there.
        state: None,
        filter: None,
    };

    // Which type the family needs. A family with no handler keeps the generic
    // fields, exactly as an absent type does.
    let specific = match family.as_str() {
        "AF_UNIX" => Some("unix_sock"),
        "AF_INET" | "AF_INET6" => Some("inet_sock"),
        "AF_NETLINK" => Some("netlink_sock"),
        "AF_VSOCK" => Some("vsock_sock"),
        "AF_PACKET" => Some("packet_sock"),
        "AF_XDP" => Some("xdp_sock"),
        "AF_BLUETOOTH" => Some("bt_sock"),
        _ => None,
    };
    let Some(type_name) = specific else {
        details.state = Some(generic_state(socket)?);
        return Some(details);
    };
    let Ok(template) = context.symbol_space.get_type(&kernel.qualified(type_name)) else {
        details.state = Some(generic_state(socket)?);
        return Some(details);
    };
    // The same bytes, read as the family's own type: where they live does not
    // change, only how they are interpreted.
    let child = context
        .object_from_template(template.clone(), socket.layer_name(), socket.offset())
        .with_native_layer(socket.native_layer_name());

    match family.as_str() {
        "AF_UNIX" => {
            // These reads are unguarded upstream, so a socket whose peer has
            // been paged out is skipped rather than reported half-read.
            details.source_address = unix_name(&child, context, kernel)?;
            details.source_port = Some(socket_inode(&child, context, kernel)?.to_string());
            let peer = child.member("peer").and_then(|peer| peer.pointer_value()).ok()?;
            if peer != 0 {
                // The peer is named by a pointer, so it is read from the
                // layer this socket's pointers refer to.
                let other = context
                    .object_from_template(template.clone(), child.native_layer_name(), peer)
                    .with_native_layer(child.native_layer_name());
                details.destination_address = unix_name(&other, context, kernel)?;
                details.destination_port =
                    Some(socket_inode(&other, context, kernel)?.to_string());
            }
            // A stream unix socket reuses the connection states.
            details.state = Some(if socket_type == "STREAM" {
                let index = common.member("skc_state").and_then(|s| s.as_u64()).ok()?;
                TCP_STATES
                    .get(index as usize)
                    .copied()
                    .unwrap_or("Unknown unix_sock stream state")
                    .to_string()
            } else {
                generic_state(socket)?
            });
        }
        "AF_INET" | "AF_INET6" => {
            details.protocol = inet_protocol(socket, family_index);
            details.source_address = inet_address(&common, family_index, true);
            details.source_port = child
                .member("inet_sport")
                .and_then(|port| port.as_u64())
                .ok()
                .map(|port| (port as u16).to_be().to_string());
            details.destination_address = inet_address(&common, family_index, false);
            details.destination_port = common
                .member("skc_dport")
                .and_then(|port| port.as_u64())
                .ok()
                .map(|port| (port as u16).to_be().to_string());
            // Only a stream socket has a connection state.
            details.state = Some(if socket_type == "STREAM" {
                let index = common.member("skc_state").and_then(|s| s.as_u64()).ok()?;
                TCP_STATES
                    .get(index as usize)
                    .copied()
                    .unwrap_or("Unknown inet_sock stream state")
                    .to_string()
            } else {
                generic_state(socket)?
            });
        }
        "AF_NETLINK" => {
            details.protocol = netlink_protocol(socket);
            if let Ok(groups) = child
                .member("groups")
                .and_then(|groups| groups.dereference())
                .and_then(|groups| groups.as_u64())
            {
                details.source_address = Some(format!("groups:0x{groups:08x}"));
            }
            details.source_port = child
                .member("portid")
                .or_else(|_| child.member("pid"))
                .and_then(|port| port.as_u64())
                .ok()
                .map(|port| port.to_string());

            let group = child
                .member("dst_group")
                .and_then(|group| group.as_u64())
                .unwrap_or(0);
            let mut destination = format!("group:0x{group:08x}");
            if let Ok(name) = child
                .member("module")
                .and_then(|module| module.dereference())
                .and_then(|module| module.member("name"))
                .and_then(|name| name.as_string())
            {
                if !name.is_empty() {
                    destination = format!("{destination},lkm:{name}");
                }
            }
            details.destination_address = Some(destination);
            details.destination_port = child
                .member("dst_portid")
                .or_else(|_| child.member("dst_pid"))
                .and_then(|port| port.as_u64())
                .ok()
                .map(|port| port.to_string());
            details.state = Some(generic_state(socket)?);
        }
        "AF_VSOCK" => {
            let field = |group: &str, name: &str| {
                child
                    .member(group)
                    .and_then(|addr| addr.member(name))
                    .and_then(|value| value.as_u64())
                    .ok()
                    .map(|value| value.to_string())
            };
            details.source_address = field("local_addr", "svm_cid");
            details.source_port = field("local_addr", "svm_port");
            details.destination_address = field("remote_addr", "svm_cid");
            details.destination_port = field("remote_addr", "svm_port");
            details.state = Some(generic_state(socket)?);
        }
        "AF_PACKET" => {
            details.protocol = packet_protocol(&child);
            let index = child
                .member("ifindex")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            // A socket bound to no interface sees them all.
            details.source_address = Some(if index > 0 {
                device_name(context, kernel, index).unwrap_or_default()
            } else {
                "ANY".to_string()
            });
            details.state = Some(generic_state(socket)?);
        }
        "AF_BLUETOOTH" => {
            details.protocol = bluetooth_protocol(socket);
            let index = common.member("skc_state").and_then(|s| s.as_u64()).ok()?;
            details.state = BLUETOOTH_STATES
                .get(index as usize)
                .map(|state| state.to_string());
        }
        "AF_XDP" => {
            // The socket keeps its own state as an enumeration.
            details.state = Some(child.member("state").and_then(|s| s.enum_name()).ok()?);
        }
        _ => {}
    }

    // The filter is only reported once a family handler has run.
    details.filter = socket_filter(socket);
    Some(details)
}

/// The path a unix socket is bound to.
fn unix_name(
    unix: &Object,
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Option<Option<String>> {
    // The outer option reports whether the read succeeded. The inner one
    // whether the socket is bound to a path at all.
    let address = unix.member("addr").ok()?.pointer_value().ok()?;
    if address == 0 {
        return Some(None);
    }
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("unix_address"))
        .ok()?;
    let holder = context
        .object_from_template(template, unix.native_layer_name(), address)
        .with_native_layer(unix.native_layer_name());
    let name = holder.member("name").ok()?;
    // The name is a `sockaddr_un`, whose path follows the family word.
    let bytes = context
        .layers
        .read(unix.native_layer_name(), name.offset() + 2, 108, true)
        .ok()?;
    // Decoded the way every other character array is, so a path that runs into
    // unrelated bytes ends where they start rather than trailing them.
    Some(Some(decode_string(&bytes, Encoding::Utf8)))
}

/// The inode number of the socket a `sock` belongs to.
fn socket_inode(
    socket: &Object,
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Option<u64> {
    let owner = socket
        .member("sk")
        .and_then(|sk| sk.member("sk_socket"))
        .or_else(|_| socket.member("sk_socket"))
        .ok()?
        .pointer_value()
        .ok()?;
    // A socket with no file behind it has no inode number to report.
    if owner == 0 {
        return Some(0);
    }
    Some(inode_of(socket, context, kernel)?)
}

/// The inode behind a socket, when one can be reached.
fn inode_of(
    socket: &Object,
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Option<u64> {
    let owner = socket
        .member("sk")
        .and_then(|sk| sk.member("sk_socket"))
        .or_else(|_| socket.member("sk_socket"))
        .ok()?
        .pointer_value()
        .ok()?;
    if owner == 0 {
        return None;
    }
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("socket_alloc"))
        .ok()?;
    let offset = context
        .symbol_space
        .find_member(&template, "socket")
        .ok()?
        .map(|(offset, _)| offset)?;
    // The owning socket is named by a pointer, so it lives wherever this
    // object's pointers point, which is not where the object itself was found
    // when it was recovered from physical memory.
    let alloc = context.object_from_template(
        template,
        socket.native_layer_name(),
        owner.checked_sub(offset)?,
    );
    alloc
        .member("vfs_inode")
        .and_then(|inode| inode.member("i_ino"))
        .and_then(|number| number.as_u64())
        .ok()
}

/// The transport protocol of an internet socket.
fn inet_protocol(socket: &Object, family: u64) -> Option<String> {
    let number = socket.member("sk_protocol").ok()?.as_u64().ok()?;
    // An IPv6 socket names a few protocol numbers differently.
    if family == 10 {
        let name = match number {
            0 => Some("HOPBYHOP_OPTS"),
            43 => Some("ROUTING"),
            44 => Some("FRAGMENT"),
            58 => Some("ICMPv6"),
            59 => Some("NO_NEXT"),
            60 => Some("DESTINATION_OPTS"),
            135 => Some("MOBILITY"),
            _ => None,
        };
        if let Some(name) = name {
            return Some(name.to_string());
        }
    }
    let name = match number {
        0 => "IP", 1 => "ICMP", 2 => "IGMP", 4 => "IPIP", 6 => "TCP", 8 => "EGP",
        12 => "PUP", 17 => "UDP", 22 => "IDP", 29 => "TP", 33 => "DCCP",
        41 => "IPV6", 46 => "RSVP", 47 => "GRE", 50 => "ESP", 51 => "AH",
        92 => "MTP", 94 => "BEETPH", 98 => "ENCAP", 103 => "PIM", 108 => "COMP",
        132 => "SCTP", 136 => "UDPLITE", 137 => "MPLS", 143 => "ETHERNET",
        255 => "RAW", 262 => "MPTCP",
        _ => return None,
    };
    Some(name.to_string())
}

/// The address on one end of an internet socket.
fn inet_address(common: &Object, family: u64, source: bool) -> Option<String> {
    if family == 2 {
        let member = if source { "skc_rcv_saddr" } else { "skc_daddr" };
        let raw = common.member(member).ok()?.as_u64().ok()? as u32;
        return Some(convert_ipv4(raw));
    }
    let member = if source { "skc_v6_rcv_saddr" } else { "skc_v6_daddr" };
    let bytes = common.member(member).ok()?.bytes().ok()?;
    Some(convert_ipv6(&bytes))
}

/// The netlink protocol a socket speaks.
fn netlink_protocol(socket: &Object) -> Option<String> {
    const PROTOCOLS: &[&str] = &[
        "NETLINK_ROUTE", "NETLINK_UNUSED", "NETLINK_USERSOCK", "NETLINK_FIREWALL",
        "NETLINK_SOCK_DIAG", "NETLINK_NFLOG", "NETLINK_XFRM", "NETLINK_SELINUX",
        "NETLINK_ISCSI", "NETLINK_AUDIT", "NETLINK_FIB_LOOKUP", "NETLINK_CONNECTOR",
        "NETLINK_NETFILTER", "NETLINK_IP6_FW", "NETLINK_DNRTMSG",
        "NETLINK_KOBJECT_UEVENT", "NETLINK_GENERIC", "NETLINK_DM",
        "NETLINK_SCSITRANSPORT", "NETLINK_ECRYPTFS", "NETLINK_RDMA",
        "NETLINK_CRYPTO", "NETLINK_SMC",
    ];
    let index = socket.member("sk_protocol").ok()?.as_u64().ok()?;
    Some(
        PROTOCOLS
            .get(index as usize)
            .copied()
            .unwrap_or("Unknown netlink_sock protocol")
            .to_string(),
    )
}

/// The bluetooth protocol a socket speaks.
fn bluetooth_protocol(socket: &Object) -> Option<String> {
    const PROTOCOLS: &[&str] = &[
        "L2CAP", "HCI", "SCO", "RFCOMM", "BNEP", "CMTP", "HIDP", "AVDTP",
    ];
    let index = socket.member("sk_protocol").ok()?.as_u64().ok()?;
    PROTOCOLS.get(index as usize).map(|name| name.to_string())
}

/// The ethernet protocol a packet socket is bound to.
///
/// The number is stored in network order, so it is swapped before it is named.
fn packet_protocol(packet: &Object) -> Option<String> {
    let number = (packet.member("num").ok()?.as_u64().ok()? as u16).to_be();
    if number == 0 {
        return None;
    }
    let name = match number {
        0x0001 => "ETH_P_802_3", 0x0002 => "ETH_P_AX25", 0x0003 => "ETH_P_ALL",
        0x0004 => "ETH_P_802_2", 0x0005 => "ETH_P_SNAP", 0x0006 => "ETH_P_DDCMP",
        0x0007 => "ETH_P_WAN_PPP", 0x0008 => "ETH_P_PPP_MP",
        0x0009 => "ETH_P_LOCALTALK", 0x000C => "ETH_P_CAN", 0x000F => "ETH_P_CANFD",
        0x0010 => "ETH_P_PPPTALK", 0x0011 => "ETH_P_TR_802_2",
        0x0016 => "ETH_P_CONTROL", 0x0017 => "ETH_P_IRDA", 0x0018 => "ETH_P_ECONET",
        0x0019 => "ETH_P_HDLC", 0x001A => "ETH_P_ARCNET", 0x001B => "ETH_P_DSA",
        0x001C => "ETH_P_TRAILER", 0x0060 => "ETH_P_LOOP",
        0x0800 => "ETH_P_IP", 0x0806 => "ETH_P_ARP", 0x86DD => "ETH_P_IPV6",
        0x8100 => "ETH_P_8021Q", 0x88A8 => "ETH_P_8021AD", 0x8863 => "ETH_P_PPP_DISC",
        0x8864 => "ETH_P_PPP_SES", 0x888E => "ETH_P_PAE",
        other => return Some(format!("{other:#x}")),
    };
    Some(name.to_string())
}

/// The name of the interface an index refers to.
fn device_name(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    index: i64,
) -> Option<String> {
    for namespace in list_net_namespaces(context, kernel).ok()? {
        for device in list_net_devices(kernel, &namespace).unwrap_or_default() {
            if device.index().ok() == Some(index) {
                return device.name().ok();
            }
        }
    }
    None
}

/// A description of the filter attached to a socket.
///
/// A classic filter is a program the kernel interprets. An extended one is a
/// BPF program with an identity of its own, which is worth naming.
fn socket_filter(socket: &Object) -> Option<String> {
    let attached = |name: &str| -> Option<Object> {
        let pointer = socket.member(name).ok()?;
        (pointer.pointer_value().ok()? != 0).then(|| pointer.dereference().ok())?
    };

    let (kind, filter) = if let Some(filter) = attached("sk_filter") {
        ("socket_filter", filter)
    } else if let Some(filter) = attached("sk_reuseport_cb") {
        ("reuseport_filter", filter)
    } else {
        return None;
    };

    let mut fields = vec![format!("filter_type={kind}")];
    // Anything without an extended program behind it is a classic filter.
    let mut flavour = "cBPF";
    let program = filter
        .member("prog")
        .ok()
        .filter(|prog| prog.pointer_value().unwrap_or(0) != 0)
        .and_then(|prog| prog.dereference().ok());

    if let Some(program) = program {
        match program.member("type").and_then(|kind| kind.enum_name()) {
            Ok(name) if name == "BPF_PROG_TYPE_SOCKET_FILTER" => flavour = "eBPF",
            Ok(name) if name == "BPF_PROG_TYPE_UNSPEC" => {}
            Ok(name) => {
                fields.push(format!("bpf_filter_type=UNK({name})"));
                return Some(fields.join(","));
            }
            Err(_) => {}
        }
    }
    fields.push(format!("bpf_filter_type={flavour}"));
    Some(fields.join(","))
}
