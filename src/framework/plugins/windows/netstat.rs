//! List the network connections the stack is still tracking.
//!
//! Where scanning finds every endpoint structure the pools ever held, this
//! walks the tables the network driver keeps: the partitions holding
//! established connections, and the port pools holding listeners and datagram
//! sockets. What it reports is what the machine believed was open.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::windows::netscan;
use crate::framework::plugins::windows::pe_symbols::resolve_across_instances;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid};

pub struct NetStat;

/// The driver that tracks the connections.
const DRIVER: &str = "tcpip.sys";

/// A bitmap of ports is one page and a half at most. Anything larger means the
/// size was smeared.
const MAXIMUM_BITMAP: u64 = 8192 * 10;

/// A hash table larger than this has been smeared rather than grown.
const MAXIMUM_TABLE: u64 = 4096;

impl Plugin for NetStat {
    fn name(&self) -> &'static str {
        "windows.netstat.NetStat"
    }

    fn description(&self) -> &'static str {
        "Traverses network tracking structures present in a particular windows memory image."
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
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            if !is_time(&values[9]) {
                continue;
            }
            let description = format!(
                "Network connection: Process {} {} Local Address {}:{} Remote Address {}:{} \
                 State {} Protocol {} ",
                number(&values[7]),
                number(&values[8]),
                number(&values[2]),
                number(&values[3]),
                number(&values[4]),
                number(&values[5]),
                number(&values[6]),
                number(&values[1])
            );
            timeline.push(description, TimeKind::Created, values[9].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let corrupt = config.get_bool("include-corrupt").unwrap_or(false);
        let table = netscan::netscan_table(&context, &kernel)?;

        // The tables belong to the driver, and are found by the names its own
        // database gives them.
        let Some((base, size)) = driver_image(&context, &kernel) else {
            return Err(VolatilityError::Other(
                "Unable to locate the network driver in this image".to_string(),
            ));
        };
        let wanted = [
            "PartitionTable",
            "PartitionCount",
            "UdpPortPool",
            "TcpPortPool",
            "UdpCompartmentSet",
            "TcpCompartmentSet",
        ];
        let resolved = resolve_across_instances(
            &context,
            &[(kernel.layer_name.clone(), base, size)],
            DRIVER,
            &wanted,
        );
        if resolved.is_empty() {
            return Err(VolatilityError::Other(
                "Unable to locate symbols for the memory image's tcpip module".to_string(),
            ));
        }
        let address_of = |name: &str| -> Option<u64> {
            resolved
                .iter()
                .find(|(found, _)| found == name)
                .map(|(_, address)| *address)
        };

        let mut endpoints: Vec<Object> = Vec::new();
        endpoints.extend(partitions(&context, &kernel, &table, &address_of));
        endpoints.extend(port_pools(&context, &kernel, &table, &address_of));

        let mut grid = TreeGrid::new(self.columns());
        let mut seen: HashSet<u64> = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(endpoint.offset()) {
                continue;
            }
            // The rows are the same the scanning plugin produces, so the two
            // report identically for the endpoints both find.
            for row in netscan::rows_for(&context, &kernel, &endpoint, corrupt) {
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// Where the network driver is loaded.
fn driver_image(context: &Arc<Context>, kernel: &Module) -> Option<(u64, u64)> {
    let head = context
        .object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))
        .ok()?;
    let entries = walk_list(
        &head,
        &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
        "InLoadOrderLinks",
        true,
    )
    .ok()?;

    entries.into_iter().find_map(|entry| {
        let name = entry
            .member("BaseDllName")
            .and_then(|name| unicode_string(&name))
            .ok()?;
        if name != DRIVER {
            return None;
        }
        let base = entry
            .member("DllBase")
            .and_then(|base| base.pointer_value())
            .ok()?;
        let size = entry
            .member("SizeOfImage")
            .and_then(|size| size.as_u64())
            .ok()?;
        Some((base, size))
    })
}

/// The established connections, which the driver keeps one table of per
/// processor group.
fn partitions(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
    address_of: &impl Fn(&str) -> Option<u64>,
) -> Vec<Object> {
    let mut found = Vec::new();
    let (Some(table_symbol), Some(count_symbol)) =
        (address_of("PartitionTable"), address_of("PartitionCount"))
    else {
        return found;
    };

    let Ok(partition_table) = read_pointer(context, &kernel.layer_name, table_symbol) else {
        return found;
    };
    let Ok(count) = context
        .layers
        .read(&kernel.layer_name, count_symbol, 1, false)
        .map(|data| data[0] as u64)
    else {
        return found;
    };

    let partition_type = format!("{table}!_PARTITION");
    let Ok(partition_template) = context.symbol_space.get_type(&partition_type) else {
        return found;
    };
    let Ok(partition_size) = context.symbol_space.size_of(&partition_template) else {
        return found;
    };
    let endpoint_type = format!("{table}!_TCP_ENDPOINT");
    let Some(list_offset) = member_offset(context, &endpoint_type, "ListEntry") else {
        return found;
    };

    for index in 0..count {
        let at = partition_table + index * partition_size;
        let Ok(partition) = context.object(&partition_type, &kernel.layer_name, at) else {
            continue;
        };
        let Ok(endpoints) = partition
            .member("Endpoints")
            .and_then(|endpoints| endpoints.dereference())
        else {
            continue;
        };
        let (Ok(entries), Ok(directory), Ok(size)) = (
            endpoints.member("NumEntries").and_then(|value| value.as_u64()),
            endpoints
                .member("Directory")
                .and_then(|value| value.pointer_value()),
            endpoints.member("TableSize").and_then(|value| value.as_u64()),
        ) else {
            continue;
        };
        if entries == 0 || size > MAXIMUM_TABLE {
            continue;
        }

        // Each bucket holds a pointer into a connection. A bucket that names
        // itself is empty.
        for bucket in 0..size {
            let at = directory + bucket * 0x10;
            let Ok(pointer) = read_pointer(context, &kernel.layer_name, at) else {
                continue;
            };
            if pointer == at || pointer == 0 {
                continue;
            }
            let Some(start) = pointer.checked_sub(list_offset) else {
                continue;
            };
            if let Ok(endpoint) = context.object(&endpoint_type, &kernel.layer_name, start) {
                found.push(endpoint);
            }
        }
    }
    found
}

/// The listeners and datagram sockets, which the driver keeps by port.
fn port_pools(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
    address_of: &impl Fn(&str) -> Option<u64>,
) -> Vec<Object> {
    let mut found = Vec::new();

    // Older drivers name the pools directly. Newer ones name the compartment
    // holding each.
    let pools = match (address_of("UdpPortPool"), address_of("TcpPortPool")) {
        (Some(udp), Some(tcp)) => {
            let (Ok(udp), Ok(tcp)) = (
                read_pointer(context, &kernel.layer_name, udp),
                read_pointer(context, &kernel.layer_name, tcp),
            ) else {
                return found;
            };
            Some((udp, tcp))
        }
        _ => {
            let (Some(udp), Some(tcp)) = (
                address_of("UdpCompartmentSet"),
                address_of("TcpCompartmentSet"),
            ) else {
                return found;
            };
            let pool_of = |symbol: u64| -> Option<u64> {
                let set = read_pointer(context, &kernel.layer_name, symbol).ok()?;
                context
                    .object(
                        &format!("{table}!_INET_COMPARTMENT_SET"),
                        &kernel.layer_name,
                        set,
                    )
                    .ok()?
                    .member("InetCompartment")
                    .and_then(|compartment| compartment.dereference())
                    .and_then(|compartment| compartment.member("ProtocolCompartment"))
                    .and_then(|protocol| protocol.dereference())
                    .and_then(|protocol| protocol.member("PortPool"))
                    .and_then(|pool| pool.pointer_value())
                    .ok()
            };
            match (pool_of(udp), pool_of(tcp)) {
                (Some(udp), Some(tcp)) => Some((udp, tcp)),
                _ => None,
            }
        }
    };
    let Some((udp_pool, tcp_pool)) = pools else {
        return found;
    };

    for (pool, kind) in [(tcp_pool, "tcp"), (udp_pool, "udp")] {
        for port in pool_ports(context, kernel, table, pool) {
            if port == 0 {
                continue;
            }
            found.extend(sockets_on_port(context, kernel, table, pool, port, kind));
        }
    }
    found
}

/// The ports a pool records as in use.
fn pool_ports(context: &Arc<Context>, kernel: &Module, table: &str, pool: u64) -> Vec<u64> {
    let Ok(pool) = context.object(
        &format!("{table}!_INET_PORT_POOL"),
        &kernel.layer_name,
        pool,
    ) else {
        return Vec::new();
    };
    let (Ok(buffer), Ok(bits)) = (
        pool.member("PortBitMap")
            .and_then(|bitmap| bitmap.member("Buffer"))
            .and_then(|buffer| buffer.pointer_value()),
        pool.member("PortBitMap")
            .and_then(|bitmap| bitmap.member("SizeOfBitMap"))
            .and_then(|size| size.as_u64()),
    ) else {
        return Vec::new();
    };

    let bytes = bits / 8;
    if bytes > MAXIMUM_BITMAP {
        return Vec::new();
    }

    let mut ports = Vec::new();
    for index in 0..bytes {
        let Ok(data) = context
            .layers
            .read(&kernel.layer_name, buffer + index, 1, false)
        else {
            continue;
        };
        for bit in 0..8 {
            if data[0] & (1 << bit) != 0 {
                ports.push(index * 8 + bit);
            }
        }
    }
    ports
}

/// The sockets bound to one port.
fn sockets_on_port(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
    pool: u64,
    port: u64,
    kind: &str,
) -> Vec<Object> {
    let type_name = match kind {
        "tcp" => format!("{table}!_TCP_LISTENER"),
        _ => format!("{table}!_UDP_ENDPOINT"),
    };
    let Some(next_offset) = member_offset(context, &type_name, "Next") else {
        return Vec::new();
    };

    // A port is an index into the pool: the high byte selects a list, the low
    // byte an entry within it.
    let Ok(pool) = context.object(
        &format!("{table}!_INET_PORT_POOL"),
        &kernel.layer_name,
        pool,
    ) else {
        return Vec::new();
    };
    // A port is an index into the pool: the high byte selects a list, the low
    // byte an entry within it.
    let Ok(assignment) = pool
        .member("PortAssignments")
        .and_then(|assignments| assignments.index(port >> 8))
        .and_then(|assignment| assignment.dereference())
        .and_then(|assignment| assignment.member("InPaBigPoolBase"))
        .and_then(|base| base.dereference())
        .and_then(|base| base.member("Assignments"))
        .and_then(|assignments| assignments.index(port & 0xFF))
        .and_then(|entry| entry.member("Entry"))
        .and_then(|entry| entry.pointer_value())
    else {
        return Vec::new();
    };

    // The recorded pointer is masked and names a place inside the socket
    // rather than its start.
    let mut address = decode_pointer(assignment);
    let mut found = Vec::new();
    while address != 0 {
        let Some(start) = address.checked_sub(next_offset) else {
            break;
        };
        let Ok(socket) = context.object(&type_name, &kernel.layer_name, start) else {
            break;
        };
        found.push(socket.clone());

        // The same port on another interface is another socket, linked from
        // this one.
        let Ok(next) = socket
            .member("Next")
            .and_then(|next| next.pointer_value())
        else {
            break;
        };
        address = decode_pointer(next);
    }
    found
}

/// The address a recorded pointer names, with the bits the driver keeps for
/// itself removed.
fn decode_pointer(value: u64) -> u64 {
    value & 0xFFFF_FFFF_FFFF_FFFC
}

/// Read a pointer-sized word.
fn read_pointer(context: &Arc<Context>, layer: &str, at: u64) -> Result<u64> {
    let data = context.layers.read(layer, at, 8, false)?;
    Ok(u64::from_le_bytes(data.try_into().unwrap()))
}

/// Where a member sits inside a type.
fn member_offset(context: &Arc<Context>, type_name: &str, member: &str) -> Option<u64> {
    let template = context.symbol_space.get_type(type_name).ok()?;
    context
        .symbol_space
        .find_member(&template, member)
        .ok()?
        .map(|(offset, _)| offset)
}
