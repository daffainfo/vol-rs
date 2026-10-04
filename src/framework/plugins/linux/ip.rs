//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{list_net_devices, list_net_namespaces};

/// Lists network interface information for all devices
pub struct Addr;

impl Plugin for Addr {
    fn name(&self) -> &'static str {
        "linux.ip.Addr"
    }

    fn description(&self) -> &'static str {
        "Lists network interface information for all devices"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("NetNS"),
            Column::int("Index"),
            Column::string("Interface"),
            Column::string("MAC"),
            Column::bool("Promiscuous"),
            Column::string("IP"),
            Column::int("Prefix"),
            Column::string("Scope Type"),
            Column::string("State"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        for namespace in list_net_namespaces(&context, &kernel)? {
            // A kernel before 3.8 has nothing to name a namespace by, and a
            // zero is treated the same way, since upstream tests the number for
            // truth rather than for presence.
            let namespace_id = net_namespace_id(&namespace).filter(|id| *id != 0);

            for device in list_net_devices(&kernel, &namespace).unwrap_or_default() {
                let mac = device.mac_address();

                // IPv4 first, then IPv6, which is the order `ip addr` uses.
                // A device with no address configured contributes no rows.
                let addresses = device
                    .ipv4_addresses()
                    .into_iter()
                    .chain(device.ipv6_addresses());

                for (address, prefix, scope) in addresses {
                    grid.push(
                        0,
                        vec![
                            match namespace_id {
                                Some(id) => Value::int(id as i64),
                                None => Value::not_available(),
                            },
                            or_unreadable(device.index(), Value::int),
                            or_unreadable(device.name(), Value::string),
                            match &mac {
                                Some(mac) => Value::string(mac.clone()),
                                None => Value::not_available(),
                            },
                            Value::Bool(device.is_promiscuous()),
                            Value::string(address),
                            Value::int(prefix as i64),
                            Value::string(scope),
                            Value::string(device.state()),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// A network namespace's own inode number, which is what names it.
///
/// Kernel 3.8 gave namespaces an inode, moving it into `ns` in 3.19. A kernel
/// older than that has nothing to report here. `net_namespace_list` itself
/// exists from kernels >= 2.6.24.
fn net_namespace_id(namespace: &crate::framework::objects::Object) -> Option<u64> {
    // 3.8.13 <= kernel < 3.19.8 keeps it in `proc_inum`, kernel >= 3.19.8 in
    // `ns.inum`, and a kernel < 3.8.13 has no net_namespace inode at all.
    if namespace.has_member("proc_inum") {
        return namespace.member("proc_inum").and_then(|id| id.as_u64()).ok();
    }
    namespace
        .member("ns")
        .ok()
        .filter(|ns| ns.has_member("inum"))
        .and_then(|ns| ns.member("inum").ok())
        .and_then(|inum| inum.as_u64().ok())
}

/// Lists information about network interfaces similar to `ip link show`
pub struct Link;

impl Plugin for Link {
    fn name(&self) -> &'static str {
        "linux.ip.Link"
    }

    fn description(&self) -> &'static str {
        "Lists information about network interfaces similar to `ip link show`"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("NS"),
            Column::string("Interface"),
            Column::string("MAC"),
            Column::string("State"),
            Column::int("MTU"),
            Column::string("Qdisc"),
            Column::int("Qlen"),
            Column::string("Flags"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        for namespace in list_net_namespaces(&context, &kernel)? {
            // A kernel before 3.8 has nothing to name a namespace by, and a
            // zero is treated the same way, since upstream tests the number for
            // truth rather than for presence.
            let namespace_id = net_namespace_id(&namespace).filter(|id| *id != 0);

            for device in list_net_devices(&kernel, &namespace).unwrap_or_default() {
                grid.push(
                    0,
                    vec![
                        match namespace_id {
                            Some(id) => Value::int(id as i64),
                            None => Value::not_available(),
                        },
                        or_unreadable(device.name(), Value::string),
                        device
                            .mac_address()
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                        Value::string(device.state()),
                        device
                            .object
                            .member("mtu")
                            .and_then(|mtu| mtu.as_i64())
                            .map(Value::int)
                            .unwrap_or_else(|_| Value::unreadable()),
                        // The queueing discipline names how the interface
                        // schedules outbound packets.
                        device
                            .object
                            .member("qdisc")
                            .and_then(|qdisc| qdisc.dereference())
                            .and_then(|qdisc| qdisc.member("ops"))
                            .and_then(|ops| ops.dereference())
                            .and_then(|ops| ops.member("id"))
                            .and_then(|id| id.as_string())
                            .map(Value::string)
                            .unwrap_or_else(|_| Value::not_available()),
                        device
                            .object
                            .member("tx_queue_len")
                            .and_then(|len| len.as_i64())
                            .map(Value::int)
                            .unwrap_or_else(|_| Value::unreadable()),
                        Value::string(
                            // `ip link` drops the IFF_ prefix and does not show
                            // RUNNING, which it considers redundant with the
                            // operational state.
                            device
                                .flag_names()
                                .into_iter()
                                .filter(|flag| flag != "IFF_RUNNING")
                                .map(|flag| flag.trim_start_matches("IFF_").to_string())
                                .collect::<Vec<String>>()
                                .join(","),
                        ),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
