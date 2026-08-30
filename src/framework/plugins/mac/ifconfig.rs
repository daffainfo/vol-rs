//! Report the network interfaces and their addresses.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::{format_sockaddr, format_sockaddr_dl, walk_tailq};

pub struct IfConfig;

/// The interface is capturing all traffic, not just its own.
const IFF_PROMISC: u64 = 0x100;

impl Plugin for IfConfig {
    fn name(&self) -> &'static str {
        "mac.ifconfig.Ifconfig"
    }

    fn description(&self) -> &'static str {
        "Lists network interface information for all devices"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Interface"),
            Column::string("IP Address"),
            Column::string("Mac Address"),
            Column::bool("Promiscuous"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // The list is named differently depending on how the kernel was built.
        let head = ["ifnet_head", "dlil_ifnet_head"]
            .iter()
            .find_map(|symbol| {
                context
                    .object_from_symbol(&kernel, symbol, None)
                    .ok()
            })
            .ok_or_else(|| {
                crate::error::VolatilityError::Other(
                    "Could not find the interface list; the kernel symbols may not match"
                        .to_string(),
                )
            })?;

        let interfaces = walk_tailq(&head, &kernel.qualified("ifnet"), "if_link")?;
        let mut grid = TreeGrid::new(self.columns());

        for interface in interfaces {
            // The interface name is the driver name plus its unit number, which
            // is how the system presents it: `en0`, `lo0` and so on.
            let name = interface
                .member("if_name")
                .and_then(|name| pointer_to_string(&name, 32))
                .unwrap_or_default();
            let unit = interface
                .member("if_unit")
                .and_then(|unit| unit.as_u64())
                .unwrap_or(0);
            let label = format!("{name}{unit}");

            let promiscuous = interface
                .member("if_flags")
                .and_then(|flags| flags.as_u64())
                .map(|flags| flags & IFF_PROMISC == IFF_PROMISC)
                .unwrap_or(false);

            // The hardware address is held by the link-level address where the
            // kernel records one, and otherwise by the first address in the
            // list. Either way it is read as a link-level address whatever the
            // family says.
            let link_address = if interface.has_member("if_lladdr") {
                interface
                    .member("if_lladdr")
                    .and_then(|address| address.dereference())
                    .and_then(|address| address.member("ifa_addr"))
                    .and_then(|sockaddr| sockaddr.dereference())
            } else {
                interface
                    .member("if_addrhead")
                    .and_then(|head| head.member("tqh_first"))
                    .and_then(|first| first.dereference())
                    .and_then(|first| first.member("ifa_addr"))
                    .and_then(|sockaddr| sockaddr.dereference())
            };
            let mac = link_address
                .and_then(|sockaddr| sockaddr.cast(&kernel.qualified("sockaddr_dl")))
                .map(|sockaddr| format_sockaddr_dl(&sockaddr))
                .ok();

            // Each interface may carry several addresses, and each one is
            // reported on its own.
            let addresses = interface
                .member("if_addrhead")
                .and_then(|head| walk_tailq(&head, &kernel.qualified("ifaddr"), "ifa_link"))
                .unwrap_or_default();

            for entry in addresses {
                let address = entry
                    .member("ifa_addr")
                    .and_then(|sockaddr| sockaddr.dereference())
                    .map(|sockaddr| format_sockaddr(&sockaddr))
                    .unwrap_or_default();

                grid.push(
                    0,
                    vec![
                        Value::string(label.clone()),
                        Value::string(address),
                        match &mac {
                            Some(mac) => Value::string(mac.clone()),
                            None => Value::not_available(),
                        },
                        Value::Bool(promiscuous),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
