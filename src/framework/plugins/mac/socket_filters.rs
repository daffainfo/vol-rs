//! List the registered socket filters.
//!
//! A socket filter sees, and can rewrite, traffic passing through any socket it
//! attaches to. Legitimate firewalls use them. So does anything wanting to
//! intercept network traffic from inside the kernel.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::{walk_tailq, ExtensionResolver};

pub struct SocketFilters;

/// The callbacks a filter can install, each intercepting a different operation.
const FILTER_MEMBERS: &[&str] = &[
    "sf_unregistered",
    "sf_attach",
    "sf_detach",
    "sf_notify",
    "sf_getpeername",
    "sf_getsockname",
    "sf_data_in",
    "sf_data_out",
    "sf_connect_in",
    "sf_connect_out",
    "sf_bind",
    "sf_setoption",
    "sf_getoption",
    "sf_listen",
    "sf_ioctl",
];

impl Plugin for SocketFilters {
    fn name(&self) -> &'static str {
        "mac.socket_filters.Socket_filters"
    }

    fn description(&self) -> &'static str {
        "Enumerates kernel socket filters."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Filter", ColumnType::UInt),
            Column::string("Name"),
            Column::string("Member"),
            Column::new("Socket", ColumnType::UInt),
            Column::new("Handler", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        // Filters are registered on a list the socket layer keeps.
        let head = context.object_from_symbol(&kernel, "sock_filter_head", None)?;
        let filters = walk_tailq(&head, &kernel.qualified("socket_filter"), "sf_global_next")?;

        let mut grid = TreeGrid::new(self.columns());

        for filter in filters {
            let name = filter
                .member("sf_filter")
                .and_then(|inner| inner.member("sf_name"))
                .and_then(|name| pointer_to_string(&name, 128))
                .unwrap_or_default();

            let Ok(callbacks) = filter.member("sf_filter") else {
                continue;
            };

            // The socket the filter was attached to, where it was attached to
            // one rather than registered for every socket.
            let socket = filter
                .member("sf_entry_head")
                .and_then(|head| head.dereference())
                .and_then(|entry| entry.member("sfe_socket"))
                .map(|socket| socket.offset())
                .unwrap_or(0);

            // Report each installed callback. An absent one is simply not
            // intercepted by this filter.
            for member in FILTER_MEMBERS {
                let Ok(handler) = callbacks
                    .member(member)
                    .and_then(|handler| handler.pointer_value())
                else {
                    continue;
                };
                if handler == 0 {
                    continue;
                }

                let (module, symbol) = match &resolver {
                    Some(resolver) => resolver.describe_unshifted(&context, handler),
                    None => ("UNKNOWN".to_string(), "N/A".to_string()),
                };

                grid.push(
                    0,
                    vec![
                        Value::hex(callbacks.offset()),
                        Value::string(name.clone()),
                        Value::string(*member),
                        Value::hex(socket),
                        Value::hex(handler),
                        Value::string(module),
                        Value::string(symbol),
                    ],
                )?;
            }

        }
        Ok(grid)
    }
}
