//! List the processes watching filesystem events.
//!
//! A process registered with the vfs event system is told about every file
//! change on the system, which is worth knowing about whether the watcher is
//! Spotlight or something less welcome.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct VfsEvents;

/// The event types a watcher can subscribe to, in bit order.
const EVENT_NAMES: &[&str] = &[
    "CREATE_FILE",
    "DELETE",
    "STAT_CHANGED",
    "RENAME",
    "CONTENT_MODIFIED",
    "EXCHANGE",
    "FINDER_INFO_CHANGED",
    "CREATE_DIR",
    "CHOWN",
    "XATTR_MODIFIED",
    "XATTR_REMOVED",
    "DOCID_CREATED",
    "DOCID_CHANGED",
];

impl Plugin for VfsEvents {
    fn name(&self) -> &'static str {
        "mac.vfsevents.VFSevents"
    }

    fn description(&self) -> &'static str {
        "Lists processes that are filtering file system events"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::int("PID"),
            Column::string("Events"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // The kernel keeps a fixed table of watchers, sized by the symbol file.
        let table = context.object_from_symbol(&kernel, "watcher_table", None)?;
        let slots = table.count().unwrap_or(0);

        let mut grid = TreeGrid::new(self.columns());

        for index in 0..slots {
            let Ok(pointer) = table.index(index) else {
                continue;
            };
            // Most of the table is unused, which is how it usually looks.
            let Ok(address) = pointer.pointer_value() else {
                continue;
            };
            if address == 0 {
                continue;
            }
            let Ok(watcher) = pointer.dereference() else {
                continue;
            };

            let name = watcher
                .member("proc_name")
                .and_then(|name| name.as_string())
                .unwrap_or_default();

            // The event list holds one byte per kind of event, set where the
            // watcher asked to hear about it.
            let Ok(list) = watcher
                .member("event_list")
                .and_then(|list| list.pointer_value())
            else {
                continue;
            };
            let Ok(raw) = context
                .layers
                .read(&kernel.layer_name, list, EVENT_NAMES.len(), false)
            else {
                continue;
            };

            let events: Vec<&str> = EVENT_NAMES
                .iter()
                .zip(raw.iter())
                .filter(|(_, subscribed)| **subscribed == 1)
                .map(|(name, _)| *name)
                .collect();
            // A watcher listening for nothing is not reported.
            if events.is_empty() {
                continue;
            }

            grid.push(
                0,
                vec![
                    Value::string(name),
                    watcher
                        .member("pid")
                        .and_then(|pid| pid.as_i64())
                        .map(Value::int)
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::string(events.join(",")),
                ],
            )?;
        }
        Ok(grid)
    }
}
