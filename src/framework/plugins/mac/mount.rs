//! List the mounted filesystems.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::list_mounts;

pub struct Mount;

impl Plugin for Mount {
    fn name(&self) -> &'static str {
        "mac.mount.Mount"
    }

    fn description(&self) -> &'static str {
        "A module containing a collection of plugins that produce data typically found in Mac's mount command"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Device"),
            Column::string("Mount Point"),
            Column::string("Type"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        for mount in list_mounts(&context, &kernel)? {
            grid.push(
                0,
                vec![
                    // Upstream fills the Device column from `f_mntonname` and
                    // the Mount Point column from `f_mntfromname`, which is the
                    // opposite of what those names mean. The columns are its
                    // public interface, so the values follow it.
                    mount
                        .mount_point()
                        .map(Value::string)
                        .unwrap_or_else(Value::unreadable),
                    mount.device().map(Value::string).unwrap_or_else(Value::unreadable),
                    mount
                        .filesystem_type()
                        .map(Value::string)
                        .unwrap_or_else(Value::unreadable),
                ],
            )?;
        }
        Ok(grid)
    }
}
