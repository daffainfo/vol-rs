//! List services from the controller's own list, and find the ones it hides.
//!
//! The service controller keeps every service on a linked list reachable from a
//! marker inside its own executable. Walking that list is what the system
//! itself does, so a service present in memory but absent from the walk is one
//! something has unlinked, which is what these two views compare.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::svcscan::{
    prerequisites, service_columns, service_list, service_scan,
};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct SvcList;

impl Plugin for SvcList {
    fn name(&self) -> &'static str {
        "windows.svclist.SvcList"
    }

    fn description(&self) -> &'static str {
        "Lists services contained with the services.exe doubly linked list of services"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        service_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let (table, registry) = prerequisites(&context, &kernel)?;

        let mut grid = TreeGrid::new(self.columns());
        for row in service_list(&context, &kernel, &physical, &table, &registry)? {
            grid.push(0, row)?;
        }
        Ok(grid)
    }
}

/// Services that scanning finds but the controller's own list does not.
pub struct SvcDiff {
    /// The name this view is registered under, since it is reachable at two.
    pub name: &'static str,
}

impl Plugin for SvcDiff {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        // The older of the two names is marked as on its way out.
        if self.name.starts_with("windows.svcdiff") {
            "Compares services found through list walking versus scanning to find rootkits \
             (deprecated)."
        } else {
            "Compares services found through list walking versus scanning to find rootkits"
        }
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        service_columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let (table, registry) = prerequisites(&context, &kernel)?;

        if !crate::framework::plugins::windows::svcscan::supports_service_list(&context, &kernel) {
            log::warn!(
                "This plugin only supports Windows 10 version 15063+ 64bit Windows memory samples"
            );
            return Ok(TreeGrid::new(self.columns()));
        }

        let scanned = service_scan(&context, &kernel, &physical, &table, &registry)?;
        let listed = service_list(&context, &kernel, &physical, &table, &registry)?;

        // A service is recognised by its name, so one record standing in for
        // another spelling of the same service is not reported as hidden.
        let listed_names: Vec<String> = listed.iter().filter_map(service_name).collect();

        let mut grid = TreeGrid::new(self.columns());
        let mut reported: Vec<String> = Vec::new();
        for row in scanned {
            let Some(name) = service_name(&row) else {
                continue;
            };
            if listed_names.contains(&name) || reported.contains(&name) {
                continue;
            }
            reported.push(name);
            grid.push(0, row)?;
        }
        Ok(grid)
    }
}

/// The name a service row carries.
fn service_name(row: &Vec<Value>) -> Option<String> {
    match row.get(6) {
        Some(Value::Str(name)) => Some(name.clone()),
        _ => None,
    }
}
