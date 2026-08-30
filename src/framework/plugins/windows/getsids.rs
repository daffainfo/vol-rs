//! Report the SIDs owning each process.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;
use crate::framework::plugins::windows::registry;
use crate::framework::symbols::windows::registry as registry_symbols;
use crate::framework::symbols::windows::sid_data;

pub struct GetSids;

impl Plugin for GetSids {
    fn name(&self) -> &'static str {
        "windows.getsids.GetSIDs"
    }

    fn description(&self) -> &'static str {
        "Print the SIDs owning each process"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::string("SID"),
            Column::string("Name"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        // The users a machine knows are named in its registry.
        let users = user_names(&context, &kernel).unwrap_or_default();
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            for sid in process.sids().unwrap_or_default() {
                // A fixed identifier first, then the service accounts, then
                // the users the registry names, and finally the patterns for
                // identifiers that carry a domain in the middle.
                let resolved = sid_data::well_known(&sid)
                    .or_else(|| sid_data::service(&sid))
                    .map(|name| Value::string(name))
                    .or_else(|| users.get(&sid).map(|name| Value::string(name.clone())))
                    .or_else(|| sid_data::by_pattern(&sid).map(Value::string))
                    .unwrap_or_else(Value::not_available);
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::string(sid),
                        resolved,
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The users this machine knows, as its registry names them.
///
/// Each profile is a subkey named after the account's identifier, holding the
/// path of that account's profile directory. The last part of the path is the
/// name a person would recognise.
fn user_names(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<std::collections::HashMap<String, String>> {
    const PROFILES: &str = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

    let mut users = std::collections::HashMap::new();
    for hive_object in registry::list_hives(context, kernel)? {
        let Ok(hive) = registry::open_hive(context, kernel, hive_object) else {
            continue;
        };
        // Only the software hive carries the profile list.
        if !hive
            .hive_name()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("config\\software")
        {
            continue;
        }

        let table = kernel.symbol_table_name.clone();
        let Ok(root) = registry_symbols::read_key(
            context,
            &hive,
            &table,
            hive.root_cell_offset(),
            String::new(),
        ) else {
            continue;
        };

        // Descend to the profile list rather than walking the whole hive.
        let mut key = root;
        let mut found = true;
        for component in PROFILES.split('\\') {
            let children = registry_symbols::subkeys(context, &hive, &table, &key)
                .unwrap_or_default();
            match children.into_iter().find(|child| {
                child
                    .name()
                    .map(|name| name.eq_ignore_ascii_case(component))
                    .unwrap_or(false)
            }) {
                Some(child) => key = child,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if !found {
            continue;
        }

        // Each profile is named after the account it belongs to.
        for profile in registry_symbols::subkeys(context, &hive, &table, &key).unwrap_or_default() {
            let Ok(identifier) = profile.name() else {
                continue;
            };
            for value in
                registry_symbols::values(context, &hive, &table, &profile).unwrap_or_default()
            {
                if value.name().unwrap_or_default() != "ProfileImagePath" {
                    continue;
                }
                if let Ok(path) = value.decoded(&hive) {
                    if let Some(name) = path.trim_end_matches('\0').rsplit('\\').next() {
                        users.insert(identifier.clone(), name.to_string());
                    }
                }
            }
        }
    }
    Ok(users)
}
