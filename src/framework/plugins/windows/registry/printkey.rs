//! Print the keys and values under a registry path.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{
    read_key, subkeys, value_cell, values, RegistryKey,
};

pub struct PrintKey;

impl Plugin for PrintKey {
    fn name(&self) -> &'static str {
        "windows.registry.printkey.PrintKey"
    }

    fn description(&self) -> &'static str {
        "Lists the registry keys under a hive or specific key value."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new("offset", "Hive Offset", RequirementKind::Int),
            Requirement::new("key", "Key to start from", RequirementKind::String),
            Requirement::new("recurse", "Recurses through keys", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::datetime("Last Write Time"),
            Column::new("Hive Offset", ColumnType::UInt),
            Column::string("Type"),
            Column::string("Key"),
            Column::string("Name"),
            Column::bytes("Data"),
            Column::bool("Volatile"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let recurse = config.get_bool("recurse").unwrap_or(false);
        let requested_offset = config.get_int("offset").map(|value| value as u64);
        let requested_key = config.get_string("key");

        let mut grid = TreeGrid::new(self.columns());

        for hive_object in super::list_hives(&context, &kernel)? {
            if let Some(offset) = requested_offset {
                if hive_object.offset() != offset {
                    continue;
                }
            }
            let hive_offset = hive_object.offset();

            // A hive whose blocks are paged out cannot be walked. Move on
            // rather than failing the whole run.
            let Ok(hive) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };

            // A hive whose name cannot be read is still named as far as the
            // walk is concerned.
            let hive_name = hive.hive_name().unwrap_or("[NONAME]").to_string();

            // Rows are reported as they are found, so a hive that fails
            // part-way keeps what it yielded and is then marked unreadable.
            if walk_hive(
                &context,
                &hive,
                &table,
                hive_offset,
                &hive_name,
                recurse,
                requested_key.as_deref(),
                &mut grid,
            )
            .is_err()
            {
                grid.push(
                    0,
                    vec![
                        Value::unreadable(),
                        Value::hex(hive_offset),
                        Value::string("Key"),
                        Value::string(format!(
                            "{hive_name}\\{}",
                            requested_key.clone().unwrap_or_default()
                        )),
                        Value::unreadable(),
                        Value::unreadable(),
                        Value::unreadable(),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Walk one hive, reporting its keys and values as they are found.
///
/// An unreadable key or time ends the walk: the caller marks the hive, and
/// whatever was reported before the failure stands.
#[allow(clippy::too_many_arguments)]
fn walk_hive(
    context: &Arc<Context>,
    hive: &crate::framework::layers::registry::RegistryHive,
    table: &str,
    hive_offset: u64,
    hive_name: &str,
    recurse: bool,
    requested_key: Option<&str>,
    grid: &mut TreeGrid,
) -> Result<()> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;

    // The listing is of a node's children, not of the node itself, and the path
    // each row carries is the parent's, which for the root is the hive's own
    // name.
    let mut pending: Vec<(RegistryKey, String, usize)> = vec![(root, hive_name.to_string(), 1)];

    while let Some((node, path, depth)) = pending.pop() {
        // Only the requested subtree, when one was asked for.
        let wanted = requested_key
            .map(|wanted| path.contains(wanted))
            .unwrap_or(true);

        let parent_write = node.last_write_time()?;

        for child in subkeys(context, hive, table, &node)? {
            if wanted {
                grid.push(
                    depth - 1,
                    vec![
                        // A subkey is stamped with its own time, not its
                        // parent's.
                        wintime_value(child.last_write_time()?),
                        Value::hex(hive_offset),
                        Value::string("Key"),
                        Value::string(path.clone()),
                        child
                            .name()
                            .map(Value::string)
                            .unwrap_or_else(|_| Value::unreadable()),
                        Value::not_applicable(),
                        Value::Bool(child.volatile),
                    ],
                )?;
            }
            if recurse {
                let name = child.name().unwrap_or_else(|_| "-".to_string());
                pending.push((child, format!("{path}\\{name}"), depth + 1));
            }
        }

        if !wanted {
            continue;
        }
        for value in values(context, hive, table, &node)? {
            grid.push(
                depth - 1,
                vec![
                    wintime_value(parent_write),
                    Value::hex(hive_offset),
                    Value::string(value.value_type().as_str()),
                    Value::string(path.clone()),
                    value
                        .name()
                        .map(|name| {
                            // A value with no name is the key's own.
                            if name.is_empty() {
                                Value::string("(Default)")
                            } else {
                                Value::string(name)
                            }
                        })
                        .unwrap_or_else(|_| Value::unreadable()),
                    value
                        .data(hive)
                        .map(|data| value_cell(value.value_type(), &data))
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::Bool(node.volatile),
                ],
            )?;
        }
    }
    Ok(())
}
