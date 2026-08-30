//! List the kernel's sysctl knobs and their handlers.
//!
//! sysctl entries expose kernel state and let it be changed. A handler owned by
//! no loaded extension has been redirected, which lets an attacker intercept or
//! falsify what the system reports about itself.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::ExtensionResolver;

pub struct CheckSysctl;

/// Guard against a corrupt tree. The real set is a few thousand entries.
const MAX_ENTRIES: usize = 20_000;

/// What kind of value a sysctl entry holds, as the kernel records it.
const CTL_TYPES: &[&str] = &[
    "",
    "CTLTYPE_NODE",
    "CTLTYPE_INT",
    "CTLTYPE_STRING",
    "CTLTYPE_QUAD",
    "CTLTYPE_OPAQUE",
];

impl Plugin for CheckSysctl {
    fn name(&self) -> &'static str {
        "mac.check_sysctl.Check_sysctl"
    }

    fn description(&self) -> &'static str {
        "Check sysctl handlers for hooks."
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
            Column::int("Number"),
            Column::string("Perms"),
            Column::new("Handler Address", ColumnType::UInt),
            Column::string("Value"),
            Column::string("Handler Module"),
            Column::string("Handler Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        let head =
            context.object_from_symbol(&kernel, "sysctl__children", None)?;

        let mut entries = Vec::new();
        walk_oid_list(&context, &kernel, &head, false, 0, &mut entries)?;

        let mut grid = TreeGrid::new(self.columns());
        for (entry, name, value) in entries {
            let handler = entry
                .member("oid_handler")
                .and_then(|handler| handler.pointer_value())
                .unwrap_or(0);

            let (module, symbol) = match &resolver {
                Some(resolver) => resolver.describe(&context, handler),
                None => ("UNKNOWN".to_string(), "N/A".to_string()),
            };

            grid.push(
                0,
                vec![
                    Value::string(name),
                    entry
                        .member("oid_number")
                        .and_then(|number| number.as_i64())
                        .map(Value::int)
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::string(permissions(&entry)),
                    Value::hex(handler),
                    Value::string(value),
                    Value::string(module),
                    Value::string(symbol),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Follow one list of sysctl entries, and the lists hanging below it.
///
/// A list reached from an entry above it starts at its second member, which is
/// where the reference implementation begins reading.
fn walk_oid_list(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    head: &Object,
    nested: bool,
    depth: usize,
    results: &mut Vec<(Object, String, String)>,
) -> Result<()> {
    // The tree is only a few levels deep. A longer chain means corruption.
    if depth > 8 {
        return Ok(());
    }

    let template = context.symbol_space.get_type(&kernel.qualified("sysctl_oid"))?;
    let mut seen: HashSet<u64> = HashSet::new();

    let mut address = head
        .member("slh_first")
        .and_then(|first| first.pointer_value())
        .unwrap_or(0);
    if nested {
        if address == 0 {
            return Ok(());
        }
        let first = context.object_from_template(template.clone(), &kernel.layer_name, address);
        let Ok(next) = first
            .member("oid_link")
            .and_then(|link| link.member("sle_next"))
            .and_then(|next| next.pointer_value())
        else {
            return Ok(());
        };
        address = next;
    }

    while address != 0 && results.len() < MAX_ENTRIES {
        if !seen.insert(address) {
            break;
        }
        let entry = context.object_from_template(template.clone(), &kernel.layer_name, address);

        // A list ends at the first entry without a name.
        let name = entry
            .member("oid_name")
            .and_then(|name| pointer_to_string(&name, 128))
            .unwrap_or_default();
        if name.is_empty() {
            break;
        }

        let kind = entry
            .member("oid_kind")
            .and_then(|kind| kind.as_u64())
            .unwrap_or(0);
        let argument = entry
            .member("oid_arg1")
            .and_then(|argument| argument.pointer_value())
            .unwrap_or(0);

        let value = if argument == 0 {
            // An entry with nowhere to read from is one of the few the kernel
            // keeps in a variable of its own.
            global_value(context, kernel, &name)
        } else {
            match kind & 0xF {
                // A node holds the list below it rather than a value, and only
                // a node without a handler of its own is followed.
                1 => {
                    let handler = entry
                        .member("oid_handler")
                        .and_then(|handler| handler.pointer_value())
                        .unwrap_or(0);
                    if handler == 0 {
                        if let Ok(children) = entry
                            .member("oid_arg1")
                            .and_then(|argument| argument.dereference())
                            .and_then(|list| list.cast(&kernel.qualified("sysctl_oid_list")))
                        {
                            walk_oid_list(context, kernel, &children, true, depth + 1, results)?;
                        }
                    }
                    "Node".to_string()
                }
                2 | 4 | 5 => context
                    .layers
                    .read(&kernel.layer_name, argument, 4, false)
                    .map(|raw| i32::from_le_bytes(raw.try_into().unwrap()).to_string())
                    .unwrap_or_else(|_| "-1".to_string()),
                3 => entry
                    .member("oid_arg1")
                    .and_then(|argument| pointer_to_string(&argument, 64))
                    .unwrap_or_default(),
                // Anything else is named by its type rather than its value.
                other => CTL_TYPES.get(other as usize).copied().unwrap_or("").to_string(),
            }
        };

        let next = entry
            .member("oid_link")
            .and_then(|link| link.member("sle_next"))
            .and_then(|next| next.pointer_value())
            .unwrap_or(0);

        results.push((entry, name, value));
        address = next;
    }
    Ok(())
}

/// The value of a sysctl the kernel keeps in a variable of its own.
fn global_value(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    name: &str,
) -> String {
    let symbol = match name {
        "hostname" => "hostname",
        "nisdomainname" => "domainname",
        _ => return String::new(),
    };
    context
        .object_from_symbol(kernel, symbol, None)
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

/// Render an entry's access flags.
fn permissions(entry: &Object) -> String {
    let kind = entry
        .member("oid_kind")
        .and_then(|kind| kind.as_u64())
        .unwrap_or(0);
    // The top two bits of oid_kind carry read and write permission. The third
    // position marks an entry the kernel locks against concurrent access.
    let mut text = String::with_capacity(3);
    text.push(if kind & 0x8000_0000 != 0 { 'R' } else { '-' });
    text.push(if kind & 0x4000_0000 != 0 { 'W' } else { '-' });
    text.push(if kind & 0x0080_0000 != 0 { 'L' } else { '-' });
    text
}


