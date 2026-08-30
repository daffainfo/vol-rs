//! Check the ftrace subsystem for callbacks attached to kernel functions.
//!
//! ftrace can attach a callback to almost any kernel function. It is the
//! kernel's own tracing mechanism, and equally a supported way to hook any
//! function without patching code, so what is registered matters.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::resolver::ModuleResolver;

pub struct CheckFtrace;

impl Plugin for CheckFtrace {
    fn name(&self) -> &'static str {
        "linux.tracing.ftrace.CheckFtrace"
    }

    fn description(&self) -> &'static str {
        "Detect ftrace hooking"
    }

    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Investigate the ftrace infrastructure to uncover kernel attached \
             callbacks, which can be leveraged to hook kernel functions and modify \
             their behaviour.",
        )
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "show_ftrace_flags",
                "Show ftrace flags associated with an ftrace_ops struct",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        columns_for(false)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let show_flags = config.get_bool("show_ftrace_flags").unwrap_or(false);
        let resolver = ModuleResolver::new(&context, &kernel).ok();
        let mask = context.layers.address_mask(&kernel.layer_name);

        // The registered operations form a singly-linked list whose end is a
        // sentinel the kernel keeps at a known symbol.
        let mut address = context
            .object_from_symbol(&kernel, "ftrace_ops_list", None)?
            .pointer_value()?;
        let terminator = context
            .symbol_offset(&kernel, "ftrace_list_end")
            .map(|address| address & mask)
            .unwrap_or(0);

        let template = context.symbol_space.get_type(&kernel.qualified("ftrace_ops"))?;
        let entry_type = context
            .symbol_space
            .get_type(&kernel.qualified("ftrace_func_entry"))?;

        let mut grid = TreeGrid::new(columns_for(show_flags));
        let mut seen: HashSet<u64> = HashSet::new();

        while address != 0 && address != terminator {
            if !seen.insert(address) {
                break;
            }
            let operations =
                context.object_from_template(template.clone(), &kernel.layer_name, address);
            let Ok(callback) = operations
                .member("func")
                .and_then(|func| func.pointer_value())
            else {
                break;
            };

            // Which module the callback belongs to, and where that module sits.
            let (module, symbol) = match &resolver {
                Some(resolver) => resolver.describe(&context, callback),
                None => (None, None),
            };
            let module_base = match (&resolver, &module) {
                (Some(resolver), Some(name)) => resolver
                    .modules()
                    .iter()
                    .find(|entry| &entry.name == name)
                    .map(|entry| entry.base)
                    .or_else(|| resolver.kernel_base()),
                _ => None,
            };

            // What state the kernel records for this hook.
            let flags = operations
                .member("flags")
                .and_then(|value| value.as_u64())
                .map(describe_ftrace_flags)
                .unwrap_or_default();

            // One row per function the operation is attached to.
            for hooked in filter_entries(&context, &kernel, &operations, &entry_type) {
                let hook = hooked & mask;
                let names = resolver
                    .as_ref()
                    .and_then(|resolver| resolver.symbol_for(&context, hook));

                let mut row = vec![
                        Value::hex(address),
                        symbol
                            .clone()
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                        Value::hex(callback),
                        names.map(Value::string).unwrap_or_else(Value::not_available),
                        module
                            .clone()
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                        module_base.map(Value::hex).unwrap_or_else(Value::not_available),
                ];
                if show_flags {
                    row.push(Value::string(flags.clone()));
                }
                grid.push(0, row)?;
            }

            let Ok(next) = operations.member("next").and_then(|next| next.pointer_value()) else {
                break;
            };
            address = next;
        }
        Ok(grid)
    }
}

/// The columns, with the hook state included only when it was asked for.
fn columns_for(show_flags: bool) -> Vec<Column> {
    let mut columns = vec![
        Column::new("ftrace_ops address", ColumnType::UInt),
        Column::string("Callback"),
        Column::new("Callback address", ColumnType::UInt),
        Column::string("Hooked symbols"),
        Column::string("Module"),
        Column::new("Module address", ColumnType::UInt),
    ];
    if show_flags {
        columns.push(Column::string("Flags"));
    }
    columns
}

/// The names of the state bits an ftrace operation carries.
fn describe_ftrace_flags(flags: u64) -> String {
    const NAMES: [&str; 19] = [
        "FTRACE_OPS_FL_ENABLED",
        "FTRACE_OPS_FL_DYNAMIC",
        "FTRACE_OPS_FL_SAVE_REGS",
        "FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED",
        "FTRACE_OPS_FL_RECURSION",
        "FTRACE_OPS_FL_STUB",
        "FTRACE_OPS_FL_INITIALIZED",
        "FTRACE_OPS_FL_DELETED",
        "FTRACE_OPS_FL_ADDING",
        "FTRACE_OPS_FL_REMOVING",
        "FTRACE_OPS_FL_MODIFYING",
        "FTRACE_OPS_FL_ALLOC_TRAMP",
        "FTRACE_OPS_FL_IPMODIFY",
        "FTRACE_OPS_FL_PID",
        "FTRACE_OPS_FL_RCU",
        "FTRACE_OPS_FL_TRACE_ARRAY",
        "FTRACE_OPS_FL_PERMANENT",
        "FTRACE_OPS_FL_DIRECT",
        "FTRACE_OPS_FL_SUBOP",
    ];
    NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| flags & (1 << bit) != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<&str>>()
        .join(",")
}

/// The addresses an ftrace operation is attached to.
///
/// The filter is a hash table, but the reference implementation follows only
/// the chain hanging off its first bucket, so this does the same.
fn filter_entries(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    operations: &crate::framework::objects::Object,
    entry_type: &std::sync::Arc<crate::framework::objects::template::Template>,
) -> Vec<u64> {
    let hash = operations
        .member("func_hash")
        .and_then(|hash| hash.dereference())
        .and_then(|hash| hash.member("filter_hash"))
        .or_else(|_| operations.member("filter_hash"))
        .and_then(|hash| hash.dereference());
    let Ok(hash) = hash else {
        return Vec::new();
    };

    let Ok(mut current) = hash
        .member("buckets")
        .and_then(|buckets| buckets.dereference())
        .and_then(|bucket| bucket.member("first"))
        .and_then(|first| first.pointer_value())
    else {
        return Vec::new();
    };

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    while current != 0 && seen.insert(current) && results.len() < 4096 {
        let entry = context.object_from_template(entry_type.clone(), &kernel.layer_name, current);
        match entry.member("ip").and_then(|ip| ip.as_u64()) {
            Ok(ip) => results.push(ip),
            Err(_) => break,
        }
        match entry
            .member("hlist")
            .and_then(|node| node.member("next"))
            .and_then(|next| next.pointer_value())
        {
            Ok(next) => current = next,
            Err(_) => break,
        }
    }
    results
}

