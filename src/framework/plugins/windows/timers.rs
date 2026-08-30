//! List the kernel timers that are currently armed.
//!
//! A timer gives code periodic execution without a thread of its own. A timer
//! whose routine lies outside any loaded module is running code the system has
//! no record of.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kpcrs::list_kpcrs;
use crate::framework::symbols::windows::poolscanner::is_windows_8_or_later;
use crate::framework::symbols::windows::resolver::ModuleCollection;

pub struct Timers;

/// The kinds of object a timer header may claim to be. Anything else means
/// the entry is not a timer at all.
const TIMER_TYPES: [u64; 2] = [8, 9];

impl Plugin for Timers {
    fn name(&self) -> &'static str {
        "windows.timers.Timers"
    }

    fn description(&self) -> &'static str {
        "Print kernel timers and associated module DPCs"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("DueTime"),
            Column::int("Period(ms)"),
            Column::string("Signaled"),
            Column::new("Routine", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let collection = ModuleCollection::build(&context, &kernel)?;
        let mut grid = TreeGrid::new(self.columns());

        for timer in list_timers(&context, &kernel)? {
            // A header claiming any other kind is not a timer.
            let kind = timer
                .member("Header")
                .and_then(|header| header.member("Type"))
                .and_then(|kind| kind.as_u64());
            if !matches!(kind, Ok(kind) if TIMER_TYPES.contains(&kind)) {
                continue;
            }
            // The routine the timer fires is reached through its deferred
            // procedure call, which later kernels keep encoded.
            let Ok(dpc) = decode_dpc(&context, &kernel, &timer) else {
                continue;
            };
            if dpc.offset() == 0 {
                continue;
            }
            let Ok(routine) = dpc
                .member("DeferredRoutine")
                .and_then(|routine| routine.as_u64())
            else {
                continue;
            };
            if routine == 0 {
                continue;
            }

            let due = timer
                .member("DueTime")
                .and_then(|due| {
                    Ok((
                        due.member("HighPart")?.as_i64()?,
                        due.member("LowPart")?.as_u64()?,
                    ))
                })
                .map(|(high, low)| Value::string(format!("{high:#010x}:{low:#010x}")))
                .unwrap_or_else(|_| Value::unreadable());
            let period = timer
                .member("Period")
                .and_then(|period| period.as_i64())
                .map(Value::int)
                .unwrap_or_else(|_| Value::unreadable());
            let signaled = timer
                .member("Header")
                .and_then(|header| header.member("SignalState"))
                .and_then(|state| state.as_i64())
                .map(|state| Value::string(if state != 0 { "Yes" } else { "-" }))
                .unwrap_or_else(|_| Value::unreadable());

            let owners = collection.modules_at(&context, routine);
            if owners.is_empty() {
                // A routine in no loaded module is itself the finding.
                grid.push(
                    0,
                    vec![
                        Value::hex(timer.offset()),
                        due,
                        period,
                        signaled,
                        Value::hex(routine),
                        Value::not_available(),
                        Value::not_available(),
                    ],
                )?;
                continue;
            }

            for (module, symbols) in owners {
                if symbols.is_empty() {
                    grid.push(
                        0,
                        vec![
                            Value::hex(timer.offset()),
                            due.clone(),
                            period.clone(),
                            signaled.clone(),
                            Value::hex(routine),
                            Value::string(module),
                            Value::not_available(),
                        ],
                    )?;
                    continue;
                }
                // Several symbols can name the same address.
                for symbol in symbols {
                    grid.push(
                        0,
                        vec![
                            Value::hex(timer.offset()),
                            due.clone(),
                            period.clone(),
                            signaled.clone(),
                            Value::hex(routine),
                            Value::string(module.clone()),
                            Value::string(symbol.clone()),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// Every timer the kernel is holding.
///
/// From Windows 7 on there is no single table: each processor keeps its own,
/// hanging off its control block.
fn list_timers(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Object>> {
    let mut timers = Vec::new();
    let timer_type = kernel.qualified("_KTIMER");

    if is_windows_8_or_later(context, kernel) || context.symbol_space.has_type(&kernel.qualified("_KTIMER_TABLE")) {
        for (kpcr, _) in list_kpcrs(context, kernel)? {
            let Ok(table) = kpcr
                .member("Prcb")
                .and_then(|prcb| prcb.member("TimerTable"))
            else {
                continue;
            };
            let Ok(entries) = table.member("TimerEntries") else {
                continue;
            };

            // Later kernels group the entries by expiry, so the array holds
            // arrays rather than entries.
            let grouped = table.has_member("TableState");
            for entry in entries.iter_array()? {
                let heads = if grouped {
                    entry.iter_array().unwrap_or_default()
                } else {
                    vec![entry]
                };
                for head in heads {
                    let Ok(list) = head.member("Entry") else {
                        continue;
                    };
                    timers.extend(
                        walk_list(&list, &timer_type, "TimerListEntry", true).unwrap_or_default(),
                    );
                }
            }
        }
        return Ok(timers);
    }

    // Older kernels keep one table, named by a symbol.
    let table = context.symbol_offset(kernel, "KiTimerTableListHead")?;
    let entry_type = kernel.qualified("_KTIMER_TABLE_ENTRY");
    let entry_size = context
        .symbol_space
        .get_type(&entry_type)
        .and_then(|template| context.symbol_space.size_of(&template))
        // Before Vista the table is a plain array of list heads.
        .unwrap_or(16);
    // The table is 512 entries wide on 64-bit kernels and on Vista, and 256
    // on the 32-bit kernels that came before it.
    let count = if entry_size == 16 { 256 } else { 512 };

    for index in 0..count {
        let Ok(head) = context.object(
            &kernel.qualified("_LIST_ENTRY"),
            &kernel.layer_name,
            table + index * entry_size,
        ) else {
            continue;
        };
        timers.extend(walk_list(&head, &timer_type, "TimerListEntry", true).unwrap_or_default());
    }
    Ok(timers)
}

/// The deferred procedure call a timer fires.
///
/// From Windows 7 on the pointer is stored encoded, mixed with two constants
/// the kernel keeps for the purpose and with the timer's own address, so it
/// cannot be found by scanning for it.
fn decode_dpc(context: &Arc<Context>, kernel: &Module, timer: &Object) -> Result<Object> {
    let dpc_type = kernel.qualified("_KDPC");

    let (Ok(never), Ok(always)) = (
        context.object_from_symbol(kernel, "KiWaitNever", Some("unsigned long long")),
        context.object_from_symbol(kernel, "KiWaitAlways", Some("unsigned long long")),
    ) else {
        // An older kernel stores the pointer plainly.
        return timer.member("Dpc")?.dereference();
    };
    let (never, always) = (never.as_u64()?, always.as_u64()?);

    // The encoding hides bits an address would not use, so the field is taken
    // exactly as stored.
    let stored = timer.member("Dpc")?.raw_value()?;
    let entry = (stored ^ never).rotate_left((never & 0xFF) as u32);
    let entry = (entry ^ canonicalize(context, timer.layer_name(), timer.offset())).swap_bytes();
    let address = entry ^ always;

    context.object(&dpc_type, timer.layer_name(), address)
}

/// An address in the form the processor would use it, sign-extended into the
/// half of the space it belongs to.
fn canonicalize(context: &Arc<Context>, layer_name: &str, address: u64) -> u64 {
    use crate::framework::layers::intel::IntelLayer;
    context
        .layers
        .get(layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<IntelLayer>()
                .map(|intel| intel.canonicalize(address))
        })
        .unwrap_or(address)
}
