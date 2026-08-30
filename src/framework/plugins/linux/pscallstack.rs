//! Recover the kernel call stack of each thread.
//!
//! A task's kernel stack holds return addresses left by the calls that led to
//! where it is now. Resolving those to symbols shows what each thread was doing
//! when the capture was taken, and an address resolving to no known module is a
//! sign of code the kernel has no record of.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks_filtered;
use crate::framework::plugins::linux::kallsyms::KallsymsTable;

pub struct PsCallStack;

/// A kernel stack is two pages on x86-64.
const STACK_SIZE: usize = 0x4000;

impl Plugin for PsCallStack {
    fn name(&self) -> &'static str {
        "linux.pscallstack.PsCallStack"
    }

    fn description(&self) -> &'static str {
        "Enumerates the call stack of each task"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "unresolved",
                "Include unresolved stack values",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("TID"),
            Column::string("Comm"),
            Column::int("Position"),
            Column::new("Address", ColumnType::UInt),
            Column::new("Value", ColumnType::UInt),
            Column::string("Name"),
            Column::string("Type"),
            Column::string("Module"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let include_unresolved = config.get_bool("unresolved").unwrap_or(false);
        let mask = context.layers.address_mask(&kernel.layer_name);

        // A return address points into the middle of a function, so the lookup
        // has to find which symbol's range contains it.
        let table = KallsymsTable::load(&context, &kernel)?;
        let mut symbols = table.decode(&context, &kernel)?;
        // Sorted by address only, so symbols sharing one keep the order the
        // kernel lists them in and the first of a group is reported.
        symbols.sort_by_key(|symbol| symbol.address & mask);

        // Only an address inside the kernel's own code can name a function.
        let marker = |name: &str| context.symbol_offset(&kernel, name).ok().map(|a| a & mask);
        let text = (marker("_stext"), marker("_etext"));
        let init_text = (marker("_sinittext"), marker("_einittext"));
        let in_kernel_text = |address: u64| {
            let within = |range: (Option<u64>, Option<u64>)| match range {
                (Some(start), Some(end)) => (start..end).contains(&address),
                _ => false,
            };
            within(text) || within(init_text)
        };

        let mut grid = TreeGrid::new(self.columns());

        // The filter selects processes. A selected process brings its threads
        // with it, whatever their own ids.
        let selected =
            |task: &crate::framework::symbols::linux::Task| match task.tid() {
                Ok(tid) => pid_matches(&filter, tid),
                Err(_) => false,
            };

        for task in list_tasks_filtered(&context, &kernel, true, &selected)? {
            let Ok(tid) = task.tid() else { continue };
            let comm = task.comm().unwrap_or_default();

            // A user process's stack is read through its own address space. A
            // kernel thread has none and uses the kernel's.
            let layer = if task.is_kernel_thread() {
                kernel.layer_name.clone()
            } else {
                match task.process_layer() {
                    Ok(Some(layer)) => layer,
                    _ => continue,
                }
            };

            let Ok(base) = task
                .object
                .member("stack")
                .and_then(|stack| stack.pointer_value())
            else {
                continue;
            };
            // The stack pointer is stored as a plain integer, so the base is
            // sign-extended back to match it before they are compared.
            let base = canonical(base);
            let top = base + STACK_SIZE as u64;

            // The walk starts where the thread's stack pointer was left.
            let Ok(pointer) = task
                .object
                .member("thread")
                .and_then(|thread| thread.member("sp"))
                .and_then(|sp| sp.as_u64())
            else {
                continue;
            };
            if !(base..top).contains(&pointer) {
                continue;
            }

            let mut current = pointer;
            let mut position = 0i64;
            while current < top {
                let Ok(raw) = context.layers.read(&layer, current, 8, false) else {
                    position += 1;
                    current += 8;
                    continue;
                };
                let value = u64::from_le_bytes(raw.try_into().unwrap());
                if value == 0 {
                    position += 1;
                    current += 8;
                    continue;
                }

                let masked = value & mask;
                let found = if in_kernel_text(masked) {
                    containing_symbol(&symbols, masked, mask)
                } else {
                    None
                };
                if let Some((name, letter)) = found {
                    grid.push(
                        0,
                        vec![
                            Value::int(tid as i64),
                            Value::string(comm.clone()),
                            Value::int(position),
                            Value::hex(current & mask),
                            Value::hex(value & mask),
                            Value::string(name),
                            Value::string(letter.to_string()),
                            Value::string("kernel"),
                        ],
                    )?;
                } else if include_unresolved {
                    grid.push(
                        0,
                        vec![
                            Value::int(tid as i64),
                            Value::string(comm.clone()),
                            Value::int(position),
                            Value::hex(current & mask),
                            Value::hex(value & mask),
                            Value::not_available(),
                            Value::not_available(),
                            Value::not_available(),
                        ],
                    )?;
                }

                position += 1;
                current += 8;
            }
        }
        Ok(grid)
    }
}

/// The symbol whose range contains `address`, with its `nm` type letter.
fn containing_symbol(
    symbols: &[crate::framework::plugins::linux::kallsyms::Symbol],
    address: u64,
    mask: u64,
) -> Option<(String, char)> {
    let index = symbols.partition_point(|symbol| (symbol.address & mask) <= address);
    if index == 0 {
        return None;
    }
    // Symbols sharing an address are aliases. The first of them is reported.
    let mut first = index - 1;
    let start = symbols[first].address & mask;
    while first > 0 && (symbols[first - 1].address & mask) == start {
        first -= 1;
    }
    let symbol = &symbols[first];

    // A symbol runs to wherever the next one begins.
    let end = symbols
        .get(index)
        .map(|next| next.address & mask)
        .unwrap_or(u64::MAX);
    (address < end).then(|| (symbol.name.clone(), symbol.letter))
}

/// Sign-extend a kernel address the way the layer canonicalises it.
fn canonical(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xFFFF_0000_0000_0000
    } else {
        address & 0x0000_FFFF_FFFF_FFFF
    }
}
