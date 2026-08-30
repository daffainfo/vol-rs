//! List the kernel's large pool allocations.
//!
//! Allocations too big for the ordinary pool are tracked in a separate table
//! rather than being given a pool header, so they are enumerated from that
//! table rather than found by scanning.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::template::Template;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct BigPools;

impl Plugin for BigPools {
    fn name(&self) -> &'static str {
        "windows.bigpools.BigPools"
    }

    fn description(&self) -> &'static str {
        "List big page pools."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "tags",
                "Comma separated list of pool tags to filter pools returned",
                RequirementKind::String,
            ),
            Requirement::new(
                "show-free",
                "Show freed regions (otherwise only show allocations in use)",
                RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Allocation", ColumnType::UInt),
            Column::string("Tag"),
            Column::string("PoolType"),
            Column::new("NumberOfBytes", ColumnType::UInt),
            Column::string("Status"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // One comma separated list of tags, split the way upstream splits it.
        let wanted: Option<Vec<String>> = config
            .get_string("tags")
            .filter(|tags| !tags.is_empty())
            .map(|tags| tags.split(',').map(str::to_string).collect());

        let mut grid = TreeGrid::new(self.columns());
        // Freed allocations are left out unless the caller asks for them.
        let show_free = config.get_bool("show-free").unwrap_or(false);

        for allocation in list_big_pools(&context, &kernel, wanted.as_deref(), show_free)? {
            grid.push(
                0,
                vec![
                    Value::hex(allocation.address),
                    Value::string(allocation.tag),
                    allocation
                        .entry
                        .member("PoolType")
                        .and_then(|kind| kind.as_u64())
                        .map(|kind| Value::string(pool_type_name(&context, &kernel, kind)))
                        .unwrap_or_else(|_| Value::unreadable()),
                    allocation
                        .entry
                        .member("NumberOfBytes")
                        .and_then(|bytes| bytes.as_u64())
                        .map(Value::hex)
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::string(if allocation.free { "Free" } else { "Allocated" }),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// One live allocation from the kernel's big pool table.
pub struct BigPoolAllocation {
    /// Where the allocation begins.
    pub address: u64,
    /// The four characters the allocator was tagged with.
    pub tag: String,
    /// Whether the slot has been freed.
    pub free: bool,
    /// The table entry itself, for callers that want the rest of it.
    pub entry: crate::framework::objects::Object,
}

/// The kernel's table of allocations too large for the pools.
///
/// Several plugins look for their own structures here rather than scanning,
/// because an allocation of this size is recorded rather than searched for.
pub fn list_big_pools(
    context: &Arc<Context>,
    kernel: &Module,
    tags: Option<&[String]>,
    show_free: bool,
) -> Result<Vec<BigPoolAllocation>> {
    let mut results = Vec::new();
    // The table's address and its size are held in separate symbols.
    let table_address = context
        .object_from_symbol(kernel, "PoolBigPageTable", Some("pointer"))?
        .pointer_value()?;
    let size = context
        .object_from_symbol(kernel, "PoolBigPageTableSize", Some("unsigned long long"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    if table_address == 0 || size == 0 {
        return Ok(Vec::new());
    }

    let entry_type = kernel.qualified("_POOL_TRACKER_BIG_PAGES");
    let template = context.symbol_space.get_type(&entry_type)?;
    let entry_size = context.symbol_space.size_of(&template)?;

    // A table larger than this means the size symbol was misread.
    let count = size.min(0x100000);

    for index in 0..count {
        let entry = context.object_from_template(
            template.clone(),
            &kernel.layer_name,
            table_address + index * entry_size,
        );

        // An entry with no key is a slot that has never been used.
        if entry
            .member("Key")
            .and_then(|key| key.as_u64())
            .map(|key| key == 0)
            .unwrap_or(true)
        {
            continue;
        }
        let Ok(address) = entry.member("Va").and_then(|va| va.as_u64()) else {
            continue;
        };
        // The low bit marks a free slot. It is part of the address as the
        // table records it, and is reported as such. Only whether the slot is
        // free is read from it. A freed allocation is listed when asked for.
        let free = address & 1 != 0;
        if address & !1 == 0 || (free && !show_free) {
            continue;
        }
        let allocation = address;

        let tag = entry
            .member("Key")
            .and_then(|key| key.as_u64())
            .map(|key| {
                // The tag is four characters packed into a word. A byte
                // that is not printable is dropped rather than stood in
                // for, so a three-letter tag reads as three letters.
                (key.to_le_bytes()[..4])
                    .iter()
                    .filter(|byte| byte.is_ascii_graphic())
                    .map(|&byte| byte as char)
                    .collect::<String>()
            })
            .unwrap_or_default();

        if let Some(wanted) = tags {
            if !wanted.iter().any(|candidate| *candidate == tag) {
                continue;
            }
        }

        results.push(BigPoolAllocation {
            address: allocation,
            tag,
            free,
            entry,
        });
    }
    Ok(results)
}

/// What the kernel calls a pool type.
///
/// Several names share a value in the kernel's own enumeration, so the first of
/// them is used. Which, symbol files being written in name order, is the
/// alphabetically first.
fn pool_type_name(context: &Arc<Context>, kernel: &Module, value: u64) -> String {
    let names = context
        .symbol_space
        .get_type(&kernel.qualified("_POOL_TYPE"))
        .ok()
        .and_then(|template| match template.as_ref() {
            Template::Enumeration(enumeration) => {
                let mut matching: Vec<&String> = enumeration
                    .choices
                    .iter()
                    .filter(|(_, held)| **held as u64 == value)
                    .map(|(name, _)| name)
                    .collect();
                matching.sort();
                matching.first().map(|name| (*name).clone())
            }
            _ => None,
        });
    names.unwrap_or_else(|| format!("Unknown choice {value}"))
}
