//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

/// Lists virtual mapped sections.
pub struct VirtMap;

impl Plugin for VirtMap {
    fn name(&self) -> &'static str {
        "windows.virtmap.VirtMap"
    }

    fn description(&self) -> &'static str {
        "Lists virtual mapped sections."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Region"),
            Column::new("Start offset", ColumnType::UInt),
            Column::new("End offset", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let found = determine_map(&context, &kernel)?;

        let mut grid = TreeGrid::new(self.columns());
        for (region, ranges) in found {
            for (start, end) in ranges {
                grid.push(
                    0,
                    vec![
                        Value::string(region.clone()),
                        Value::hex(start),
                        Value::hex(end),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Returns the virtual map from a windows kernel module.
///
/// The kernel's own map of its address space.
///
/// Newer kernels list the regions outright. Older ones keep a byte per large
/// page saying which kind of region that page belongs to, and the regions are
/// recovered by collapsing runs of the same kind.
pub fn determine_map(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Result<BTreeMap<String, Vec<(u64, u64)>>> {
    // The names of the kinds come first, because without them nothing that
    // follows can be reported.
    let kinds = context
        .symbol_space
        .get_enumeration(&kernel.qualified("_MI_SYSTEM_VA_TYPE"))?;
    let kinds = kinds.as_enum().ok_or_else(|| {
        VolatilityError::Other("_MI_SYSTEM_VA_TYPE is not an enumeration".to_string())
    })?;

    let page_size = context
        .layers
        .get(&kernel.layer_name)
        .ok()
        .and_then(|layer| layer.page_size())
        .unwrap_or(0x1000);
    let entry_size = context
        .symbol_space
        .get_type(&kernel.qualified("_MMPTE"))
        .and_then(|template| context.symbol_space.size_of(&template))?;
    if entry_size == 0 {
        return Err(VolatilityError::Other(
            "_MMPTE has no size".to_string(),
        ));
    }
    let large_page_size = (page_size * page_size) / entry_size;

    let mut found: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();

    if context
        .symbol_space
        .has_symbol(&kernel.qualified("MiVisibleState"))
    {
        let state = context
            .object_from_symbol(kernel, "MiVisibleState", Some("pointer"))?
            .pointer_value()?;
        let visible = context.object(
            &kernel.qualified("_MI_VISIBLE_STATE"),
            &kernel.layer_name,
            state,
        )?;

        if let Ok(regions) = visible.member("SystemVaRegions") {
            for index in 0..regions.count()? {
                let region = regions.index(index)?;
                let (Ok(base), Ok(bytes)) = (
                    region.member("BaseAddress").and_then(|base| base.as_u64()),
                    region.member("NumberOfBytes").and_then(|bytes| bytes.as_u64()),
                ) else {
                    continue;
                };
                found
                    .entry(kinds.lookup(index as i64))
                    .or_default()
                    .push((base, bytes));
            }
            return Ok(found);
        }

        if let Ok(types) = visible.member("SystemVaType") {
            let start = system_range_start(context, kernel)?;
            return collapse_runs(kinds, large_page_size, start, &types);
        }

        return Err(VolatilityError::symbol(
            Some(kernel.symbol_table_name.clone()),
            Some("SystemVaRegions".to_string()),
            "Required structures not found".to_string(),
        ));
    }

    if context
        .symbol_space
        .has_symbol(&kernel.qualified("MiSystemVaType"))
    {
        let start = system_range_start(context, kernel)?;
        // One byte per large page, covering the rest of the address space.
        let count = (0xFFFF_FFFFu64 + 1 - start) / large_page_size;
        let address = context.symbol_offset(kernel, "MiSystemVaType")?;
        let template = context.symbol_space.get_type(&kernel.qualified("char"))?;
        let array_template = std::sync::Arc::new(
            crate::framework::objects::template::Template::Array {
                count,
                subtype: template,
            },
        );
        let array = context.object_from_template(array_template, &kernel.layer_name, address);
        return collapse_runs(kinds, large_page_size, start, &array);
    }

    Err(VolatilityError::symbol(
        Some(kernel.symbol_table_name.clone()),
        Some("MiVisibleState".to_string()),
        "Required structures not found".to_string(),
    ))
}

/// Where the kernel's own half of the address space begins.
fn system_range_start(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Result<u64> {
    context
        .object_from_symbol(kernel, "MmSystemRangeStart", Some("pointer"))?
        .pointer_value()
}

/// Turn a byte per large page into one range per run of the same kind.
fn collapse_runs(
    kinds: &Arc<crate::framework::objects::template::EnumTemplate>,
    large_page_size: u64,
    range_start: u64,
    types: &crate::framework::objects::Object,
) -> Result<BTreeMap<String, Vec<(u64, u64)>>> {
    let mut found: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    let mut start = range_start;
    let mut previous: Option<String> = None;
    let mut size = large_page_size;

    for index in 0..types.count()? {
        let Ok(value) = types.index(index).and_then(|entry| entry.as_u64()) else {
            continue;
        };
        let name = kinds.lookup(value as i64);
        if Some(&name) != previous.as_ref() {
            found.entry(name.clone()).or_default().push((start, size));
            start += size;
            size = large_page_size;
        } else {
            size += large_page_size;
        }
        previous = Some(name);
    }
    Ok(found)
}
