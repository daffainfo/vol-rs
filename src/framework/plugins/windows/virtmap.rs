//! Report the kernel's named virtual memory regions.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

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

        // The kernel keeps the map of its own address space in one structure,
        // named by a symbol that points at it.
        let state = context
            .object_from_symbol(&kernel, "MiVisibleState", Some("pointer"))?
            .pointer_value()?;
        let visible = context.object(
            &kernel.qualified("_MI_VISIBLE_STATE"),
            &kernel.layer_name,
            state,
        )?;

        let kinds = context
            .symbol_space
            .get_type(&kernel.qualified("_MI_SYSTEM_VA_TYPE"))?;
        let kinds = kinds
            .as_enum()
            .ok_or_else(|| VolatilityError::Other("_MI_SYSTEM_VA_TYPE is not an enumeration".into()))?;

        // Each region is named by its index into the kernel's own list of the
        // kinds of address space it keeps.
        let regions = visible.member("SystemVaRegions")?;
        let mut found: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
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
