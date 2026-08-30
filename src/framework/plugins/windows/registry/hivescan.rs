//! Scan physical memory for registry hives.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::bigpools::list_big_pools;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{is_windows_8_1_or_later, scan_for_tag};

pub struct HiveScan;

impl Plugin for HiveScan {
    fn name(&self) -> &'static str {
        "windows.registry.hivescan.HiveScan"
    }

    fn description(&self) -> &'static str {
        "Scans for registry hives present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::new("Offset", ColumnType::UInt)]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let sixty_four_bit = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8)
            == 8;

        let mut grid = TreeGrid::new(self.columns());

        // A hive is far too large for the pools on a modern 64-bit kernel, so
        // it is recorded in the big pool table rather than searched for.
        if is_windows_8_1_or_later(&context, &kernel) && sixty_four_bit {
            let tags = [String::from("CM10")];
            // An allocation is named by a kernel pointer. The hive built on it
            // is addressed by what the layer can reach.
            let mask = context.layers.address_mask(&kernel.layer_name);
            for allocation in list_big_pools(&context, &kernel, Some(&tags), false)? {
                grid.push(0, vec![Value::hex(allocation.address & mask)])?;
            }
            return Ok(grid);
        }

        for object in scan_for_tag(&context, &kernel, b"CM10")? {
            grid.push(0, vec![Value::hex(object.offset())])?;
        }
        Ok(grid)
    }
}
