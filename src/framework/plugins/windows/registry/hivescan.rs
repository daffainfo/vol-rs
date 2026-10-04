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

/// Scans for registry hives present in a particular windows memory image.
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
        let mut grid = TreeGrid::new(self.columns());
        for hive in scan_hives(&context, &kernel)? {
            grid.push(0, vec![Value::hex(hive.offset())])?;
        }
        Ok(grid)
    }
}

/// Scans for hives using the poolscanner module and constraints or bigpools
/// module with tag.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
///
/// The hives memory still holds, whether or not the kernel still lists them.
///
/// A hive is far too large for the pools on a modern 64-bit kernel, so there
/// it is recorded in the big page table and found by its tag there rather than
/// by searching memory.
pub fn scan_hives(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Result<Vec<crate::framework::objects::Object>> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    if is_windows_8_1_or_later(context, kernel) && sixty_four_bit {
        let template = context
            .symbol_space
            .get_type(&kernel.qualified("_CMHIVE"))?;
        let tags = [String::from("CM10")];
        return Ok(list_big_pools(context, kernel, Some(&tags), false)?
            .into_iter()
            .map(|allocation| {
                context.object_from_template(
                    template.clone(),
                    &kernel.layer_name,
                    allocation.address,
                )
            })
            .collect());
    }

    scan_for_tag(context, kernel, b"CM10")
}
