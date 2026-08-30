//! Locate the per-processor control regions.
//!
//! Each logical processor has a `_KPCR`, and the kernel keeps an array of
//! pointers to their control blocks. Finding them gives a per-CPU view that
//! several other analyses build on.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct Kpcrs;

impl Plugin for Kpcrs {
    fn name(&self) -> &'static str {
        "windows.kpcrs.KPCRs"
    }

    fn description(&self) -> &'static str {
        "Print KPCR structure for each processor"
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
            Column::new("PRCB Offset", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        let mut grid = TreeGrid::new(self.columns());
        for (kpcr, prcb) in list_kpcrs(&context, &kernel)? {
            grid.push(0, vec![Value::hex(kpcr.offset()), Value::hex(prcb)])?;
        }
        Ok(grid)
    }
}

/// The processor control region of each processor.
///
/// The kernel keeps an array of pointers to the control blocks, and the region
/// itself sits a fixed distance in front of the block it contains.
pub fn list_kpcrs(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<Vec<(crate::framework::objects::Object, u64)>> {
    let kpcr_type = kernel.qualified("_KPCR");
    let kpcr_template = context.symbol_space.get_type(&kpcr_type)?;
    let relative = context
        .symbol_space
        .find_member(&kpcr_template, "Prcb")?
        .map(|(offset, _)| offset)
        .unwrap_or(0);
    // Later kernels name the current block separately from the one they hold.
    let current = if context
        .symbol_space
        .find_member(&kpcr_template, "CurrentPrcb")?
        .is_some()
    {
        "CurrentPrcb"
    } else {
        "Prcb"
    };

    let count = context
        .object_from_symbol(kernel, "KeNumberProcessors", Some("unsigned int"))
        .and_then(|value| value.as_u64())
        .unwrap_or(1);

    let block_array = context.symbol_offset(kernel, "KiProcessorBlock")?;
    let pointer_size = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8) as u64;
    let mask = context.layers.address_mask(&kernel.layer_name);

    let mut results = Vec::new();
    for index in 0..count {
        let Ok(raw) = context.layers.read(
            &kernel.layer_name,
            block_array + index * pointer_size,
            pointer_size as usize,
            false,
        ) else {
            continue;
        };
        let mut buffer = [0u8; 8];
        buffer[..raw.len()].copy_from_slice(&raw);
        let block = u64::from_le_bytes(buffer) & mask;

        // A block that cannot be read belongs to a processor the image never
        // captured.
        if block == 0 || !context.layers.is_valid(&kernel.layer_name, block, 1) {
            continue;
        }

        let Ok(kpcr) = context.object(&kpcr_type, &kernel.layer_name, block - relative) else {
            continue;
        };
        let prcb = kpcr
            .member(current)
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        results.push((kpcr, prcb));
    }
    Ok(results)
}
