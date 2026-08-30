//! List drivers the kernel has unloaded.
//!
//! Windows keeps a small ring of recently unloaded drivers for crash analysis.
//! A driver that ran and then unloaded leaves no other trace, so this is often
//! the only record that it was ever present.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct UnloadedModules;

impl Plugin for UnloadedModules {
    fn name(&self) -> &'static str {
        "windows.unloadedmodules.UnloadedModules"
    }

    fn description(&self) -> &'static str {
        "Lists the unloaded kernel modules."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::new("StartAddress", ColumnType::UInt),
            Column::new("EndAddress", ColumnType::UInt),
            Column::datetime("Time"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            let description = format!("Unloaded Module: {}", text(&values[0]));
            timeline.push(description, TimeKind::Changed, values[3].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        let sixty_four_bit = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8)
            == 8;

        // The kernel records how many slots of the ring it has used. A count
        // beyond any plausible number means the field was smeared, and the
        // whole ring is read instead.
        let counter_type = if sixty_four_bit {
            "unsigned long long"
        } else {
            "unsigned long"
        };
        let mut count = context
            .object_from_symbol(&kernel, "MmLastUnloadedDriver", Some(counter_type))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        if count > 1024 {
            log::warn!("Implausible unloaded driver count {count}; reading 1024 entries");
            count = 1024;
        }

        let table_address = context.symbol_offset(&kernel, "MmUnloadedDrivers")?;
        // The table is named by a plain machine word, so it is masked to the
        // bits the layer addresses just as a typed pointer would be.
        let pointer = context
            .object(&kernel.qualified("pointer"), &kernel.layer_name, table_address)?
            .as_u64()?
            & context.layers.address_mask(&kernel.layer_name);
        if pointer == 0 {
            return Ok(grid);
        }

        // The entry type is not in the kernel's own symbols. It ships as its
        // own small file, which refers back to the kernel's types.
        let table = if sixty_four_bit {
            "unloadedmodules-x64"
        } else {
            "unloadedmodules-x86"
        };
        context.ensure_table(table, "windows", table)?;
        context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;

        let template = context.symbol_space.get_type(&format!("{table}!_UNLOADED_DRIVER"))?;
        let size = context.symbol_space.size_of(&template)?;
        let mask = context.layers.address_mask(&kernel.layer_name);
        let kernel_space_start = kernel_space_start(&context, &kernel);

        for index in 0..count {
            let entry = context.object_from_template(
                template.clone(),
                &kernel.layer_name,
                pointer + index * size,
            );

            let (Ok(start), Ok(end), Ok(time), Ok(name)) = (
                entry.member("StartAddress").and_then(|value| value.as_u64()),
                entry.member("EndAddress").and_then(|value| value.as_u64()),
                entry.member("CurrentTime").and_then(|value| value.as_u64()),
                entry.member("Name").and_then(|name| unicode_string(&name)),
            ) else {
                continue;
            };
            let (start, end) = (start & mask, end & mask);

            // A real entry names a page-aligned range inside kernel space and
            // carries a time. Anything else is an unused or smeared slot.
            if time <= 1024
                || start <= kernel_space_start
                || start & 0xFFF != 0
                || end & 0xFFF != 0
                || end <= kernel_space_start
            {
                continue;
            }

            grid.push(
                0,
                vec![
                    Value::string(name),
                    Value::hex(start),
                    Value::hex(end),
                    wintime_value(time),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Where kernel space begins, which is what tells a real pointer from a
/// smeared one.
fn kernel_space_start(context: &Arc<Context>, kernel: &Module) -> u64 {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let (type_name, default) = if sixty_four_bit {
        ("unsigned long long", 0xFFFF_8000_0000_0000u64)
    } else {
        ("unsigned long", 0x8000_0000)
    };
    // The kernel states where its own space starts. The architectural value
    // stands in when that word cannot be read.
    context
        .object_from_symbol(kernel, "MmSystemRangeStart", Some(type_name))
        .and_then(|value| value.as_u64())
        .map(|value| value & context.layers.address_mask(&kernel.layer_name))
        .unwrap_or(default & context.layers.address_mask(&kernel.layer_name))
}
