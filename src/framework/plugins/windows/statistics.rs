//! Count what the kernel's address space actually maps.
//!
//! Walking every page of the kernel's address space says how much of it a
//! capture recovered: how many pages are present, how many the system had
//! written to its page file, and how many the tables describe but the image
//! does not contain.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::intel::IntelLayer;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};

/// What a failed translation says: whether the page was swapped out, and how
/// much of the address space the failing level covers.
fn fault_of(error: &crate::error::VolatilityError) -> Option<(bool, u32)> {
    use crate::error::{AddressFault, VolatilityError};
    match error {
        VolatilityError::InvalidAddress { fault, .. } => match fault {
            AddressFault::Swapped { invalid_bits, .. } => Some((true, *invalid_bits)),
            AddressFault::Paged { invalid_bits, .. } => Some((false, *invalid_bits)),
            AddressFault::Invalid => None,
        },
        _ => None,
    }
}

pub struct Statistics;

impl Plugin for Statistics {
    fn name(&self) -> &'static str {
        "windows.statistics.Statistics"
    }

    fn description(&self) -> &'static str {
        "Lists statistics about the memory space."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("Valid pages (all)"),
            Column::int("Valid pages (large)"),
            Column::int("Swapped Pages (all)"),
            Column::int("Swapped Pages (large)"),
            Column::int("Invalid Pages (all)"),
            Column::int("Invalid Pages (large)"),
            Column::int("Other Invalid Pages (all)"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let layer_name = config
            .get_string("primary")
            .unwrap_or_else(|| "base".to_string());
        let layer = context.layers.get(&layer_name)?;

        let mut pages = 0i64;
        let mut large_pages = 0i64;
        let mut swapped = 0i64;
        let mut large_swapped = 0i64;
        let mut invalid = 0i64;
        let mut large_invalid = 0i64;
        let mut other_invalid = 0i64;

        if let Some(intel) = layer.as_any().downcast_ref::<IntelLayer>() {
            // The step the walk expects is a whole register's worth of address
            // space, so on any real machine every page it meets is smaller.
            let expected: u128 = 1u128 << intel.config().bits_per_register;
            let maximum = layer.maximum_address() as u128;
            let base = intel.base_layer_name().to_string();

            let mut address: u128 = 0;
            while address < maximum {
                // The whole of the rest of the space is asked for at once, so
                // the answer is whatever the first page that is not there says.
                let requested = (expected * 2).min(u64::MAX as u128) as u64;
                let size: u128 = match layer.mapping(
                    &context.layers,
                    address as u64,
                    requested,
                    false,
                ) {
                    Ok(entries) => {
                        let Some(first) = entries.first() else {
                            break;
                        };
                        if first.layer != base {
                            swapped += 1;
                        } else {
                            pages += 1;
                        }
                        let size = first.size as u128;
                        if size > expected {
                            large_pages += 1;
                        }
                        size
                    }
                    Err(error) => {
                        match fault_of(&error) {
                            Some((true, bits)) => {
                                swapped += 1;
                                let size = 1u128 << bits;
                                if size != expected {
                                    large_swapped += 1;
                                }
                                size
                            }
                            Some((false, bits)) => {
                                invalid += 1;
                                let size = 1u128 << bits;
                                if size != expected {
                                    large_invalid += 1;
                                }
                                size
                            }
                            None => {
                                other_invalid += 1;
                                expected
                            }
                        }
                    }
                };
                address += size;
            }
        }

        let mut grid = TreeGrid::new(self.columns());
        grid.push(
            0,
            vec![
                Value::int(pages),
                Value::int(large_pages),
                Value::int(swapped),
                Value::int(large_swapped),
                Value::int(invalid),
                Value::int(large_invalid),
                Value::int(other_invalid),
            ],
        )?;
        Ok(grid)
    }
}
