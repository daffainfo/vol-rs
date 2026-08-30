//! Check each registry hive's cell-lookup routine for hooking.
//!
//! Every hive carries a function pointer the configuration manager calls to
//! translate a cell index into an address. Replacing it lets an attacker hide
//! or falsify registry content for every reader on the system, so a routine
//! that does not belong to the kernel is a serious finding.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::unicode_string;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::resolver::ModuleResolver;

pub struct GetCellRoutine;

impl Plugin for GetCellRoutine {
    fn name(&self) -> &'static str {
        "windows.registry.getcellroutine.GetCellRoutine"
    }

    fn description(&self) -> &'static str {
        "Reports registry hives with a hooked GetCellRoutine handler"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Hive Offset", ColumnType::UInt),
            Column::string("Hive Name"),
            Column::string("GetCellRoutine Module"),
            Column::new("GetCellRoutine Handler", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ModuleResolver::new(&context, &kernel).ok();
        let mut grid = TreeGrid::new(self.columns());

        for hive in super::list_hives(&context, &kernel)? {
            // The routine lives on the inner hive structure, which older
            // kernels expose directly on the _CMHIVE.
            let inner = hive.member("Hive").unwrap_or_else(|_| hive.clone());
            let Ok(handler) = inner
                .member("GetCellRoutine")
                .and_then(|routine| routine.pointer_value())
            else {
                continue;
            };

            let module = match (&resolver, handler) {
                (Some(resolver), address) if address != 0 => {
                    resolver.describe(&context, address).0
                }
                _ => None,
            };

            // A routine inside the kernel image is the expected case. Reporting
            // it would bury the hooked hives among the healthy ones.
            let hooked = module
                .as_deref()
                .map(|name| !name.eq_ignore_ascii_case("ntoskrnl.exe"))
                .unwrap_or(true);
            if !hooked {
                continue;
            }

            let name = ["FileFullPath", "FileUserName", "HiveRootPath"]
                .iter()
                .find_map(|member| {
                    hive.member(member)
                        .ok()
                        .and_then(|field| unicode_string(&field).ok())
                        .filter(|name| !name.is_empty())
                });

            grid.push(
                0,
                vec![
                    Value::hex(hive.offset()),
                    match name {
                        Some(name) => Value::string(name),
                        None => Value::not_applicable(),
                    },
                    // A handler owned by nothing known is exactly the finding.
                    module.map(Value::string).unwrap_or_else(Value::not_available),
                    Value::hex(handler),
                ],
            )?;
        }
        Ok(grid)
    }
}
