//! Check the TrustedBSD policy hooks.
//!
//! TrustedBSD lets an extension register a callback for almost every security
//! decision the kernel makes. It is a legitimate mechanism that antivirus uses,
//! but also a complete interception point, so which extension owns each hook
//! matters.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::ExtensionResolver;

pub struct TrustedBsd;

impl Plugin for TrustedBsd {
    fn name(&self) -> &'static str {
        "mac.trustedbsd.Trustedbsd"
    }

    fn description(&self) -> &'static str {
        "Checks for malicious trustedbsd modules"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Member"),
            Column::string("Policy Name"),
            Column::new("Handler Address", ColumnType::UInt),
            Column::string("Handler Module"),
            Column::string("Handler Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        // Registered policies are on a list the kernel keeps.
        let head = context.object_from_symbol(&kernel, "mac_policy_list", Some("mac_policy_list"))?;
        // The table has one more slot than its highest index.
        let count = head.member("staticmax")?.as_u64()?.wrapping_add(1);
        let entries = head.member("entries")?.pointer_value()?;
        if entries == 0 {
            return Ok(TreeGrid::new(self.columns()));
        }

        let entry_template = context
            .symbol_space
            .get_type(&kernel.qualified("mac_policy_list_element"))?;
        let entry_size = context.symbol_space.size_of(&entry_template)?;

        let mut grid = TreeGrid::new(self.columns());

        for index in 0..count {
            let element = context.object_from_template(
                entry_template.clone(),
                &kernel.layer_name,
                entries + index * entry_size,
            );

            let Ok(policy) = element
                .member("mpc")
                .and_then(|mpc| mpc.dereference())
            else {
                continue;
            };

            // The policy's operations structure holds one pointer per hook. Each
            // non-null one is a decision this policy intercepts. A policy with
            // no operations decides nothing.
            let Ok(operations) = policy
                .member("mpc_ops")
                .and_then(|ops| ops.dereference())
            else {
                continue;
            };

            let name = policy
                .member("mpc_name")
                .and_then(|name| pointer_to_string(&name, 255))
                .unwrap_or_else(|_| "N/A".to_string());

            for member in operations.member_names().unwrap_or_default() {
                let Ok(handler) = operations
                    .member(&member)
                    .and_then(|hook| hook.pointer_value())
                else {
                    continue;
                };
                if handler == 0 {
                    continue;
                }

                let (module, symbol) = match &resolver {
                    Some(resolver) => resolver.describe(&context, handler),
                    None => ("UNKNOWN".to_string(), "N/A".to_string()),
                };

                grid.push(
                    0,
                    vec![
                        Value::string(member),
                        Value::string(name.clone()),
                        Value::hex(handler),
                        Value::string(module),
                        Value::string(symbol),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
