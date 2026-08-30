//! List the kauth scopes and their registered listeners.
//!
//! kauth is the kernel's authorisation framework: an extension registers a
//! listener on a scope and is consulted on every decision in it. That makes a
//! listener a complete view of, and veto over, the activity in its scope.
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
use crate::framework::symbols::mac::{walk_tailq, ExtensionResolver};

pub struct KauthScopes;

impl Plugin for KauthScopes {
    fn name(&self) -> &'static str {
        "mac.kauth_scopes.Kauth_scopes"
    }

    fn description(&self) -> &'static str {
        "Lists kauth scopes and their status"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::new("IData", ColumnType::UInt),
            Column::int("Listeners"),
            Column::new("Callback Address", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        let head =
            context.object_from_symbol(&kernel, "kauth_scopes", None)?;
        let scopes = walk_tailq(&head, &kernel.qualified("kauth_scope"), "ks_link")?;

        let mut grid = TreeGrid::new(self.columns());

        for scope in scopes {
            let name = scope
                .member("ks_identifier")
                .and_then(|identifier| pointer_to_string(&identifier, 128))
                .unwrap_or_default();

            // The scope's own callback runs before any listener's. A scope
            // without one is not reported.
            let callback = scope
                .member("ks_callback")
                .and_then(|callback| callback.pointer_value())
                .unwrap_or(0);
            if callback == 0 {
                continue;
            }

            // The scope holds a fixed table of listeners, of which only the
            // ones with a callback are in use.
            let listeners = match scope.member("ks_listeners") {
                Ok(list) => {
                    let slots = list.count().unwrap_or(0);
                    (0..slots)
                        .filter(|slot| {
                            list.index(*slot)
                                .and_then(|listener| listener.member("kll_callback"))
                                .and_then(|callback| callback.pointer_value())
                                .unwrap_or(0)
                                != 0
                        })
                        .count()
                }
                Err(_) => 0,
            };

            let (module, symbol) = match &resolver {
                Some(resolver) => resolver.describe(&context, callback),
                None => ("UNKNOWN".to_string(), "N/A".to_string()),
            };

            grid.push(
                0,
                vec![
                    Value::string(name),
                    scope
                        .member("ks_idata")
                        .and_then(|idata| idata.as_u64())
                        .map(Value::hex)
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::int(listeners as i64),
                    Value::hex(callback),
                    Value::string(module),
                    Value::string(symbol),
                ],
            )?;
        }
        Ok(grid)
    }
}
