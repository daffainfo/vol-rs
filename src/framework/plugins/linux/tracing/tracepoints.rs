//! Check the kernel's tracepoints for attached probes.
//!
//! A tracepoint is a fixed instrumentation site the kernel exposes. Attaching a
//! probe to one gives a callback on every hit, which is a supported hooking
//! mechanism and therefore worth enumerating.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::resolver::ModuleResolver;

pub struct CheckTracepoints;

/// A probe list longer than this means the structure was misread.
const MAX_PROBES: u64 = 64;

impl Plugin for CheckTracepoints {
    fn name(&self) -> &'static str {
        "linux.tracing.tracepoints.CheckTracepoints"
    }

    fn description(&self) -> &'static str {
        "Detect tracepoints hooking"
    }

    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Investigate the tracepoints subsystem to uncover kernel attached \
             probes, which can be leveraged to hook kernel functions and modify \
             their behaviour.",
        )
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("tracepoint"),
            Column::new("tracepoint address", ColumnType::UInt),
            Column::string("Probe"),
            Column::new("Probe address", ColumnType::UInt),
            Column::int("Probe priority"),
            Column::string("Module"),
            Column::new("Module address", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ModuleResolver::new(&context, &kernel).ok();

        // The kernel keeps its tracepoints in a contiguous table bounded by two
        // linker-provided symbols.
        let start = context.symbol_offset(&kernel, "__start___tracepoints_ptrs")?;
        let end = context.symbol_offset(&kernel, "__stop___tracepoints_ptrs")?;
        if end <= start {
            return Ok(TreeGrid::new(self.columns()));
        }

        let template = context.symbol_space.get_type(&kernel.qualified("tracepoint"))?;
        let probe_template = context
            .symbol_space
            .get_type(&kernel.qualified("tracepoint_func"))?;
        let probe_size = context.symbol_space.size_of(&probe_template)?;

        let mut grid = TreeGrid::new(self.columns());
        let mut entry = start;

        while entry < end {
            let Ok(raw) = context.layers.read(&kernel.layer_name, entry, 8, false) else {
                break;
            };
            entry += 8;
            let address = u64::from_le_bytes(raw.try_into().unwrap());
            if address == 0 {
                continue;
            }

            let tracepoint =
                context.object_from_template(template.clone(), &kernel.layer_name, address);
            let name = tracepoint
                .member("name")
                .and_then(|name| pointer_to_string(&name, 128))
                .unwrap_or_default();

            // A tracepoint with no probes is idle, which is the normal state.
            let Ok(probes) = tracepoint
                .member("funcs")
                .and_then(|funcs| funcs.pointer_value())
            else {
                continue;
            };
            if probes == 0 {
                continue;
            }

            for index in 0..MAX_PROBES {
                let probe = context.object_from_template(
                    probe_template.clone(),
                    &kernel.layer_name,
                    probes + index * probe_size,
                );
                let Ok(handler) = probe.member("func").and_then(|func| func.pointer_value())
                else {
                    break;
                };
                // A null entry terminates the probe array.
                if handler == 0 {
                    break;
                }

                let (module, symbol) = match &resolver {
                    Some(resolver) => resolver.describe(&context, handler),
                    None => (None, None),
                };
                let module_base = resolver
                    .as_ref()
                    .and_then(|resolver| resolver.module_for(handler))
                    .map(|module| module.base)
                    .unwrap_or(0);

                grid.push(
                    0,
                    vec![
                        Value::string(name.clone()),
                        Value::hex(address),
                        symbol.map(Value::string).unwrap_or_else(Value::not_available),
                        Value::hex(handler),
                        probe
                            .member("prio")
                            .and_then(|priority| priority.as_i64())
                            .map(Value::int)
                            // Older kernels do not order their probes.
                            .unwrap_or_else(|_| Value::not_applicable()),
                        module.map(Value::string).unwrap_or_else(Value::not_available),
                        Value::hex(module_base),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
