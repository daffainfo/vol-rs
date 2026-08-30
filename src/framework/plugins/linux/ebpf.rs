//! List the loaded eBPF programs.
//!
//! eBPF runs verified bytecode inside the kernel, attached to tracepoints,
//! sockets and system calls. It is a legitimate and widely used mechanism, and
//! also a way to run kernel-level code without loading a module, so what is
//! loaded is worth knowing.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::error::VolatilityError;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::symbols::linux::xarray_entries;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct Ebpf;

impl Plugin for Ebpf {
    fn name(&self) -> &'static str {
        "linux.ebpf.EBPF"
    }

    fn description(&self) -> &'static str {
        "Enumerate eBPF programs"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Address", ColumnType::UInt),
            Column::string("Name"),
            Column::string("Tag"),
            Column::string("Type"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // Programs are registered in an IDR, which the kernel walks by ID.
        // Reading the radix tree is version-specific, so the entries are taken
        // from the id-to-pointer array the IDR keeps.
        let idr = context.object_from_symbol(&kernel, "prog_idr", Some("idr"))?;
        let template = context.symbol_space.get_type(&kernel.qualified("bpf_prog"))?;

        let mut grid = TreeGrid::new(self.columns());

        for address in xarray_entries(&context, &kernel, &idr.member("idr_rt")?)? {
            let program =
                context.object_from_template(template.clone(), &kernel.layer_name, address);

            // The auxiliary structure carries the program's name.
            let auxiliary = program.member("aux").and_then(|aux| aux.dereference());
            let name = auxiliary
                .as_ref()
                .ok()
                .and_then(|aux| aux.member("name").ok())
                .and_then(|name| name.as_string().ok())
                .filter(|name| !name.is_empty());

            // The tag is a short hash of the program, shown as hex.
            let tag = program
                .member("tag")
                .ok()
                .and_then(|tag| tag.bytes().ok())
                .map(|bytes| {
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                });

            // The type moved out of the auxiliary structure in kernel 4.1.
            let kind = program
                .member("type")
                .or_else(|_| {
                    auxiliary
                        .as_ref()
                        .map_err(|_| VolatilityError::Other("no aux".to_string()))
                        .and_then(|aux| aux.member("prog_type"))
                })
                .and_then(|value| value.enum_name())
                .ok();

            grid.push(
                0,
                vec![
                    Value::hex(program.offset()),
                    name.map(Value::string).unwrap_or_else(Value::not_available),
                    tag.map(Value::string).unwrap_or_else(Value::not_available),
                    kind.map(Value::string).unwrap_or_else(Value::not_available),
                ],
            )?;
        }
        Ok(grid)
    }
}
