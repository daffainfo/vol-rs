//! The four debug registers let a thread trap on access to a specific address
//! without modifying any code. Debuggers use them, and so does malware that
//! wants to intercept a function without leaving a patch behind, so a thread
//! with them set outside a debugging session is worth explaining.
//!
//! Full details on the techniques used in these plugins to detect EDR-evading
//! malware can be found in our 20 page whitepaper submitted to DEFCON along
//! with the presentation:
//!
//! https://www.volexity.com/wp-content/uploads/2024/08/Defcon24_EDR_Evasion_Detection_White-Paper_Andrew-Case.pdf
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use std::collections::HashMap;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::walk_list;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::windows::vadinfo::{end_vpn, file_name_of, start_vpn, walk_vad_tree};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, pe, Process};

/// Class that defines the basic interface that all Plugins must maintain.
///
/// The constructor must only take a `context` and `config_path`, so that
/// plugins can be launched automatically. As such all configuration information
/// must be provided through the requirements and configuration information in
/// the context it is passed.
pub struct DebugRegisters;

impl Plugin for DebugRegisters {
    fn name(&self) -> &'static str {
        "windows.debugregisters.DebugRegisters"
    }

    fn description(&self) -> &'static str {
        // Upstream has no docstring for this plugin, so its help page carries
        // no description either.
        ""
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        let mut columns = vec![
            Column::string("Process"),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("State"),
            Column::int("Dr7"),
        ];
        // Gathers information related to the debug registers for the given
        // thread: the owner process of the thread and the values for dr7, dr0,
        // dr1, dr2 and dr3. One address, range and symbol per register.
        for index in 0..4 {
            columns.push(Column::new(format!("Dr{index}"), ColumnType::UInt));
            columns.push(Column::string(format!("Range{index}")));
            columns.push(Column::string(format!("Symbol{index}")));
        }
        columns
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        // The mapped files of each process, worked out once per process.
        let mut ranges: HashMap<u64, Vec<MappedFile>> = HashMap::new();
        // Every mapped file in the image, keyed by its name, which is what says
        // where a module's export table might be found. This lookup takes a
        // while, so only perform it if we need to.
        let mut modules: Option<HashMap<String, Vec<Instance>>> = None;

        for process in list_processes(&context, &kernel)? {
            let threads = process
                .object
                .member("ThreadListHead")
                .and_then(|head| {
                    walk_list(&head, &kernel.qualified("_ETHREAD"), "ThreadListEntry", true)
                })
                .unwrap_or_default();

            for thread in threads {
                let Some(registers) = read_debug_registers(&thread) else {
                    continue;
                };
                // 0 = debug registers not active, 4 = terminated. Either way
                // the thread holds stale values that mean nothing.
                if registers.control == 0 || registers.state == 4 {
                    continue;
                }
                // The addresses are read against the process the thread belongs
                // to, which is not always the one it was reached through.
                let Some(owner) = owning_process(&thread, &kernel) else {
                    continue;
                };
                // bail if all are 0
                if registers.addresses.iter().all(|address| *address == 0) {
                    continue;
                }

                let mapped = ranges
                    .entry(owner.object.offset())
                    .or_insert_with(|| mapped_files(&context, &kernel, &owner));
                // A process whose ranges cannot be read, or one that has
                // already gone, says nothing about its own addresses.
                if mapped.is_empty() {
                    continue;
                }
                let mapped = mapped.clone();
                let collected = modules
                    .get_or_insert_with(|| all_mapped_files(&context, &kernel, &physical));

                let described: Vec<(Option<String>, Option<String>)> = registers
                    .addresses
                    .iter()
                    .map(|address| path_and_symbol(&context, collected, &mapped, *address))
                    .collect();
                // if none map to an actual file VAD then bail
                if described.iter().all(|(path, _)| path.is_none()) {
                    continue;
                }

                let Ok(tid) = thread
                    .member("Cid")
                    .and_then(|cid| cid.member("UniqueThread"))
                    .and_then(|tid| tid.pointer_value())
                else {
                    continue;
                };

                let mut row = vec![
                    Value::string(owner.image_file_name().unwrap_or_default()),
                    Value::int(owner.pid().unwrap_or(0) as i64),
                    Value::int(tid as i64),
                    Value::int(registers.state as i64),
                    Value::int(registers.control as i64),
                ];
                for (address, (path, symbol)) in registers.addresses.iter().zip(described) {
                    row.push(Value::hex(*address));
                    row.push(
                        path.map(Value::string)
                            .unwrap_or_else(Value::not_applicable),
                    );
                    row.push(
                        symbol
                            .map(Value::string)
                            .unwrap_or_else(Value::not_applicable),
                    );
                }
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// One of a process's ranges that maps a file.
#[derive(Clone)]
struct MappedFile {
    start: u64,
    size: u64,
    path: String,
}

/// Where one module was found: the layer to read it through and the range it
/// occupies there.
struct Instance {
    layer: String,
    start: u64,
}

/// The process the thread belongs to.
///
/// Windows XP records it on the thread itself; later versions moved it into the
/// control block.
fn owning_process(thread: &Object, kernel: &Module) -> Option<Process> {
    let pointer = thread
        .member("ThreadsProcess")
        .or_else(|_| thread.member("Tcb").and_then(|tcb| tcb.member("Process")))
        .ok()?;
    let address = pointer.pointer_value().ok()?;
    if address == 0 {
        return None;
    }
    let template = thread
        .context()
        .symbol_space
        .get_type(&kernel.qualified("_EPROCESS"))
        .ok()?;
    let object =
        thread
            .context()
            .object_from_template(template, thread.layer_name(), address);
    object.is_readable().then(|| Process::new(object))
}

/// Every range of a process that maps a file, with the file's path.
///
/// A path with no separator in it is not a path, which is how a smeared name is
/// rejected.
fn mapped_files(context: &Arc<Context>, kernel: &Module, process: &Process) -> Vec<MappedFile> {
    let Ok(nodes) = walk_vad_tree(context, kernel, process) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for node in nodes {
        let Some(path) = file_name_of(&node) else {
            continue;
        };
        if !path.contains('\\') {
            continue;
        }
        let (Some(start), Some(end)) = (start_vpn(&node), end_vpn(&node)) else {
            continue;
        };
        results.push(MappedFile {
            start,
            size: end - start + 1,
            path,
        });
    }
    results
}

/// Every mapped file across every process, keyed by the file's own name.
fn all_mapped_files(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
) -> HashMap<String, Vec<Instance>> {
    let mut found: HashMap<String, Vec<Instance>> = HashMap::new();
    let Ok(processes) = list_processes(context, kernel) else {
        return found;
    };
    for process in processes {
        let Ok(layer) = process.address_space(physical) else {
            continue;
        };
        for range in mapped_files(context, kernel, &process) {
            found
                .entry(base_name(&range.path))
                .or_default()
                .push(Instance {
                    layer: layer.clone(),
                    start: range.start,
                });
        }
    }
    found
}

/// A path's last component, lowercased, which is how a module is named.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

/// The file an address lands in, and the exported name at it where there is one.
fn path_and_symbol(
    context: &Arc<Context>,
    modules: &HashMap<String, Vec<Instance>>,
    ranges: &[MappedFile],
    address: u64,
) -> (Option<String>, Option<String>) {
    if address == 0 {
        return (None, None);
    }
    let Some(range) = ranges
        .iter()
        .find(|range| range.start <= address && address < range.start + range.size)
    else {
        return (None, None);
    };
    let path = range.path.clone();

    // The name is looked for in whichever copies of that file are mapped, so a
    // module paged out of one process may still be readable in another.
    let name = base_name(&path);
    let Some(instances) = modules.get(&name) else {
        return (Some(path), None);
    };
    for instance in instances {
        let Ok(data) = context
            .layers
            .read(&instance.layer, instance.start, 0x100_0000, true)
        else {
            continue;
        };
        let Some(exports) = pe::exports(&data) else {
            continue;
        };
        for export in exports {
            if instance.start + export.address as u64 == address && !export.name.is_empty() {
                return (Some(path), Some(export.name));
            }
        }
    }
    (Some(path), None)
}

/// The debug registers saved in a thread's kernel context.
struct DebugRegisterSet {
    control: u64,
    state: u64,
    addresses: [u64; 4],
}

/// Read a thread's saved debug registers.
///
/// They are saved in the trap frame the thread was last interrupted with, so a
/// thread that has never entered the kernel has none to read.
fn read_debug_registers(thread: &Object) -> Option<DebugRegisterSet> {
    let control_block = thread.member("Tcb").ok()?;
    let frame = control_block
        .member("TrapFrame")
        .and_then(|frame| frame.dereference())
        .ok()?;

    let control = frame.member("Dr7").and_then(|value| value.as_u64()).ok()?;
    let state = control_block
        .member("State")
        .and_then(|value| value.as_u64())
        .ok()?;
    let read = |name: &str| -> u64 {
        frame
            .member(name)
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
    };
    Some(DebugRegisterSet {
        control,
        state,
        addresses: [read("Dr0"), read("Dr1"), read("Dr2"), read("Dr3")],
    })
}
