//! A process that has been unlinked from the active process list (by a rootkit,
//! or simply by having exited) is invisible to `pslist`, but its pool
//! allocation may still be present in memory. Scanning for the pool tag finds
//! those.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context, Module};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::symbols::windows::poolscanner::{builtin_constraints, generate_pool_scan};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::Process;

use super::pslist::{process_columns, process_row};

/// Scans for processes present in a particular windows memory image.
pub struct PsScan;

/// The pool tag the kernel allocates `_EPROCESS` structures under. The tag's
/// last byte has its high bit set when the allocation is in non-paged pool.
const PROCESS_POOL_TAGS: [&[u8]; 2] = [b"Proc", b"Pro\xe3"];

impl Plugin for PsScan {
    fn name(&self) -> &'static str {
        "windows.psscan.PsScan"
    }

    fn description(&self) -> &'static str {
        "Scans for processes present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process ID to include (all other processes are excluded)"),
            Requirement::new("dump", "Extract listed processes", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
            Requirement::new(
                "physical",
                "Display physical offset instead of virtual",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        // The offset column is named for the address space the run asks for,
        // which the grid itself settles once the configuration is known.
        process_columns(false)
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
            let description = format!(
                "Process: {} {} ({})",
                number(&values[0]),
                text(&values[2]),
                number(&values[3])
            );
            timeline.push(description.clone(), TimeKind::Created, values[8].clone());
            timeline.push(description, TimeKind::Modified, values[9].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let physical = config.get_bool("physical").unwrap_or(false);
        let physical_name = crate::framework::plugins::windows::physical_layer(config);
        let dump = config.get_bool("dump").unwrap_or(false);

        let mut grid = TreeGrid::new(process_columns(physical));

        for process in scan_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let file_output = if dump {
                // A scanned process sits in physical memory, where nothing it
                // points at can be followed, so the same process is found in
                // the kernel's own space before anything is read through it.
                // windows 10 objects (maybe others in the future) are already
                // in virtual memory
                let virtual_process = if process.object.layer_name() == kernel.layer_name {
                    Some(Process::new(process.object.clone()))
                } else {
                    virtual_process_from_physical(&context, &kernel, &process)
                };
                // This listing names the file as it opens it, so two
                // processes sharing an image both report the same name even
                // though the second is written beside the first.
                match virtual_process.and_then(|process| {
                    crate::framework::plugins::windows::pslist::dump_process_image(
                        &context,
                        &physical_name,
                        &process,
                        pid,
                    )
                }) {
                    Some((preferred, _)) => Value::string(preferred),
                    None => Value::string("Error outputting file"),
                }
            } else {
                Value::string("Disabled")
            };

            // Upstream translates the offset through the kernel's own layer,
            // which a scanned process does not live in, and guards none of it.
            // Where the pool scan works in physical memory the translation
            // faults on the first process and ends the listing.
            let offset = if physical {
                match crate::framework::plugins::windows::physical_offset_from_virtual(
                    &context, &kernel, &process,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        grid.mark_failed(error);
                        break;
                    }
                }
            } else {
                process.object.offset()
            };
            grid.push(0, process_row(&process, pid, offset, file_output))?;
        }
        Ok(grid)
    }
}

/// Scans for processes using the poolscanner module and constraints.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
/// * `kernel` - The module for the kernel
///
/// # Returns
///
/// A list of processes found by scanning the kernel's layer for process pool
/// signatures, whether or not the kernel still lists them.
pub fn scan_processes(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Process>> {
    let constraints = builtin_constraints(&PROCESS_POOL_TAGS);
    Ok(generate_pool_scan(context, kernel, &constraints)?
        .into_iter()
        .map(|hit| Process::new(hit.object))
        .collect())
}

/// Returns a virtual process from a physical addressed one
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
/// * `kernel` - The module for the kernel
/// * `process` - the process object with physical address
///
/// # Returns
///
/// A process object on virtual address layer.
///
/// Nothing a physically addressed process points at can be followed, so
/// upstream bounces off the first entry of its thread list to reach an
/// `_ETHREAD` in the kernel's own space, asks that thread which process owns
/// it, and keeps the answer only when translating it leads back to where the
/// scan found it.
fn virtual_process_from_physical(
    context: &Arc<Context>,
    kernel: &Module,
    process: &Process,
) -> Option<Process> {
    let thread_template = context
        .symbol_space
        .get_type(&kernel.qualified("_ETHREAD"))
        .ok()?;
    let link = context
        .symbol_space
        .find_member(&thread_template, "ThreadListEntry")
        .ok()?
        .map(|(offset, _)| offset)?;

    // Start out with the member offset
    let mut offsets = vec![link];
    // If (and only if) we're dealing with 64-bit Windows 7 SP1 then add the
    // other commonly seen member offset to the list
    let sixty_four_bit = context
        .layers
        .get(&kernel.layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<crate::framework::layers::intel::IntelLayer>()
                .map(|layer| layer.config().bits_per_register)
        })
        .unwrap_or(32)
        == 64;
    if sixty_four_bit && os_version(context, kernel) == Some((6, 1, 7601)) {
        offsets.push(link + 8);
    }

    let head = process
        .object
        .member("ThreadListHead")
        .and_then(|list| list.member("Flink"))
        .and_then(|flink| flink.pointer_value())
        .ok()?;
    let layer = context.layers.get(&kernel.layer_name).ok()?;

    // Now we can try to bounce back
    for offset in offsets {
        let Some(address) = head.checked_sub(offset) else {
            continue;
        };
        let thread =
            context.object_from_template(thread_template.clone(), &kernel.layer_name, address);
        // Ask for the thread's process to get an _EPROCESS with a virtual
        // address layer
        let Some(candidate) = owning_process(&thread, kernel) else {
            continue;
        };
        // Sanity check the bounce. This compares the original offset with the
        // new one (translated from virtual layer).
        let Ok(mapping) = layer.mapping(&context.layers, candidate.object.offset(), 0, false)
        else {
            continue;
        };
        let Some(entry) = mapping.first() else {
            continue;
        };
        if entry.mapped_offset == process.object.offset() {
            return Some(candidate);
        }
    }
    None
}

/// The process a thread belongs to.
fn owning_process(thread: &crate::framework::objects::Object, kernel: &Module) -> Option<Process> {
    let process = thread
        .member("Tcb")
        .and_then(|tcb| tcb.member("Process"))
        .or_else(|_| thread.member("ThreadsProcess"))
        .and_then(|process| process.dereference_as(&kernel.qualified("_EPROCESS")))
        .ok()?;
    Some(Process::new(process))
}

/// Returns the complete OS version (MAJ,MIN,BUILD).
fn os_version(context: &Arc<Context>, kernel: &Module) -> Option<(u64, u64, u64)> {
    let (major, minor) = crate::framework::plugins::windows::info::windows_version(context, kernel)?;
    let build = context
        .object_from_symbol(kernel, "KdVersionBlock", Some("_DBGKD_GET_VERSION64"))
        .ok()?
        .member("MinorVersion")
        .and_then(|value| value.as_u64())
        .ok()?;
    Some((major, minor, build))
}
