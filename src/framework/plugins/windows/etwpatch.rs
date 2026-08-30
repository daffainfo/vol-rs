//! Detect processes that have patched out ETW logging.
//!
//! Event Tracing for Windows is what most security tooling reads. A process can
//! blind that tooling by overwriting the first instruction of the logging
//! function in its own copy of `ntdll` with an immediate return, which costs
//! one byte and stops every event the process would have produced.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, pe};

pub struct EtwPatch;

/// The logging functions worth checking, and the module that exports them.
const WATCHED: &[(&str, &str)] = &[
    ("ntdll.dll", "EtwEventWrite"),
    ("ntdll.dll", "EtwEventWriteFull"),
    ("ntdll.dll", "EtwEventWriteEx"),
    ("ntdll.dll", "NtTraceEvent"),
    ("ntdll.dll", "EtwNotificationRegister"),
];

/// How many opening bytes to inspect.
const PROLOGUE_BYTES: usize = 8;

impl Plugin for EtwPatch {
    fn name(&self) -> &'static str {
        "windows.etwpatch.EtwPatch"
    }

    fn description(&self) -> &'static str {
        "Identifies ETW (Event Tracing for Windows) patching techniques used by malware to evade detection."
    }

    fn epilog(&self) -> Option<&'static str> {
        Some(
            "This plugin examines the first opcode of key ETW functions in \
             ntdll.dll and advapi32.dll to detect common ETW bypass techniques such \
             as return pointer manipulation (RET) or function redirection (JMP). \
             Attackers often patch these functions to prevent security tools from \
             receiving telemetry about process execution, API calls, and other \
             system events.",
        )
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::string("DLL"),
            Column::string("Function"),
            Column::new("Offset", ColumnType::UInt),
            Column::string("Opcode"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };
            let Ok(peb) = process.peb(&layer) else { continue };

            let entries = peb
                .member("Ldr")
                .and_then(|ldr| ldr.dereference())
                .and_then(|ldr| ldr.member("InLoadOrderModuleList"))
                .and_then(|head| {
                    walk_list(
                        &head,
                        &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
                        "InLoadOrderLinks",
                        true,
                    )
                })
                .unwrap_or_default();

            for entry in entries {
                let module_name = entry
                    .member("BaseDllName")
                    .and_then(|name| unicode_string(&name))
                    .unwrap_or_default();

                let watched: Vec<&str> = WATCHED
                    .iter()
                    .filter(|(module, _)| module.eq_ignore_ascii_case(&module_name))
                    .map(|(_, function)| *function)
                    .collect();
                if watched.is_empty() {
                    continue;
                }

                let Ok(base) = entry.member("DllBase").and_then(|b| b.pointer_value()) else {
                    continue;
                };
                let size = entry
                    .member("SizeOfImage")
                    .and_then(|size| size.as_u64())
                    .unwrap_or(0) as usize;
                let Ok(image) = context.layers.read(&layer, base, size.min(0x400000), true)
                else {
                    continue;
                };

                for export in pe::exports(&image).unwrap_or_default() {
                    if !watched.contains(&export.name.as_str()) {
                        continue;
                    }
                    let start = export.address as usize;
                    let Some(prologue) = image.get(start..start + PROLOGUE_BYTES) else {
                        continue;
                    };

                    let Some(description) = patched_opcode(prologue) else {
                        continue;
                    };

                    grid.push(
                        0,
                        vec![
                            Value::int(pid as i64),
                            Value::string(name.clone()),
                            Value::string(module_name.clone()),
                            Value::string(export.name.clone()),
                            Value::hex(base + export.address as u64),
                            Value::string(description),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}

/// Recognise a prologue that has been replaced with an early return.
///
/// Returns `None` for an intact function, which is the normal case and not a
/// finding.
fn patched_opcode(prologue: &[u8]) -> Option<String> {
    match prologue.first()? {
        // A bare RET, or one that pops arguments, returns before doing anything.
        0xC3 => Some("ret".to_string()),
        0xC2 => Some(format!(
            "ret {:#x}",
            u16::from_le_bytes([prologue[1], prologue[2]])
        )),
        // `xor eax, eax` followed by a return reports success without logging.
        0x33 | 0x31 if prologue.get(2) == Some(&0xC3) => Some("xor eax, eax; ret".to_string()),
        // A jump at the very first byte redirects the function wholesale.
        0xE9 => Some("jmp".to_string()),
        0xEB => Some("jmp short".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_common_patches() {
        assert_eq!(patched_opcode(&[0xC3, 0, 0, 0, 0, 0, 0, 0]), Some("ret".to_string()));
        assert_eq!(
            patched_opcode(&[0x33, 0xC0, 0xC3, 0, 0, 0, 0, 0]),
            Some("xor eax, eax; ret".to_string())
        );
        assert!(patched_opcode(&[0xE9, 0x11, 0x22, 0x33, 0x44, 0, 0, 0]).is_some());
    }

    #[test]
    fn an_intact_prologue_is_not_a_finding() {
        // The usual `mov r10, rcx. Mov eax, imm32` system-call stub opening.
        assert!(patched_opcode(&[0x4C, 0x8B, 0xD1, 0xB8, 0x0F, 0x00, 0x00, 0x00]).is_none());
    }
}
