//! List the modules loaded into each process, from the PEB's loader data.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::WOW64_TABLE;

pub struct DllList;

impl Plugin for DllList {
    fn name(&self) -> &'static str {
        "windows.dlllist.DllList"
    }

    fn description(&self) -> &'static str {
        "Lists the loaded DLLs in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process IDs to include (all other processes are excluded)"),
            Requirement::new(
                "offset",
                "Process offset in the physical address space",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::new(
                "base",
                "Specify a base virtual address in process memory",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::new(
                "name",
                "Specify a regular expression to match dll name(s)",
                crate::framework::plugins::RequirementKind::String,
            ),
            Requirement::new(
                "ignore-case",
                "Specify case insensitivity for the regular expression name matching",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "dump",
                "Extract listed DLLs",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Base", ColumnType::UInt),
            Column::new("Size", ColumnType::UInt),
            Column::string("Name"),
            Column::string("Path"),
            Column::int("LoadCount"),
            Column::datetime("LoadTime"),
            Column::string("File output"),
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
            // A module with no recorded load time has nothing to place.
            if !is_time(&values[6]) {
                continue;
            }
            let description = format!(
                "DLL Load: Process {} {} Loaded {} ({}) Size {} Offset {}",
                number(&values[0]),
                text(&values[1]),
                text(&values[4]),
                text(&values[5]),
                number(&values[3]),
                number(&values[2])
            );
            timeline.push(description, TimeKind::Created, values[6].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let dump = config.get_bool("dump").unwrap_or(false);
        let wanted_base = config.get_int("base").filter(|base| *base != 0).map(|base| base as u64);
        // A pattern is matched against both the short and the full name, and
        // a module matching neither is left out.
        let pattern = match config.get_string("name") {
            Some(text) => {
                let text = if config.get_bool("ignore-case").unwrap_or(false) {
                    format!("(?i){text}")
                } else {
                    text
                };
                match regex::Regex::new(&text) {
                    Ok(pattern) => Some(pattern),
                    Err(error) => {
                        log::debug!("Error parsing regular expression: {error}");
                        return Ok(TreeGrid::new(self.columns()));
                    }
                }
            }
            None => None,
        };
        let mut grid = TreeGrid::new(self.columns());

        for process in
            crate::framework::plugins::windows::selected_processes(&context, &kernel, config)?
        {
            let Ok(pid) = process.pid() else { continue };
            let name = process.image_file_name().unwrap_or_default();

            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };
            let entries = load_order_modules(&context, &kernel, &process, &layer, "InLoadOrderModuleList");

            for entry in entries {
                let short = entry
                    .member("BaseDllName")
                    .and_then(|value| unicode_string(&value));
                let full = entry
                    .member("FullDllName")
                    .and_then(|value| unicode_string(&value));
                if let Some(pattern) = &pattern {
                    // A module whose names cannot be read cannot be matched.
                    let (Ok(short), Ok(full)) = (&short, &full) else {
                        continue;
                    };
                    if !pattern.is_match(short) && !pattern.is_match(full) {
                        continue;
                    }
                }
                if let Some(wanted) = wanted_base {
                    let base = entry
                        .member("DllBase")
                        .and_then(|base| base.pointer_value())
                        .unwrap_or(0);
                    if base != wanted {
                        continue;
                    }
                }

                let file_output = if dump {
                    let base = entry
                        .member("DllBase")
                        .and_then(|base| base.pointer_value());
                    match base {
                        Ok(base) => dump_ldr_entry(
                            &context,
                            &layer,
                            &entry,
                            base,
                            &format!("pid.{pid}."),
                        )
                        .unwrap_or_else(|| "Error outputting file".to_string()),
                        Err(_) => "Error outputting file".to_string(),
                    }
                } else {
                    "Disabled".to_string()
                };
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        entry
                            .member("DllBase")
                            .and_then(|base| base.pointer_value())
                            .map(Value::hex)
                            .unwrap_or_else(|_| Value::unreadable()),
                        entry
                            .member("SizeOfImage")
                            .and_then(|size| size.as_u64())
                            .map(Value::hex)
                            .unwrap_or_else(|_| Value::unreadable()),
                        entry
                            .member("BaseDllName")
                            .and_then(|value| unicode_string(&value))
                            .map(Value::string)
                            .unwrap_or_else(|_| Value::unreadable()),
                        entry
                            .member("FullDllName")
                            .and_then(|value| unicode_string(&value))
                            .map(Value::string)
                            .unwrap_or_else(|_| Value::unreadable()),
                        // A load count the kernel does not track is reported as
                        // unavailable rather than as zero.
                        entry
                            .member("LoadCount")
                            .or_else(|_| entry.member("ObsoleteLoadCount"))
                            .and_then(|value| value.as_u64())
                            // The field is unsigned in the symbols but counted
                            // as signed, so a fully loaded module reads as -1
                            // rather than as sixty-five thousand.
                            .map(|value| Value::int(value as u16 as i16 as i64))
                            .unwrap_or_else(|_| Value::not_available()),
                        // LoadTime only exists from Windows 7 onwards.
                        match entry.member("LoadTime") {
                            Ok(load_time) => load_time
                                .member("QuadPart")
                                .or_else(|_| Ok(load_time.clone()))
                                .and_then(|value| value.as_u64())
                                .map(wintime_value)
                                .unwrap_or_else(|_: crate::error::VolatilityError| {
                                    Value::unreadable()
                                }),
                            Err(_) => Value::not_applicable(),
                        },
                        Value::string(file_output),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The modules a process has loaded, in the order the list names.
///
/// A process running under WoW64 keeps a second, 32-bit list of its modules,
/// described by its own types, and both are walked.
pub fn load_order_modules(
    context: &Arc<Context>,
    kernel: &Module,
    process: &crate::framework::symbols::windows::Process,
    layer: &str,
    list_member: &str,
) -> Vec<Object> {
    let mut lists: Vec<(Object, String)> = Vec::new();
    if let Ok(head) = process
        .peb(layer)
        .and_then(|peb| peb.member("Ldr"))
        .and_then(|ldr| ldr.dereference())
        .and_then(|ldr| ldr.member(list_member))
    {
        lists.push((head, kernel.qualified("_LDR_DATA_TABLE_ENTRY")));
    }
    if context.ensure_table(WOW64_TABLE, "windows", "wow64").is_ok() {
        if let Ok(Some(peb)) = process.peb32(layer) {
            // In the 32-bit view the pointer is a plain word, so the list head
            // is built at the address it holds.
            let head = peb
                .member("Ldr")
                .and_then(|ldr| ldr.as_u64())
                .and_then(|address| {
                    context.object(&format!("{WOW64_TABLE}!_PEB_LDR_DATA"), layer, address)
                })
                .and_then(|ldr| ldr.member(list_member));
            if let Ok(head) = head {
                lists.push((head, format!("{WOW64_TABLE}!_LDR_DATA_TABLE_ENTRY")));
            }
        }
    }

    let mut entries = Vec::new();
    for (head, entry_type) in lists {
        if let Ok(found) = walk_list(&head, &entry_type, list_link(list_member), true) {
            // An entry whose base cannot be read says nothing about what is
            // loaded, so it is left out.
            entries.extend(found.into_iter().filter(|entry| {
                entry
                    .member("DllBase")
                    .and_then(|base| base.pointer_value())
                    .is_ok()
            }));
        }
    }
    entries
}

/// The link member that pairs with a list head.
fn list_link(list_member: &str) -> &'static str {
    match list_member {
        "InInitializationOrderModuleList" => "InInitializationOrderLinks",
        "InMemoryOrderModuleList" => "InMemoryOrderLinks",
        _ => "InLoadOrderLinks",
    }
}

/// Write out the image a module entry describes, named after the entry.
///
/// The name records both where the entry sits and where the image is loaded,
/// so two processes sharing a library still produce distinct files.
pub fn dump_ldr_entry(
    context: &Arc<Context>,
    layer: &str,
    entry: &crate::framework::objects::Object,
    base: u64,
    prefix: &str,
) -> Option<String> {
    let full_name = entry
        .member("FullDllName")
        .and_then(|value| unicode_string(&value))
        .unwrap_or_else(|_| "UnreadableDLLName".to_string());
    let file = full_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&full_name)
        .to_string();
    let name = crate::framework::plugins::windows::pslist::sanitize_filename(&format!(
        "{prefix}{file}.{:#x}.{base:#x}.dmp",
        entry.offset()
    ));

    // The file is produced even when the image could not be rebuilt in full,
    // which is what upstream leaves behind. Only a complete rebuild is
    // reported as a successful extraction.
    let rebuilt = crate::framework::symbols::windows::pe::reconstruct(context, layer, base);
    let data = match &rebuilt {
        Ok(data) => data.clone(),
        Err(error) => {
            log::debug!("Unable to dump PE file at offset {base}: {error}");
            Vec::new()
        }
    };
    crate::framework::plugins::write_extracted(&name, &data).ok()?;
    rebuilt.ok().map(|_| name)
}
