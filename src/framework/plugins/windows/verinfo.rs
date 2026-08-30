//! Report the version stamped into each loaded module.
//!
//! A module whose version does not match what Windows shipped, or which has no
//! version at all, is worth a second look.
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
use crate::framework::plugins::windows::dlllist::load_order_modules;
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::pe;

pub struct VerInfo;

/// How much of each image to search for the version structure. It lives in the
/// resource section, which is near the end of a typical module, so the whole
/// image is not read.
const _SEARCH_BYTES: usize = 0x100000;

impl Plugin for VerInfo {
    fn name(&self) -> &'static str {
        "windows.verinfo.VerInfo"
    }

    fn description(&self) -> &'static str {
        "Lists version information from PE files."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "extensive",
                "Search physical layer for version information",
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
            Column::string("Name"),
            Column::int("Major"),
            Column::int("Minor"),
            Column::int("Product"),
            Column::int("Build"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let extensive = config.get_bool("extensive").unwrap_or(false);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // The kernel's own modules come first. They belong to no process.
        // Each is read through a session's address space, and the sessions are
        // taken one at a time and never revisited, so only the first few
        // modules are ever looked up at all.
        let mut sessions = crate::framework::plugins::windows::modules::session_layers(
            &context, &kernel, &physical,
        )
        .into_iter();
        let modules = context
            .object_from_symbol(&kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))
            .and_then(|head| {
                walk_list(
                    &head,
                    &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
                    "InLoadOrderLinks",
                    true,
                )
            })
            .unwrap_or_default();

        for entry in modules {
            let name = entry
                .member("BaseDllName")
                .and_then(|name| unicode_string(&name))
                .map(Value::string)
                .unwrap_or_else(|_| Value::unreadable());
            let Ok(base) = entry
                .member("DllBase")
                .and_then(|base| base.pointer_value())
            else {
                continue;
            };
            let size = entry
                .member("SizeOfImage")
                .and_then(|size| size.as_u64())
                .unwrap_or(0) as usize;

            let session = find_session_layer(&context, &mut sessions, base);
            let mut cells = match session {
                Some(layer) => version_cells(&context, &layer, base, size),
                None => (
                    Value::unreadable(),
                    Value::unreadable(),
                    Value::unreadable(),
                    Value::unreadable(),
                ),
            };
            // A module whose headers are paged out can still be found by
            // searching the image itself for the version resource, which is
            // slow enough that it is only done when asked for.
            if extensive && matches!(cells.0, Value::Absent(_)) {
                if let Value::Str(file) = &name {
                    if let Some(found) = search_version_info(&context, &physical, file) {
                        cells = found;
                    }
                }
            }
            let (major, minor, product, build) = cells;
            grid.push(
                0,
                vec![
                    Value::not_applicable(),
                    Value::not_applicable(),
                    Value::hex(base),
                    name,
                    major,
                    minor,
                    product,
                    build,
                ],
            )?;
        }

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let process_name = process.image_file_name().unwrap_or_default();

            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };

            let entries = load_order_modules(
                &context,
                &kernel,
                &process,
                &layer,
                "InLoadOrderModuleList",
            );

            for entry in entries {
                let Ok(base) = entry
                    .member("DllBase")
                    .and_then(|base| base.pointer_value())
                else {
                    continue;
                };
                if base == 0 {
                    continue;
                }

                let name = entry
                    .member("BaseDllName")
                    .and_then(|name| unicode_string(&name))
                    .map(Value::string)
                    .unwrap_or_else(|_| Value::unreadable());

                let size = entry
                    .member("SizeOfImage")
                    .and_then(|size| size.as_u64())
                    .unwrap_or(0) as usize;
                let (major, minor, product, build) =
                    version_cells(&context, &layer, base, size);

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(process_name.clone()),
                        Value::hex(base),
                        name,
                        major,
                        minor,
                        product,
                        build,
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The four parts of an image's product version, as cells.
///
/// The version lives in a resource of its own, so the image's headers are read
/// first to find where its resources are, and only that part of it is read.
/// An image whose resources cannot be reached reports nothing, which is the
/// common case for the components that carry none.
fn version_cells(
    context: &Arc<Context>,
    layer: &str,
    base: u64,
    size: usize,
) -> (Value, Value, Value, Value) {
    let unreadable = || {
        (
            Value::unreadable(),
            Value::unreadable(),
            Value::unreadable(),
            Value::unreadable(),
        )
    };

    let Some(version) = image_version(context, layer, base, size) else {
        return unreadable();
    };
    (
        Value::int(version.major as i64),
        Value::int(version.minor as i64),
        Value::int(version.product as i64),
        Value::int(version.build as i64),
    )
}

/// The product version an image records.
fn image_version(
    context: &Arc<Context>,
    layer: &str,
    base: u64,
    size: usize,
) -> Option<crate::framework::symbols::windows::pe::VersionInfo> {
    // An image claiming to be larger than any real one is not one, and
    // upstream refuses to read it at all.
    const MAXIMUM_IMAGE: usize = 256 * 1024 * 1024;
    if size > MAXIMUM_IMAGE {
        return None;
    }

    let headers = context.layers.read(layer, base, 0x1000, true).ok()?;
    let (resources, length) = pe::resource_directory(&headers)?;

    let region = context
        .layers
        .read(layer, base + resources as u64, length as usize, true)
        .ok()?;
    // An image often carries the version in several languages. The first that
    // can be read is the one reported.
    for (address, blob_length) in pe::resource_data(&region, pe::RT_VERSION) {
        // The block is named by an address relative to the image, which is
        // usually inside the resources that were just read.
        let start = (address as usize).checked_sub(resources as usize);
        let blob = match start {
            Some(start) if start + blob_length as usize <= region.len() => {
                region[start..start + blob_length as usize].to_vec()
            }
            _ => match context
                .layers
                .read(layer, base + address as u64, blob_length as usize, true)
            {
                Ok(blob) => blob,
                Err(_) => continue,
            },
        };
        if let Some(version) = pe::version_info(&blob) {
            return Some(version);
        }
    }
    None
}

/// The next session layer that can reach an address.
///
/// The sessions are consumed as they are examined: one that has already been
/// looked at is not looked at again, which is why a listing resolves only its
/// first few modules.
fn find_session_layer(
    context: &Arc<Context>,
    sessions: &mut std::vec::IntoIter<(u64, String)>,
    address: u64,
) -> Option<String> {
    for (_, layer) in sessions.by_ref() {
        if context.layers.is_valid(&layer, address, 1) {
            return Some(layer);
        }
    }
    None
}

/// Find a module's version by searching the image for its version resource.
///
/// The resource records the file's original name, so the name is looked for
/// and the fixed version block just before it is read.
fn search_version_info(
    context: &Arc<Context>,
    layer: &str,
    file_name: &str,
) -> Option<(Value, Value, Value, Value)> {
    use crate::framework::layers::scanners::{scan_layer, BytesScanner};

    // How far back from the name the block may sit.
    const PREAMBLE: u64 = 0x500;
    // The signature the fixed version block opens with.
    const SIGNATURE: [u8; 4] = [0xBD, 0x04, 0xEF, 0xFE];

    let needle: Vec<u8> = format!("OriginalFilename\0{file_name}")
        .encode_utf16()
        .flat_map(|unit| unit.to_be_bytes())
        .collect();
    let Ok(handle) = context.layers.get(layer) else {
        return None;
    };
    let scanner = BytesScanner::new(needle);

    let mut found = None;
    let _ = scan_layer(handle.as_ref(), &context.layers, &scanner, None, |offset| {
        if found.is_some() || offset < PREAMBLE {
            return;
        }
        let Ok(data) = context
            .layers
            .read(layer, offset - PREAMBLE, PREAMBLE as usize, false)
        else {
            return;
        };
        let Some(at) = data
            .windows(4)
            .position(|window| window == SIGNATURE)
            .map(|at| at + 4)
        else {
            return;
        };
        let Some(block) = data.get(at..at + 20) else {
            return;
        };
        let word = |index: usize| -> i64 {
            u16::from_le_bytes(block[index..index + 2].try_into().unwrap()) as i64
        };
        // The four halves are recorded out of order.
        found = Some((
            Value::int(word(6)),
            Value::int(word(4)),
            Value::int(word(10)),
            Value::int(word(8)),
        ));
    });
    found
}
