//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;
use crate::framework::layers::DataLayer;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

/// Lists the registry hives present in a particular memory image.
pub struct HiveList;

impl Plugin for HiveList {
    fn name(&self) -> &'static str {
        "windows.registry.hivelist.HiveList"
    }

    fn description(&self) -> &'static str {
        "Lists the registry hives present in a particular memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "filter",
                "String to filter hive names returned",
                RequirementKind::String,
            ),
            Requirement::new("dump", "Extract listed registry hives", RequirementKind::Bool),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("FileFullPath"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = config.get_string("filter");
        let dump = config.get_bool("dump").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        for hive_object in super::list_hive_objects(&context, &kernel, filter.as_deref())? {
            let path = super::hive_object_name(&hive_object);
            let file_output = if dump {
                match dump_hive(&context, &kernel, hive_object.clone()) {
                    Ok(name) => Value::string(name),
                    // Upstream guards none of the writing, so the first hive
                    // it cannot read ends the listing with the failure
                    // reported rather than marking that one row.
                    Err(error) => {
                        grid.mark_failed(error);
                        break;
                    }
                }
            } else {
                Value::string("Disabled")
            };

            grid.push(
                0,
                vec![
                    Value::hex(hive_object.offset()),
                    // A hive with no recorded path is normal for the in-memory
                    // ones, so it is reported with an empty name rather than
                    // skipped.
                    Value::string(path.unwrap_or_default()),
                    file_output,
                ],
            )?;
        }
        Ok(grid)
    }
}

/// How much of a hive to read at a time.
const CHUNK: u64 = 0x500000;

/// Write a hive out as a file in the on-disk registry format.
///
/// The file starts with the hive's own header block, which lives outside the
/// cell space, and continues with the stable store read through the layer.
fn dump_hive(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    hive_object: crate::framework::objects::Object,
) -> Result<String> {
    use std::io::Write;

    let hive = super::open_hive(context, kernel, hive_object)?;
    let maximum = hive.stable_length();
    let name = sanitize_hive_name(hive.hive_name().unwrap_or("[NONAME]"));
    let file_name = format!("registry.{name}.{:#x}.hive", hive.hive_offset());

    let (stored, mut handle) = crate::framework::plugins::open_extracted(&file_name)
        .map_err(|error| crate::error::VolatilityError::Io(format!("{error}")))?;
    // Once the file is open a failure is reported against it before it is
    // passed on, which is what the reference implementation's own file handle
    // does as the block it was opened in unwinds.
    let mut note = |error: &crate::error::VolatilityError| {
        log::warn!("File {file_name} could not be written: {error}");
    };

    let header = match hive.base_block() {
        Some(address) => context
            .layers
            .read(hive.base_layer(), address, 1 << 12, false)
            .inspect_err(&mut note)?,
        // A hive whose header is paged out is written with a blank one, so the
        // cell offsets in the rest of the file still land where they should.
        None => vec![0u8; 1 << 12],
    };
    handle
        .write_all(&header)
        .map_err(|error| crate::error::VolatilityError::Io(format!("{error}")))?;

    let mut at = 0u64;
    while at < maximum {
        let size = CHUNK.min(maximum - at) as usize;
        let chunk = context
            .layers
            .read(hive.name(), at, size, true)
            .inspect_err(&mut note)?;
        handle
            .write_all(&chunk)
            .map_err(|error| crate::error::VolatilityError::Io(format!("{error}")))?;
        at += CHUNK;
    }

    // The name reported is the one written, which is not the one asked for
    // when a file of that name was already there.
    Ok(stored)
}

/// A hive's name as a file name: the last path component, with the characters
/// a name should not carry removed.
fn sanitize_hive_name(name: &str) -> String {
    name.rsplit('\\')
        .next()
        .unwrap_or(name)
        .replace(' ', "_")
        .replace('.', "")
        .replace('[', "")
        .replace(']', "")
}
