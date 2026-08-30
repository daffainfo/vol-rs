//! Report the header of a Windows crash dump.
//!
//! The header records how the dump was produced and where the kernel's key
//! structures were, which is useful for confirming an image is what it claims
//! to be before trusting anything else read from it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::crash::check_header;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct CrashInfo;

/// Offsets of the header fields, which the on-disk format fixes. The 64-bit
/// layout widens the pointers but keeps the same ordering.
struct Fields {
    word: usize,
    pfn_database: u64,
    ps_loaded_module_list: u64,
    ps_active_process_head: u64,
    machine_image_type: u64,
    number_processors: u64,
    kd_debugger_data_block: u64,
}

const FIELDS_64: Fields = Fields {
    word: 8,
    pfn_database: 0x18,
    ps_loaded_module_list: 0x20,
    ps_active_process_head: 0x28,
    machine_image_type: 0x30,
    number_processors: 0x34,
    kd_debugger_data_block: 0x80,
};

const FIELDS_32: Fields = Fields {
    word: 4,
    pfn_database: 0x14,
    ps_loaded_module_list: 0x18,
    ps_active_process_head: 0x1C,
    machine_image_type: 0x20,
    number_processors: 0x24,
    kd_debugger_data_block: 0x60,
};

impl Plugin for CrashInfo {
    fn name(&self) -> &'static str {
        "windows.crashinfo.Crashinfo"
    }

    fn description(&self) -> &'static str {
        "Lists the information from a Windows crash dump."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Signature"),
            Column::int("MajorVersion"),
            Column::int("MinorVersion"),
            Column::new("DirectoryTableBase", ColumnType::UInt),
            Column::new("PfnDataBase", ColumnType::UInt),
            Column::new("PsLoadedModuleList", ColumnType::UInt),
            Column::new("PsActiveProcessHead", ColumnType::UInt),
            Column::new("MachineImageType", ColumnType::UInt),
            Column::int("NumberProcessors"),
            Column::new("KdDebuggerDataBlock", ColumnType::UInt),
            Column::int("DumpType"),
            Column::int("SystemUpTime"),
            Column::string("Comment"),
            Column::datetime("SystemTime"),
            Column::int("BitmapHeaderSize"),
            Column::int("BitmapSize"),
            Column::int("BitmapPages"),
        ]
    }

    fn run(&self, context: Arc<Context>, _config: &Configuration) -> Result<TreeGrid> {
        // The crash layer sits directly on the file, so its base layer is the
        // one carrying the header.
        let base = context
            .layers
            .names()
            .into_iter()
            .find(|name| name.starts_with("base"))
            .ok_or_else(|| VolatilityError::Other("No base layer".to_string()))?;

        let header = check_header(&context.layers, &base).map_err(|_| {
            VolatilityError::Other(
                "This image is not a Windows crash dump; crashinfo has nothing to report"
                    .to_string(),
            )
        })?;

        let fields = if header.is_64bit { &FIELDS_64 } else { &FIELDS_32 };

        let read = |offset: u64, width: usize| -> Value {
            match context.layers.read(&base, offset, width, false) {
                Ok(data) => {
                    let mut buffer = [0u8; 8];
                    buffer[..data.len()].copy_from_slice(&data);
                    Value::hex(u64::from_le_bytes(buffer))
                }
                Err(_) => Value::unreadable(),
            }
        };
        let read_int = |offset: u64| -> Value {
            match context.layers.read(&base, offset, 4, false) {
                Ok(data) => Value::int(u32::from_le_bytes(data.try_into().unwrap()) as i64),
                Err(_) => Value::unreadable(),
            }
        };

        let mut grid = TreeGrid::new(self.columns());
        grid.push(
            0,
            vec![
                Value::string("PAGE"),
                read_int(0x08),
                read_int(0x0C),
                Value::hex(header.directory_table_base),
                read(fields.pfn_database, fields.word),
                read(fields.ps_loaded_module_list, fields.word),
                read(fields.ps_active_process_head, fields.word),
                read_int(fields.machine_image_type),
                read_int(fields.number_processors),
                read(fields.kd_debugger_data_block, fields.word),
                Value::int(header.dump_type as i64),
                // These trailing fields sit at offsets that vary across
                // Windows versions and are described by the crash symbol file
                // this port does not yet load. Reporting them as unavailable is
                // preferable to reading a fixed offset that may be wrong.
                Value::not_available(),
                Value::not_available(),
                Value::not_available(),
                Value::not_available(),
                Value::not_available(),
                Value::not_available(),
            ],
        )?;
        Ok(grid)
    }
}
