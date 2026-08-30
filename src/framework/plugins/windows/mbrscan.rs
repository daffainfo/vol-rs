//! Scan memory for Master Boot Records.
//!
//! An MBR occupies the first sector of a disk: boot code, a disk signature, a
//! four-entry partition table, and a fixed two-byte signature that closes the
//! sector. Recovering one from memory shows what the machine booted from, and
//! comparing its boot code against a known-good hash is how a bootkit shows
//! itself.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use md5::{Digest, Md5};

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, BytesScanner};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct MbrScan;

/// A sector is 512 bytes, and the record's signature closes it.
const SECTOR_SIZE: usize = 0x200;
/// The two bytes every record ends with.
const BOOT_SIGNATURE: &[u8; 2] = b"\x55\xAA";
/// Where the boot code ends.
const BOOTCODE_LENGTH: usize = 0x1B8;

impl Plugin for MbrScan {
    fn name(&self) -> &'static str {
        "windows.mbrscan.MBRScan"
    }

    fn description(&self) -> &'static str {
        "Scans for and parses potential Master Boot Records (MBRs)"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "full",
                "It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)",
                RequirementKind::Bool,
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        columns_for(false)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let layer_name = physical_layer(config);
        let full = config.get_bool("full").unwrap_or(false);
        let layer = context.layers.get(&layer_name)?;
        // The record's own structures ship as a file of their own.
        context.ensure_table("mbr", "windows", "mbr")?;

        // The signature is only two bytes, so most hits are coincidence. A
        // record with no boot code at all is the one case ruled out.
        let scanner = BytesScanner::new(BOOT_SIGNATURE.to_vec());
        let mut hits: Vec<u64> = Vec::new();
        scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
            hits.push(offset)
        })?;

        let mut grid = TreeGrid::new(columns_for(full));

        for hit in hits {
            // The signature closes the sector, so the record begins before it.
            let Some(start) = hit.checked_sub((SECTOR_SIZE - BOOT_SIGNATURE.len()) as u64) else {
                continue;
            };
            let Ok(sector) = layer.read(&context.layers, start, SECTOR_SIZE, true) else {
                continue;
            };
            let bootcode = &sector[..BOOTCODE_LENGTH.min(sector.len())];
            if bootcode.iter().all(|byte| *byte == 0) {
                continue;
            }

            let Ok(table) = context.object("mbr!PARTITION_TABLE", &layer_name, start) else {
                continue;
            };
            let signature = disk_signature(&table);
            let bootcode_hash = hash(bootcode);
            let full_hash = hash(&sector);

            // The record itself, and then each of the four entries beneath it.
            let mut row = vec![
                Value::hex(hit),
                Value::string(signature.clone()),
                Value::string(bootcode_hash.clone()),
                Value::string(full_hash.clone()),
                Value::not_applicable(),
                Value::not_applicable(),
                Value::not_applicable(),
                Value::not_applicable(),
            ];
            if full {
                for _ in 0..8 {
                    row.push(Value::not_applicable());
                }
            }
            // Boot code is shown as instructions where they can be decoded and
            // as the bytes themselves otherwise.
            row.push(Value::HexPairs(bootcode.to_vec()));
            if full {
                row.push(Value::HexDump(bootcode.to_vec()));
            }
            grid.push(0, row)?;

            for (index, member) in ["FirstEntry", "SecondEntry", "ThirdEntry", "FourthEntry"]
                .iter()
                .enumerate()
            {
                let Ok(entry) = table.member(member) else {
                    continue;
                };
                let field = |name: &str| -> u64 {
                    entry
                        .member(name)
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0)
                };
                let byte = |name: &str, at: u64| -> u64 {
                    entry
                        .member(name)
                        .and_then(|array| array.index(at))
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0)
                };

                let bootable_flag = field("BootableFlag");
                let starting_sector = byte("StartingCHS", 1) % 64;
                let ending_sector = byte("EndingCHS", 1) % 64;

                let mut row = vec![
                    Value::hex(hit),
                    Value::string(signature.clone()),
                    Value::string(bootcode_hash.clone()),
                    Value::string(full_hash.clone()),
                    Value::int(index as i64 + 1),
                    Value::Bool(bootable_flag == 0x80),
                ];
                if full {
                    row.push(Value::hex(bootable_flag));
                }
                row.push(Value::string(partition_type(&entry)));
                if full {
                    row.extend([
                        Value::hex(field("PartitionType")),
                        Value::hex(field("StartingLBA")),
                        Value::int(
                            ((byte("StartingCHS", 1) - starting_sector) * 4
                                + byte("StartingCHS", 2)) as i64,
                        ),
                        Value::int(byte("StartingCHS", 0) as i64),
                        Value::int(starting_sector as i64),
                        Value::int(
                            ((byte("EndingCHS", 1) - ending_sector) * 4 + byte("EndingCHS", 2))
                                as i64,
                        ),
                        Value::int(byte("EndingCHS", 0) as i64),
                        Value::int(ending_sector as i64),
                    ]);
                }
                row.push(Value::hex(field("SizeInSectors")));
                row.push(Value::not_applicable());
                if full {
                    row.push(Value::not_applicable());
                }
                grid.push(1, row)?;
            }
        }
        let _ = kernel;
        Ok(grid)
    }
}

/// The columns, which depend on how much of each entry is reported.
fn columns_for(full: bool) -> Vec<Column> {
    let mut columns = vec![
        Column::new("Potential MBR at Physical Offset", ColumnType::UInt),
        Column::string("Disk Signature"),
        Column::string("Bootcode MD5"),
        Column::string("Full MBR MD5"),
        Column::int("PartitionIndex"),
        Column::bool("Bootable"),
    ];
    if full {
        columns.push(Column::new("BootFlag", ColumnType::UInt));
    }
    columns.push(Column::string("PartitionType"));
    if full {
        columns.extend([
            Column::new("PartitionTypeRaw", ColumnType::UInt),
            Column::new("StartingLBA", ColumnType::UInt),
            Column::int("StartingCylinder"),
            Column::int("StartingCHS"),
            Column::int("StartingSector"),
            Column::int("EndingCylinder"),
            Column::int("EndingCHS"),
            Column::int("EndingSector"),
        ]);
    }
    columns.push(Column::new("SectorInSize", ColumnType::UInt));
    columns.push(Column::string("Disasm"));
    if full {
        columns.push(Column::bytes("Bootcode"));
    }
    columns
}

/// The four bytes a disk is identified by.
fn disk_signature(table: &crate::framework::objects::Object) -> String {
    let byte = |at: u64| -> u64 {
        table
            .member("DiskSignature")
            .and_then(|array| array.index(at))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
    };
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}",
        byte(0),
        byte(1),
        byte(2),
        byte(3)
    )
}

/// What a partition says it holds.
fn partition_type(entry: &crate::framework::objects::Object) -> String {
    let Ok(kind) = entry.member("PartitionType") else {
        return "Not Defined PartitionType".to_string();
    };
    let known = kind
        .as_i64()
        .ok()
        .and_then(|value| {
            kind.resolved_template()
                .ok()
                .and_then(|template| template.as_enum().map(|kind| kind.is_valid_choice(value)))
        })
        .unwrap_or(false);
    if !known {
        return "Not Defined PartitionType".to_string();
    }
    kind.enum_name()
        .unwrap_or_else(|_| "Not Defined PartitionType".to_string())
}

/// The digest a record is identified by.
fn hash(data: &[u8]) -> String {
    let mut digest = Md5::new();
    digest.update(data);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
