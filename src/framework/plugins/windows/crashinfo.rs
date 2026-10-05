//! The header records how the dump was produced and where the kernel's key
//! structures were, which is useful for confirming an image is what it claims
//! to be before trusting anything else read from it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::array_to_string;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::conversion::wintime_to_datetime;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

/// Lists the information from a Windows crash dump.
pub struct CrashInfo;

/// A bitmap dump records which pages it kept in a summary block that follows
/// the header, one page further in on a 64-bit dump than on a 32-bit one.
const PAGE_SIZE: u64 = 0x1000;

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
            Column::int("MachineImageType"),
            Column::int("NumberProcessors"),
            Column::new("KdDebuggerDataBlock", ColumnType::UInt),
            Column::string("DumpType"),
            Column::string("SystemUpTime"),
            Column::string("Comment"),
            Column::datetime("SystemTime"),
            Column::new("BitmapHeaderSize", ColumnType::UInt),
            Column::new("BitmapSize", ColumnType::UInt),
            Column::new("BitmapPages", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, _config: &Configuration) -> Result<TreeGrid> {
        // The crash layer knows the file it was built over, and the header
        // lives at the start of that file. An unrecognised dump type should
        // never happen, since the crash layer only accepts 0x1 and 0x5.
        let crash = match context
            .layers
            .names()
            .into_iter()
            .filter_map(|name| context.layers.get(&name).ok())
            .find(|layer| layer.kind().starts_with("WindowsCrashDump"))
        {
            Some(crash) => crash,
            None => {
                // Upstream says so on the error stream and then gives up with
                // nothing to render at all, not even a header.
                eprintln!(
                    "ERROR    volatility3.plugins.windows.crashinfo: This plugin requires a \
                     Windows crash dump"
                );
                let mut grid = TreeGrid::new(self.columns());
                grid.mark_discarded();
                return Ok(grid);
            }
        };
        let sixty_four_bit = crash.kind() == "WindowsCrashDump64Layer";
        let base = crash
            .dependencies()
            .into_iter()
            .next()
            .ok_or_else(|| VolatilityError::Other("Crash layer has no base".to_string()))?;

        // The header's own layout ships as a symbol file, one per width, and
        // the summary block a bitmap dump carries is described by a third.
        let (table, header_type, header_pages) = if sixty_four_bit {
            ("crash64", "_DUMP_HEADER64", 2)
        } else {
            ("crash", "_DUMP_HEADER", 1)
        };
        context.ensure_table(table, "windows", table)?;
        context.ensure_table("crash_common", "windows", "crash_common")?;

        let template = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(table, header_type))?;
        let header = context.object_from_template(template, &base, 0);

        let text = |member: &str| -> Value {
            match header.member(member).and_then(|field| array_to_string(&field)) {
                Ok(value) => Value::string(value),
                Err(_) => Value::unreadable(),
            }
        };
        let number = |member: &str| -> Option<u64> {
            header
                .member(member)
                .and_then(|field| field.as_u64())
                .ok()
        };
        let integer = |member: &str| -> Value {
            match number(member) {
                Some(value) => Value::int(value as i64),
                None => Value::unreadable(),
            }
        };
        let address = |member: &str| -> Value {
            match number(member) {
                Some(value) => Value::hex(value),
                None => Value::unreadable(),
            }
        };

        let dump_type = number("DumpType");
        let kind = match dump_type {
            Some(0x1) => Value::string("Full Dump (0x1)"),
            Some(0x5) => Value::string("Bitmap Dump (0x5)"),
            // The layer only accepts those two, so this should not arise.
            Some(other) => Value::string(format!("Unknown/Unsupported ({other:#x})")),
            None => Value::unreadable(),
        };

        let uptime = match number("SystemUpTime") {
            Some(value) => Value::string(uptime_text(value)),
            None => Value::unreadable(),
        };

        let time = match number("SystemTime").and_then(wintime_to_datetime) {
            Some(value) => Value::DateTime(value),
            None => Value::unreadable(),
        };

        // Only a bitmap dump has a summary block. A full dump reports these
        // three as not applicable rather than as missing.
        let (bitmap_header_size, bitmap_size, bitmap_pages) = if dump_type == Some(0x5) {
            let summary = context
                .symbol_space
                .get_type(&crate::framework::symbols::join_name(
                    "crash_common",
                    "_SUMMARY_DUMP",
                ))
                .map(|template| {
                    context.object_from_template(template, &base, PAGE_SIZE * header_pages)
                });
            let field = |name: &str| -> Value {
                match summary
                    .as_ref()
                    .ok()
                    .and_then(|summary| summary.member(name).ok())
                    .and_then(|field| field.as_u64().ok())
                {
                    Some(value) => Value::hex(value),
                    None => Value::unreadable(),
                }
            };
            (field("HeaderSize"), field("BitmapSize"), field("Pages"))
        } else {
            // A full dump carries no summary block, so these three describe
            // nothing rather than being unavailable.
            (
                Value::not_applicable(),
                Value::not_applicable(),
                Value::not_applicable(),
            )
        };

        let mut grid = TreeGrid::new(self.columns());
        grid.push(
            0,
            vec![
                text("Signature"),
                integer("MajorVersion"),
                integer("MinorVersion"),
                address("DirectoryTableBase"),
                address("PfnDataBase"),
                address("PsLoadedModuleList"),
                address("PsActiveProcessHead"),
                integer("MachineImageType"),
                integer("NumberProcessors"),
                address("KdDebuggerDataBlock"),
                kind,
                uptime,
                text("Comment"),
                time,
                bitmap_header_size,
                bitmap_size,
                bitmap_pages,
            ],
        )?;
        Ok(grid)
    }
}

/// How long the system had been up, written the way a Python timedelta writes
/// itself.
///
/// The header counts hundred-nanosecond intervals. Upstream divides that by
/// ten to get microseconds, in floating point, and the rounding that follows
/// breaks ties towards the even microsecond.
fn uptime_text(intervals: u64) -> String {
    let microseconds = (intervals as f64 / 10.0).round_ties_even() as u64;
    let days = microseconds / 86_400_000_000;
    let rest = microseconds % 86_400_000_000;
    let seconds = rest / 1_000_000;
    let fraction = rest % 1_000_000;

    let (minutes, second) = (seconds / 60, seconds % 60);
    let (hours, minute) = (minutes / 60, minutes % 60);
    let mut text = format!("{hours}:{minute:02}:{second:02}");
    if days != 0 {
        let plural = if days == 1 { "" } else { "s" };
        text = format!("{days} day{plural}, {text}");
    }
    if fraction != 0 {
        text = format!("{text}.{fraction:06}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::uptime_text;

    #[test]
    fn an_uptime_is_written_the_way_a_timedelta_is() {
        // Hundred-nanosecond intervals in, a day and change out.
        assert_eq!(uptime_text(0), "0:00:00");
        assert_eq!(uptime_text(10_000_000), "0:00:01");
        assert_eq!(uptime_text(36_000_000_000), "1:00:00");
        assert_eq!(uptime_text(864_000_000_000), "1 day, 0:00:00");
        assert_eq!(uptime_text(1_728_000_000_000), "2 days, 0:00:00");
        assert_eq!(uptime_text(12_345_678), "0:00:01.234568");
    }
}
