//! Recover the kernel log ring buffer.
//!
//! The buffer holds a sequence of records, each with a header giving its length
//! and metadata, followed by the message text. Reading it recovers boot
//! messages, driver errors and anything else the kernel logged.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct Kmsg;

/// The syslog facilities, by their numeric value.
const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp",
];

/// The syslog severities, most severe first.
const LEVELS: &[&str] = &[
    "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug",
];

impl Plugin for Kmsg {
    fn name(&self) -> &'static str {
        "linux.kmsg.Kmsg"
    }

    fn description(&self) -> &'static str {
        "Kernel log buffer reader"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("facility"),
            Column::string("level"),
            Column::string("timestamp"),
            Column::string("caller"),
            Column::string("line"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        // Kernel 5.10 replaced the flat log buffer with a pair of rings: one of
        // record descriptors, one of the text they point at.
        // `prb` is a pointer to whichever ring buffer is in use: the static one
        // on small systems, a larger allocation on machines with many CPUs.
        let address = context
            .object_from_symbol(&kernel, "prb", None)?
            .pointer_value()?;
        let rings = context.module_object(&kernel, "printk_ringbuffer", address)?;

        let descriptors = rings.member("desc_ring")?;
        let text_ring = rings.member("text_data_ring")?;

        let count = 1u64 << descriptors.member("count_bits")?.as_u64()?;
        let descriptor_base = descriptors.member("descs")?.pointer_value()?;
        let info_base = descriptors.member("infos")?.pointer_value()?;

        let descriptor_type = context.symbol_space.get_type(&kernel.qualified("prb_desc"))?;
        let info_type = context.symbol_space.get_type(&kernel.qualified("printk_info"))?;
        let descriptor_size = context.symbol_space.size_of(&descriptor_type)?;
        let info_size = context.symbol_space.size_of(&info_type)?;

        // The top two bits of a descriptor's state word hold its state. The rest
        // is the record id.
        let pointer_bits = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size() as u64 * 8)
            .unwrap_or(64);
        let flags_shift = pointer_bits - 2;
        let id_mask = !(3u64 << flags_shift);

        let text_size_bits = text_ring.member("size_bits")?.as_u64()?;
        let text_mask = 1u64 << text_size_bits;
        let text_base = text_ring.member("data")?.pointer_value()?;
        let identifier_size = pointer_bits / 8;

        let mut current = descriptors.member("tail_id")?.member("counter")?.as_u64()?;
        let mut end: Option<u64> = None;

        while Some(current) != end {
            end = Some(descriptors.member("head_id")?.member("counter")?.as_u64()?);
            let index = current % count;

            let descriptor = context.object_from_template(
                descriptor_type.clone(),
                &kernel.layer_name,
                descriptor_base + index * descriptor_size,
            );
            let info = context.object_from_template(
                info_type.clone(),
                &kernel.layer_name,
                info_base + index * info_size,
            );

            let state = descriptor
                .member("state_var")
                .and_then(|state| state.member("counter"))
                .and_then(|value| value.as_u64())
                .map(|value| (value >> flags_shift) & 3)
                .unwrap_or(0);

            // Only a committed or finalised record holds text worth reading.
            if state == 1 || state == 2 {
                let facility = info.member("facility").and_then(|v| v.as_u64()).unwrap_or(0);
                let level = info.member("level").and_then(|v| v.as_u64()).unwrap_or(0);
                let nanoseconds = info.member("ts_nsec").and_then(|v| v.as_u64()).unwrap_or(0);
                let caller = info
                    .member("caller_id")
                    .and_then(|value| value.as_u64())
                    .map(|id| {
                        let kind = if id & 0x8000_0000 != 0 { "CPU" } else { "Task" };
                        format!("{kind}({})", id & !0x8000_0000)
                    })
                    .ok();

                // A record may also carry the device that produced it, which is
                // reported as extra lines after the message itself.
                let mut lines = record_lines(
                    &context,
                    &kernel.layer_name,
                    &descriptor,
                    &info,
                    text_base,
                    text_mask,
                    identifier_size,
                );
                for (member, label) in [("subsystem", "SUBSYSTEM"), ("device", "DEVICE")] {
                    if let Ok(text) = info
                        .member("dev_info")
                        .and_then(|dev| dev.member(member))
                        .and_then(|value| value.as_string())
                    {
                        if !text.is_empty() {
                            lines.push(format!(" {label}={text}"));
                        }
                    }
                }

                for line in lines {
                    grid.push(
                        0,
                        vec![
                            Value::string(facility_name(facility)),
                            Value::string(level_name(level)),
                            // Printed as whole seconds and microseconds, which
                            // is what the kernel's own print_time does.
                            Value::string(format!(
                                "{}.{:06}",
                                nanoseconds / 1_000_000_000,
                                (nanoseconds % 1_000_000_000) / 1000
                            )),
                            match &caller {
                                Some(text) => Value::string(text.clone()),
                                None => Value::not_available(),
                            },
                            Value::string(line),
                        ],
                    )?;
                }
            }

            current = (current + 1) & id_mask;
        }
        Ok(grid)
    }
}

/// The text of one log record, split into lines.
///
/// Each block in the text ring is preceded by the id of the record that owns
/// it, so the text begins one identifier past the block's start.
fn record_lines(
    context: &Arc<Context>,
    layer: &str,
    descriptor: &crate::framework::objects::Object,
    info: &crate::framework::objects::Object,
    text_base: u64,
    text_mask: u64,
    identifier_size: u64,
) -> Vec<String> {
    let Ok(position) = descriptor.member("text_blk_lpos") else {
        return Vec::new();
    };
    let (Ok(begin), Ok(next)) = (
        position.member("begin").and_then(|v| v.as_u64()),
        position.member("next").and_then(|v| v.as_u64()),
    ) else {
        return Vec::new();
    };

    let mut begin = begin % text_mask;
    let end = next % text_mask;
    // An odd offset marks a record that carries no text at all.
    if begin & 1 != 0 {
        return Vec::new();
    }
    // A block that wraps starts again at the beginning of the ring.
    if begin > end {
        begin = 0;
    }

    let declared = info.member("text_len").and_then(|v| v.as_u64()).unwrap_or(0);
    let length = declared.min(end.saturating_sub(begin));
    if length == 0 {
        return Vec::new();
    }

    let address = text_base + begin + identifier_size;
    let Ok(data) = context.layers.read(layer, address, length as usize, false) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&data)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The syslog facility name for a numeric value.
fn facility_name(facility: u64) -> String {
    FACILITIES
        .get(facility as usize)
        .map(|name| name.to_string())
        .unwrap_or_else(|| facility.to_string())
}

/// The syslog level name for a numeric value.
fn level_name(level: u64) -> String {
    LEVELS
        .get(level as usize)
        .map(|name| name.to_string())
        .unwrap_or_else(|| level.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facilities_and_levels_are_named() {
        assert_eq!(facility_name(0), "kern");
        assert_eq!(level_name(6), "info");
        // A value the kernel has grown beyond our table is shown as itself.
        assert_eq!(facility_name(99), "99");
        assert_eq!(level_name(42), "42");
    }

    #[test]
    fn caller_ids_name_the_cpu_or_the_task() {
        let describe = |id: u64| {
            let kind = if id & 0x8000_0000 != 0 { "CPU" } else { "Task" };
            format!("{kind}({})", id & !0x8000_0000)
        };
        assert_eq!(describe(1), "Task(1)");
        assert_eq!(describe(0x8000_0003), "CPU(3)");
    }
}
