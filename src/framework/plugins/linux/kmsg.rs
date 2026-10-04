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

/// Kernel log buffer reader
pub struct Kmsg;

/// The syslog facilities, by their numeric value.
const FACILITIES: &[&str] = &[
    "kern",     // kernel messages
    "user",     // random user-level messages
    "mail",     // mail system
    "daemon",   // system daemons
    "auth",     // security/authorization messages
    "syslog",   // messages generated internally by syslogd
    "lpr",      // line printer subsystem
    "news",     // network news subsystem
    "uucp",     // UUCP subsystem
    "cron",     // clock daemon
    "authpriv", // security/authorization messages (private)
    "ftp",      // FTP daemon
];

/// The syslog severities, most severe first.
const LEVELS: &[&str] = &[
    "emerg",  // system is unusable
    "alert",  // action must be taken immediately
    "crit",   // critical conditions
    "err",    // error conditions
    "warn",   // warning conditions
    "notice", // normal but significant condition
    "info",   // informational
    "debug",  // debug-level messages
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

    /// Walks through the specific kernel implementation.
    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        let has_symbol = |name: &str| context.symbol_offset(&kernel, name).is_ok();
        let type_has = |type_name: &str, member: &str| {
            context
                .symbol_space
                .get_type(&kernel.qualified(type_name))
                .ok()
                .and_then(|template| {
                    context
                        .symbol_space
                        .find_member(&template, member)
                        .ok()
                        .map(|found| found.is_some())
                })
                .unwrap_or(false)
        };
        let has_type = |name: &str| {
            context
                .symbol_space
                .has_type(&kernel.qualified(name))
        };

        // Which implementation this kernel uses, tested in the order upstream
        // tests them.
        if has_symbol("log_end")
            && has_symbol("log_buf_len")
            && !has_symbol("log_first_idx")
            && !type_has("log", "ts_nsec")
        {
            // Before kernel 3.5 the buffer is one char array holding whole
            // lines, each with its own textual prefix.
            return flat_buffer(&context, &kernel, grid);
        }
        if type_has("log", "ts_nsec") && has_symbol("log_first_idx") {
            // 3.5 <= kernels < 3.11
            return record_buffer(&context, &kernel, grid, "log");
        }
        if !has_type("printk_ringbuffer")
            && type_has("printk_log", "ts_nsec")
            && has_symbol("log_first_idx")
        {
            // 3.11 <= kernels < 5.10, where the record type was renamed
            return record_buffer(&context, &kernel, grid, "printk_log");
        }
        if !(has_symbol("prb") && has_type("printk_ringbuffer")) {
            eprintln!(
                "ERROR    volatility3.plugins.linux.kmsg: Unsupported kernel ring buffer \
                 implementation. Please file a bug on our issue tracker with your specific \
                 kernel version."
            );
            return Ok(grid);
        }

        // Kernel 5.10 replaced the flat log buffer with a pair of rings: one
        // of record descriptors, one of the text they point at. See
        // kernel/printk/printk_ringbuffer.h.
        //
        // static struct printk_ringbuffer *prb = &printk_rb_static;
        //
        // `prb` is a pointer to whichever ring buffer is in use: the static
        // one on small systems, a larger allocation on machines with many
        // CPUs.
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
                            // See kernel/printk/printk.c:print_time(). Here,
                            // we could simply divide by a billion as a float.
                            // However, that will cause a roundoff error. For
                            // instance, using 17110365556 as input, the above
                            // will result in 17.110366, while the kernel
                            // print_time function will result in 17.110365.
                            // This might seem insignificant but it could cause
                            // some issues when compared with userland tool
                            // results or when used in timelines.
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
/// Each element in the ringbuffer is "ID + data", so the text begins one
/// identifier past the block's start. See the `prb_data_ring` struct.
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
    // This record doesn't contain text.
    if begin & 1 != 0 {
        return Vec::new();
    }
    // This means a wrap-around to the beginning of the buffer.
    if begin > end {
        begin = 0;
    }

    let declared = info.member("text_len").and_then(|v| v.as_u64()).unwrap_or(0);
    // Safety first ;)
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

/// The kernel log as a kernel before 3.5 keeps it: one character buffer of
/// whole lines, each carrying its level and timestamp as text.
fn flat_buffer(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    mut grid: TreeGrid,
) -> Result<TreeGrid> {
    let length = context
        .object_from_symbol(kernel, "log_buf_len", None)?
        .as_u64()?;
    // First, the ring buffer size is determined in the kernel configuration by
    // CONFIG_LOG_BUF_SHIFT. This static buffer is held in the '__log_buf'
    // global variable, with 'log_buf' serving as a pointer to it. The user can
    // also update this size using 'log_buf_len' in the kernel boot parameters.
    // Additionally, in SMP systems with over 64 CPUs, the ring buffer size
    // dynamically allocates based on the number of CPUs, following
    // CONFIG_LOG_CPU_MAX_BUF_SHIFT. In the last two cases mentioned above, the
    // 'log_buf' pointer is updated to this new buffer. The original static
    // buffer in '__log_buf' remains unused. Therefore, it is crucial to read
    // from 'log_buf' rather than '__log_buf'.
    let buffer = context.object_from_symbol(kernel, "log_buf", None)?;
    let mut text = crate::framework::objects::utility::pointer_to_string(&buffer, length as usize)?;
    let end = context
        .object_from_symbol(kernel, "log_end", None)?
        .as_u64()?;

    // Once the buffer has wrapped, the oldest line is wherever the writer is
    // about to overwrite, so the two halves are swapped back into order. If
    // there was a wrap-around in the ring buffer, it will find remnants at the
    // top. As those remnants do not conform to the expected line format, they
    // are discarded.
    if end > length {
        let start = (end - length) as usize;
        if start <= text.len() {
            text = format!("{}{}", &text[start..], &text[..start]);
        }
    }

    for line in crate::framework::objects::utility::python_splitlines(&text) {
        // A line that does not carry a prefix is a remnant of what the buffer
        // held before it wrapped.
        let Some((level_facility, timestamp, message)) = split_prefixed_line(line) else {
            continue;
        };
        grid.push(
            0,
            vec![
                // The lower 3 bit are the log level, the rest are the log
                // facility.
                Value::string(facility_name(level_facility >> 3)),
                Value::string(level_name(level_facility & 7)),
                Value::string(timestamp.to_string()),
                Value::not_available(),
                Value::string(message.to_string()),
            ],
        )?;
    }
    Ok(grid)
}

/// One line of a pre-3.5 log buffer, as `<level>[ timestamp] message`.
fn split_prefixed_line(line: &str) -> Option<(u64, &str, &str)> {
    let rest = line.strip_prefix('<')?;
    let (digits, rest) = rest.split_once('>')?;
    let level_facility: u64 = digits.parse().ok()?;
    let rest = rest.strip_prefix('[')?;
    let (timestamp, rest) = rest.split_once(']')?;
    let timestamp = timestamp.trim_start_matches(' ');
    // The timestamp is seconds and a fraction, both of them digits.
    let (seconds, fraction) = timestamp.split_once('.')?;
    if seconds.is_empty()
        || fraction.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let message = rest.strip_prefix(' ')?;
    Some((level_facility, timestamp, message))
}

/// The kernel log as kernels from 3.5 to 5.10 keep it: an array of records in a
/// character buffer, each record followed by its text and its key/value pairs.
fn record_buffer(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    mut grid: TreeGrid,
    record_type: &str,
) -> Result<TreeGrid> {
    let base = context
        .object_from_symbol(kernel, "log_buf", None)?
        .pointer_value()?;
    let length = context
        .object_from_symbol(kernel, "log_buf_len", None)?
        .as_u64()?;
    let first = context
        .object_from_symbol(kernel, "log_first_idx", None)?
        .as_u64()?;
    let next = context
        .object_from_symbol(kernel, "log_next_idx", None)?
        .as_u64()?;

    let template = context
        .symbol_space
        .get_type(&kernel.qualified(record_type))?;
    let record_size = context.symbol_space.size_of(&template)?;

    let mut current = first;
    let mut end = if first < next { next } else { length };
    while current < end {
        let record =
            context.object_from_template(template.clone(), &kernel.layer_name, base + current);
        let Ok(size) = record.member("len").and_then(|value| value.as_u64()) else {
            eprintln!(
                "WARNING  volatility3.plugins.linux.kmsg: Kmsg buffer msg length could not be read"
            );
            return Ok(grid);
        };
        if size == 0 {
            // As per kernel/printk.c: a length == 0 for the next message
            // indicates a wrap-around to the beginning of the buffer.
            current = 0;
            end = next;
            continue;
        }

        let facility = record.member("facility").and_then(|v| v.as_u64()).unwrap_or(0);
        let level = record.member("level").and_then(|v| v.as_u64()).unwrap_or(0);
        let nanoseconds = record.member("ts_nsec").and_then(|v| v.as_u64()).unwrap_or(0);
        let caller = record
            .member("caller_id")
            .and_then(|value| value.as_u64())
            .map(|id| {
                let kind = if id & 0x8000_0000 != 0 { "CPU" } else { "Task" };
                format!("{kind}({})", id & !0x8000_0000)
            })
            .ok();
        let timestamp = format!(
            "{}.{:06}",
            nanoseconds / 1_000_000_000,
            (nanoseconds % 1_000_000_000) / 1000
        );

        let text_length = record
            .member("text_len")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let mut lines: Vec<String> = Vec::new();
        if text_length > 0 {
            if let Ok(data) = context.layers.read(
                &kernel.layer_name,
                base + current + record_size,
                text_length as usize,
                false,
            ) {
                let text = String::from_utf8_lossy(&data).into_owned();
                lines.extend(
                    crate::framework::objects::utility::python_splitlines(&text)
                        .into_iter()
                        .map(str::to_string),
                );
            }
        }
        // The record may also carry key/value pairs, each of which is reported
        // as a line of its own.
        let dictionary_length = record
            .member("dict_len")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        if dictionary_length > 0 {
            if let Ok(data) = context.layers.read(
                &kernel.layer_name,
                base + current + record_size + text_length,
                dictionary_length as usize,
                false,
            ) {
                for chunk in data.split(|byte| *byte == 0) {
                    lines.push(format!(" {}", String::from_utf8_lossy(chunk)));
                }
            }
        }

        for line in lines {
            grid.push(
                0,
                vec![
                    Value::string(facility_name(facility)),
                    Value::string(level_name(level)),
                    Value::string(timestamp.clone()),
                    match &caller {
                        Some(text) => Value::string(text.clone()),
                        None => Value::not_available(),
                    },
                    Value::string(line),
                ],
            )?;
        }

        current += size;
    }
    Ok(grid)
}
