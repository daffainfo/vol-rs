//! Conversions between the raw values found in memory and the forms plugins
//! report: timestamps, GUIDs, IP addresses and alignment helpers.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use chrono::{DateTime, Datelike, TimeZone, Utc};

use crate::framework::renderers::{AbsentValue, Value};

/// Windows counts 100-nanosecond intervals from 1601-01-01. Unix counts seconds
/// from 1970-01-01. This is the gap between the two epochs, in seconds.
const WINDOWS_TO_UNIX_EPOCH_SECONDS: i64 = 11_644_473_600;
/// 100-nanosecond intervals per second.
const INTERVALS_PER_SECOND: i64 = 10_000_000;

/// Convert a Windows `FILETIME` into a UTC timestamp.
///
/// Returns `None` for zero (meaning "never set"), and for values that fall
/// outside the range a calendar date can represent, which is the usual sign of
/// a field that was misread rather than a genuine date.
pub fn wintime_to_datetime(wintime: u64) -> Option<DateTime<Utc>> {
    // Whole seconds only: the hundred-nanosecond part is divided away before
    // the epoch is shifted, so every Windows time reports as a round second.
    // The count is signed and divided towards negative infinity, so a value of
    // all ones lands just before the epoch rather than far beyond it.
    let seconds = (wintime as i64).div_euclid(INTERVALS_PER_SECOND);
    if seconds == 0 {
        return None;
    }
    Utc.timestamp_opt(seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS, 0)
        .single()
        // A timestamp outside the years a date can name is not one. Upstream's
        // conversion fails the same way, and the cell is left empty.
        .filter(|when| (1..=9999).contains(&when.year()))
}

/// Convert a Unix timestamp in seconds into a UTC timestamp.
pub fn unixtime_to_datetime(unixtime: i64) -> Option<DateTime<Utc>> {
    if unixtime <= 0 {
        return None;
    }
    Utc.timestamp_opt(unixtime, 0).single()
}

/// Convert a Unix timestamp with a separate nanosecond component.
///
/// Timestamps are reported to microsecond precision, so the nanosecond part is
/// rounded to the nearest microsecond rather than truncated. Truncating puts
/// roughly half of all timestamps one microsecond behind the reference
/// implementation.
pub fn unixtime_nanos_to_datetime(seconds: i64, nanoseconds: u32) -> Option<DateTime<Utc>> {
    if seconds <= 0 {
        return None;
    }

    let microseconds = (nanoseconds as u64 + 500) / 1000;
    // Rounding up from the last microsecond of a second carries into the next.
    let (seconds, microseconds) = if microseconds >= 1_000_000 {
        (seconds + 1, microseconds - 1_000_000)
    } else {
        (seconds, microseconds)
    };

    Utc.timestamp_opt(seconds, (microseconds * 1000) as u32).single()
}

/// Convert a Unix timestamp given as fractional seconds.
///
/// The reference implementation reaches every Linux timestamp through a Python
/// float and `datetime.fromtimestamp`, which rounds to the nearest microsecond
/// with ties going to even. Reproducing that arithmetic, including the
/// precision the float itself loses, is what makes the rendered microseconds
/// agree.
pub fn unixtime_float_to_datetime(unixtime: f64) -> Option<DateTime<Utc>> {
    if !(unixtime > 0.0) {
        return None;
    }
    let whole = unixtime.trunc();
    let fraction = unixtime - whole;

    let mut seconds = whole as i64;
    let mut microseconds = (fraction * 1_000_000.0).round_ties_even() as i64;
    if microseconds >= 1_000_000 {
        seconds += 1;
        microseconds -= 1_000_000;
    } else if microseconds < 0 {
        seconds -= 1;
        microseconds += 1_000_000;
    }

    Utc.timestamp_opt(seconds, (microseconds * 1000) as u32).single()
}

/// Convert seconds since the epoch into a timestamp with no zone attached.
///
/// One plugin upstream builds its timestamp with `datetime.fromtimestamp` and
/// no timezone, which reads the clock in the machine's own zone and leaves the
/// result unlabelled. The fraction is rounded to microseconds the way Python
/// rounds it, ties to even.
pub fn local_naive_from_unixtime(unixtime: f64) -> Option<chrono::NaiveDateTime> {
    use chrono::TimeZone;

    let whole = unixtime.trunc();
    let fraction = unixtime - whole;
    let mut seconds = whole as i64;
    let mut microseconds = (fraction * 1_000_000.0).round_ties_even() as i64;
    if microseconds >= 1_000_000 {
        seconds += 1;
        microseconds -= 1_000_000;
    } else if microseconds < 0 {
        seconds -= 1;
        microseconds += 1_000_000;
    }

    chrono::Local
        .timestamp_opt(seconds, (microseconds * 1000) as u32)
        .single()
        .map(|when| when.naive_local())
}

/// The same as a cell, absent when the number names no time at all.
pub fn local_naive_value(unixtime: f64) -> Value {
    match local_naive_from_unixtime(unixtime) {
        Some(when) => Value::NaiveDateTime(when),
        None => Value::Absent(AbsentValue::Unparsable),
    }
}

/// Convert a kernel `timespec64` into a timestamp.
pub fn timespec_to_datetime(seconds: i64, nanoseconds: i64) -> Option<DateTime<Utc>> {
    unixtime_float_to_datetime(seconds as f64 + nanoseconds as f64 / 1_000_000_000.0)
}

/// Split a nanosecond count into a `timespec64`, as `ns_to_timespec64` does.
///
/// The division is deliberately done in double precision. The reference
/// implementation defines its nanoseconds-per-second constant as `1e9`, a
/// float, so both the quotient and the remainder are computed as doubles. For a
/// boot timestamp, some 1.8e18 nanoseconds, that exceeds the 53 bits a double
/// carries and quietly drops the low digits. Computing this exactly instead
/// would put the rendered microseconds one out.
pub fn ns_to_timespec64(nanoseconds: i64) -> (i64, i64) {
    const NSEC_PER_SEC: f64 = 1e9;
    if nanoseconds == 0 {
        return (0, 0);
    }

    if nanoseconds > 0 {
        let value = nanoseconds as f64;
        let seconds = (value / NSEC_PER_SEC).floor();
        return (seconds as i64, (value - seconds * NSEC_PER_SEC) as i64);
    }

    let value = (-nanoseconds - 1) as f64;
    let seconds = (value / NSEC_PER_SEC).floor();
    let remainder = value - seconds * NSEC_PER_SEC;
    (
        -(seconds as i64) - 1,
        (NSEC_PER_SEC - remainder - 1.0) as i64,
    )
}

/// Render a timestamp as a cell, marking an unset or nonsensical value absent
/// rather than printing a misleading date.
pub fn wintime_value(wintime: u64) -> Value {
    // A time of zero is a time the system never recorded, which is different
    // from one it recorded and no calendar can name.
    if (wintime as i64).div_euclid(INTERVALS_PER_SECOND) == 0 {
        return Value::Absent(AbsentValue::NotApplicable);
    }
    match wintime_to_datetime(wintime) {
        Some(when) => Value::DateTime(when),
        None => Value::Absent(AbsentValue::Unparsable),
    }
}

/// Render a Windows timestamp held in a field that cannot be negative.
///
/// A field declared unsigned counts forward however large it grows, so a value
/// with the top bit set names a year far beyond any calendar rather than a
/// moment just before the epoch. Which of the two a plugin means is decided by
/// the field it read, not by the number.
pub fn wintime_unsigned_value(wintime: u64) -> Value {
    let seconds = (wintime / INTERVALS_PER_SECOND as u64) as i128;
    if seconds == 0 {
        return Value::Absent(AbsentValue::NotApplicable);
    }
    let unix = seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS as i128;
    let Ok(unix) = i64::try_from(unix) else {
        return Value::Absent(AbsentValue::Unparsable);
    };
    match Utc
        .timestamp_opt(unix, 0)
        .single()
        .filter(|when| (1..=9999).contains(&when.year()))
    {
        Some(when) => Value::DateTime(when),
        None => Value::Absent(AbsentValue::Unparsable),
    }
}

/// Render a Unix timestamp with a nanosecond part as a cell.
pub fn unixtime_nanos_value(seconds: i64, nanoseconds: u32) -> Value {
    match unixtime_nanos_to_datetime(seconds, nanoseconds) {
        Some(when) => Value::DateTime(when),
        None => Value::Absent(AbsentValue::NotApplicable),
    }
}

/// Render a Unix timestamp as a cell.
pub fn unixtime_value(unixtime: i64) -> Value {
    match unixtime_to_datetime(unixtime) {
        Some(when) => Value::DateTime(when),
        None => Value::Absent(AbsentValue::NotApplicable),
    }
}

/// Format a 16-byte Windows GUID.
///
/// The first three fields are stored little-endian and the last two big-endian,
/// which is why the halves are treated differently.
pub fn windows_bytes_to_guid(buffer: &[u8]) -> Option<String> {
    if buffer.len() < 16 {
        return None;
    }
    let data1 = u32::from_le_bytes(buffer[0..4].try_into().ok()?);
    let data2 = u16::from_le_bytes(buffer[4..6].try_into().ok()?);
    let data3 = u16::from_le_bytes(buffer[6..8].try_into().ok()?);
    let data4 = &buffer[8..16];
    Some(format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{}",
        data4[0],
        data4[1],
        data4[2..].iter().map(|b| format!("{b:02X}")).collect::<String>()
    ))
}

/// Round `address` down (or up) to a multiple of `align`.
pub fn round(address: u64, align: u64, up: bool) -> u64 {
    if align == 0 {
        return address;
    }
    let remainder = address % align;
    if remainder == 0 {
        return address;
    }
    if up {
        address + (align - remainder)
    } else {
        address - remainder
    }
}

/// Format a big-endian IPv4 address held in a 32-bit integer.
pub fn convert_ipv4(address: u32) -> String {
    // The bytes are already in network order in memory. Reading them back out
    // little-endian reproduces that order, which is what upstream's
    // `struct.pack("<I", ...)` does.
    let octets = address.to_le_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Format a 16-byte IPv6 address, collapsing the longest run of zero groups.
pub fn convert_ipv6(packed: &[u8]) -> String {
    if packed.len() < 16 {
        return String::new();
    }
    let groups: Vec<u16> = packed[..16]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    std::net::Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    )
    .to_string()
}

/// Convert a port from network byte order.
pub fn convert_port(port: u16) -> u16 {
    port.to_be()
}

/// The address family constants Windows uses in socket structures.
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 23;

/// Render a socket address for the given family.
pub fn convert_network_address(family: u32, raw: &[u8]) -> Option<String> {
    match family {
        AF_INET if raw.len() >= 4 => Some(convert_ipv4(u32::from_le_bytes(
            raw[..4].try_into().ok()?,
        ))),
        AF_INET6 if raw.len() >= 16 => Some(convert_ipv6(raw)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_epoch_converts_to_the_unix_epoch() {
        // The FILETIME for 1970-01-01T00:00:00Z.
        let filetime = (WINDOWS_TO_UNIX_EPOCH_SECONDS * INTERVALS_PER_SECOND) as u64;
        let converted = wintime_to_datetime(filetime).unwrap();
        assert_eq!(converted.timestamp(), 0);
    }

    #[test]
    fn unset_timestamps_are_absent_rather_than_1601() {
        assert!(wintime_to_datetime(0).is_none());
        assert!(matches!(
            wintime_value(0),
            Value::Absent(AbsentValue::NotApplicable)
        ));
    }

    #[test]
    fn rounding_moves_in_the_requested_direction() {
        assert_eq!(round(0x1234, 0x1000, false), 0x1000);
        assert_eq!(round(0x1234, 0x1000, true), 0x2000);
        // An already-aligned value is left alone in both directions.
        assert_eq!(round(0x2000, 0x1000, true), 0x2000);
    }

    #[test]
    fn addresses_format_for_both_families() {
        // Stored network-order as 7f 00 00 01, which reads back as this value.
        assert_eq!(convert_ipv4(0x0100_007F), "127.0.0.1");
        let loopback = [0u8; 15].iter().copied().chain([1u8]).collect::<Vec<u8>>();
        assert_eq!(convert_ipv6(&loopback), "::1");
    }

    #[test]
    fn guids_mix_endianness_the_way_windows_stores_them() {
        let raw: Vec<u8> = vec![
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44,
        ];
        assert_eq!(
            windows_bytes_to_guid(&raw).unwrap(),
            "12345678-1234-5678-9ABC-DEF011223344"
        );
    }
}
