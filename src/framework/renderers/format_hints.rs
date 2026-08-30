//! Helpers for building cells with a particular presentation.
//!
//! Plugins use these instead of formatting values into strings, so that a JSON
//! or CSV renderer still receives a typed value rather than pre-formatted text.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::framework::renderers::{AbsentValue, NumberFormat, Value};

/// A value rendered in hexadecimal.
pub fn hex(value: u64) -> Value {
    Value::UInt(value, NumberFormat::Hex)
}

/// A signed value rendered in hexadecimal.
pub fn hex_signed(value: i64) -> Value {
    Value::Int(value, NumberFormat::Hex)
}

/// A value rendered in binary.
pub fn binary(value: u64) -> Value {
    Value::UInt(value, NumberFormat::Binary)
}

/// A value rendered in octal.
pub fn octal(value: u64) -> Value {
    Value::UInt(value, NumberFormat::Octal)
}

/// Raw bytes, rendered as hex or as text depending on their content.
pub fn hex_bytes(data: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(data.into())
}

/// Bytes that are probably text: decoded leniently, falling back to hex.
pub fn multi_type_data(data: &[u8]) -> Value {
    // The choice between text and a hex dump is made when the cell is rendered,
    // so that it follows one rule everywhere.
    Value::MultiTypeData(data.to_vec())
}

/// Lift a fallible read into a cell, marking failures unreadable.
///
/// This is the shape most plugin code wants: a field that could not be read
/// should leave a gap in the row, not abort the whole plugin.
pub fn or_unreadable<T, E>(result: std::result::Result<T, E>, format: impl Fn(T) -> Value) -> Value {
    match result {
        Ok(value) => format(value),
        Err(_) => Value::Absent(AbsentValue::Unreadable),
    }
}

/// As [`or_unreadable`], but for values that are simply not present.
pub fn or_absent<T, E>(result: std::result::Result<T, E>, format: impl Fn(T) -> Value) -> Value {
    match result {
        Ok(value) => format(value),
        Err(_) => Value::Absent(AbsentValue::NotAvailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_choose_the_rendering() {
        assert_eq!(hex(255).to_string(), "0xff");
        assert_eq!(binary(5).to_string(), "0b101");
        assert_eq!(octal(8).to_string(), "0o10");
    }

    #[test]
    fn failed_reads_become_absent_cells() {
        let failed: Result<u64, ()> = Err(());
        assert!(or_unreadable(failed, Value::uint).is_absent());
        let ok: Result<u64, ()> = Ok(7);
        assert_eq!(or_unreadable(ok, Value::uint).to_string(), "7");
    }

    #[test]
    fn text_like_bytes_render_as_text() {
        assert_eq!(multi_type_data(b"hello\0").to_string(), "hello");
        // A field that is mostly NUL padding is not text, so it is dumped.
        assert!(multi_type_data(b"ab\0\0\0\0\0\0")
            .to_string()
            .contains("61 62"));
    }
}
