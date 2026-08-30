//! Error types for the Volatility 3 framework.
//!
//! Mirrors the exception hierarchy of `volatility3.framework.exceptions`.
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0 (https://www.volatilityfoundation.org/license/vsl-v1.0).

use std::fmt;

/// The kind of address failure that occurred, used to let callers skip
/// efficiently over regions that are known to be unmapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFault {
    /// A plain invalid address with no further paging information.
    Invalid,
    /// A paging failure: `invalid_bits` records how many low bits of the
    /// requested address were still unresolved when translation failed, which
    /// allows a scan to skip the whole unmapped region in one step.
    Paged { invalid_bits: u32, entry: u64 },
    /// A paged fault where the page has been swapped out to a swap layer.
    Swapped {
        invalid_bits: u32,
        entry: u64,
        swap_offset: u64,
    },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum VolatilityError {
    #[error("Layer {layer}: invalid address {address:#x}: {message}")]
    InvalidAddress {
        layer: String,
        address: u64,
        message: String,
        fault: AddressFault,
    },

    #[error("Layer {layer}: {message}")]
    Layer { layer: String, message: String },

    #[error("Symbol error{}: {message}", .table.as_deref().map(|t| format!(" in table {t}")).unwrap_or_default())]
    Symbol {
        table: Option<String>,
        name: Option<String>,
        message: String,
    },

    #[error("Symbol space error: {0}")]
    SymbolSpace(String),

    #[error("Unsatisfied requirements: {0:?}")]
    Unsatisfied(Vec<String>),

    #[error("Missing module: {0}")]
    MissingModule(String),

    #[error("Render error: {0}")]
    Render(String),

    #[error("Plugin requirement not met: {0}")]
    PluginRequirement(String),

    #[error("Version mismatch: {0}")]
    VersionMismatch(String),

    #[error("Offline: cannot access {0}")]
    Offline(String),

    #[error("{0}")]
    Other(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("JSON error: {0}")]
    Json(String),
}

impl From<std::io::Error> for VolatilityError {
    fn from(e: std::io::Error) -> Self {
        VolatilityError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for VolatilityError {
    fn from(e: serde_json::Error) -> Self {
        VolatilityError::Json(e.to_string())
    }
}

impl VolatilityError {
    /// Construct a plain invalid-address error.
    pub fn invalid_address(layer: impl Into<String>, address: u64, message: impl Into<String>) -> Self {
        VolatilityError::InvalidAddress {
            layer: layer.into(),
            address,
            message: message.into(),
            fault: AddressFault::Invalid,
        }
    }

    /// Construct a paging fault, recording how many bits remained unresolved.
    pub fn paged(
        layer: impl Into<String>,
        address: u64,
        invalid_bits: u32,
        entry: u64,
        message: impl Into<String>,
    ) -> Self {
        VolatilityError::InvalidAddress {
            layer: layer.into(),
            address,
            message: message.into(),
            fault: AddressFault::Paged { invalid_bits, entry },
        }
    }

    pub fn layer(layer: impl Into<String>, message: impl Into<String>) -> Self {
        VolatilityError::Layer {
            layer: layer.into(),
            message: message.into(),
        }
    }

    pub fn symbol(table: Option<String>, name: Option<String>, message: impl Into<String>) -> Self {
        VolatilityError::Symbol {
            table,
            name,
            message: message.into(),
        }
    }

    /// True when the error represents an unreadable address, which callers
    /// routinely treat as "skip this item" rather than a hard failure.
    pub fn is_invalid_address(&self) -> bool {
        matches!(self, VolatilityError::InvalidAddress { .. })
    }

    /// The number of low address bits known to be unmapped, if any. Scanners
    /// use this to jump past whole unmapped page tables.
    pub fn invalid_bits(&self) -> Option<u32> {
        match self {
            VolatilityError::InvalidAddress { fault, .. } => match fault {
                AddressFault::Paged { invalid_bits, .. }
                | AddressFault::Swapped { invalid_bits, .. } => Some(*invalid_bits),
                AddressFault::Invalid => None,
            },
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, VolatilityError>;

/// Helper for building `Other` errors with formatting.
#[macro_export]
macro_rules! vol_err {
    ($($arg:tt)*) => {
        $crate::error::VolatilityError::Other(format!($($arg)*))
    };
}

/// A newtype used when rendering the framework version.
pub struct Version(pub u32, pub u32, pub u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}
