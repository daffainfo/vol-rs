//! Framework-wide constants.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

/// Framework interface version (major, minor, patch), following SemVer:
/// major changes break plugin compatibility, minor additions are backwards
/// compatible, patch is bug fixes only.
pub const VERSION_MAJOR: u32 = 2;
pub const VERSION_MINOR: u32 = 28;
pub const VERSION_PATCH: u32 = 0;

/// Separator between a symbol table name and a symbol/type name, as in
/// `nt_symbols!_EPROCESS`.
pub const BANG: char = '!';

/// Default name given to the automatically constructed kernel virtual layer.
pub const DEFAULT_KERNEL_LAYER: &str = "kernel_layer";

/// Configuration path separator.
pub const CONFIG_SEPARATOR: char = '.';

/// The name of the automagic-populated primary module.
pub const KERNEL_MODULE_NAME: &str = "kernel";

/// Maximum length used when reading a NUL-terminated string of unknown size.
pub const MAX_STRING_LENGTH: usize = 1024;

/// Chunk size used by layer scanners (16MiB), and the overlap retained between
/// consecutive chunks so that matches straddling a boundary are still found.
pub const SCAN_CHUNK_SIZE: usize = 0x100_0000;
pub const SCAN_OVERLAP: usize = 0x1000;

/// Logging levels beyond DEBUG used by the Python implementation. Retained so
/// verbosity flags map onto the same meanings.
pub const LOGLEVEL_V: u8 = 1;
pub const LOGLEVEL_VV: u8 = 2;
pub const LOGLEVEL_VVV: u8 = 3;
pub const LOGLEVEL_VVVV: u8 = 4;

/// Parallelism modes available to scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parallelism {
    Off,
    Threading,
    Multiprocessing,
}

/// Well-known ISF format versions this implementation understands.
pub const SUPPORTED_ISF_VERSIONS: &[u32] = &[1, 2, 3, 4, 6];

/// Page size assumed for x86/x64 architectures.
pub const PAGE_SIZE: u64 = 0x1000;
