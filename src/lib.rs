//! A Rust port of the Volatility 3 memory forensics framework.
//!
//! The module layout mirrors the Python original so that plugins and framework
//! concepts map across one-to-one:
//!
//! - [`framework::layers`]: sources of bytes and the translations over them
//! - [`framework::symbols`]: ISF symbol tables and the space holding them
//! - [`framework::objects`]: typed views onto bytes in a layer
//! - [`framework::context`]: what an analysis run operates on
//! - [`framework::renderers`]: the tree-grid output format
//! - [`framework::automagic`]: working out how to stack layers for an image
//! - [`framework::plugins`]: the analysis plugins themselves
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0
//! (https://www.volatilityfoundation.org/license/vsl-v1.0).

pub mod constants;
pub mod error;
pub mod framework;
pub mod cli;

pub use error::{Result, VolatilityError};

/// The framework interface version, which plugins declare compatibility with.
pub fn interface_version() -> (u32, u32, u32) {
    (
        constants::VERSION_MAJOR,
        constants::VERSION_MINOR,
        constants::VERSION_PATCH,
    )
}
