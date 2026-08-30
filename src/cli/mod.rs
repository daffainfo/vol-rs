//! The command line interface.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod args;
pub mod help;
pub mod runner;

pub use runner::run_cli;
