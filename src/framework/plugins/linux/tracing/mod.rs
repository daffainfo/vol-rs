//! Linux tracing-subsystem plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod ftrace;
pub mod tracepoints;
pub mod perf_events;

use std::sync::Arc;

use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(ftrace::CheckFtrace));
    registry.add(Arc::new(tracepoints::CheckTracepoints));
    registry.add(Arc::new(perf_events::PerfEvents));
}
