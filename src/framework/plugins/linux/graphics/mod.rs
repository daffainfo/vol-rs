//! Linux graphics plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod fbdev;

use std::sync::Arc;

use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(fbdev::Fbdev));
}
