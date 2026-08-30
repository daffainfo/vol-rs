//! Plugins that work on any image, or on none at all.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod banners;
pub mod layerwriter;
pub mod isfinfo;
pub mod configwriter;
pub mod frameworkinfo;
pub mod regexscan;
pub mod yarascan;
pub mod vmscan;
pub mod timeliner;

use std::sync::Arc;

use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(banners::Banners));
    registry.add(Arc::new(layerwriter::LayerWriter));
    registry.add(Arc::new(isfinfo::IsfInfo));
    registry.add(Arc::new(configwriter::ConfigWriter));
    registry.add(Arc::new(frameworkinfo::FrameworkInfo));
    registry.add(Arc::new(regexscan::RegExScan));
    registry.add(Arc::new(yarascan::YaraScan));
    registry.add(Arc::new(vmscan::Vmscan));
    registry.add(Arc::new(timeliner::Timeliner));
}
