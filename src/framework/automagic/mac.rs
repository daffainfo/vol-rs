//! Identifying a Mac image.
//!
//! Mac kernels are recognised the same way as Linux ones, by a version banner
//! that also identifies the exact build, but the banner text and the symbol
//! sub-directory differ.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::automagic::symbol_finder::{first_known_banner, BannerIndex};
use crate::framework::automagic::DetectedOs;
use crate::framework::context::{Context, Module};
use crate::framework::layers::intel::{IntelLayer, INTEL_32E};
use crate::framework::symbols::intermed::{create_table, SymbolFinder};

/// The banner prefix Darwin kernels write.
const BANNER_PREFIX: &str = "Darwin Kernel Version ";

/// Detect a Mac image and build its kernel layer.
pub fn detect(
    context: &Arc<Context>,
    physical_layer: &str,
    finder: &SymbolFinder,
) -> Result<Option<DetectedOs>> {
    // As for Linux: knowing which banners we have symbols for lets the scan
    // stop at the first useful one.
    let index = BannerIndex::build(finder, "mac");
    if index.is_empty() {
        log::debug!("No Mac symbol files are installed");
        return Ok(None);
    }

    let banners = first_known_banner(context, physical_layer, BANNER_PREFIX, |banner| {
        index.lookup(banner).is_some()
    })?
    .into_iter()
    .collect::<Vec<_>>();
    if banners.is_empty() {
        return Ok(None);
    }

    for found in &banners {
        let Some(location) = index.lookup(&found.banner) else {
            continue;
        };
        log::info!(
            "Matched banner '{}' to symbols at {}",
            found.banner,
            location.display()
        );

        let table_name = context.symbol_space.free_table_name("kernel_symbols");
        let table = create_table(&table_name, location.load()?);
        table.set_source(location.url());
        context.add_symbol_table(table);

        // The Mac kernel's page tables are reached through the IdlePML4, whose
        // symbol address is a physical one already.
        let qualified = crate::framework::symbols::join_name(&table_name, "IdlePML4");
        let Ok(symbol) = context.symbol_space.get_symbol(&qualified) else {
            log::debug!("Symbol file has no IdlePML4; cannot locate page tables");
            continue;
        };

        let layer_name = context.layers.free_name("layer_name");
        context.layers.add(Arc::new(IntelLayer::new(
            &layer_name,
            physical_layer,
            symbol.address,
            INTEL_32E,
        )));

        let module_name = "kernel".to_string();
        context.add_module(
            Module::new(&module_name, &table_name, &layer_name, 0)
                .with_absolute_addresses(true),
        );

        return Ok(Some(DetectedOs {
            layer_name,
            module_name: Some(module_name),
        }));
    }

    Ok(None)
}
