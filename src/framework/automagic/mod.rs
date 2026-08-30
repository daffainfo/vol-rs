//! Automagic: everything the framework works out for itself so the user does
//! not have to supply it.
//!
//! Given only an image file, this determines the format, builds the layer
//! stack, identifies the operating system, locates the page tables, loads the
//! matching symbols and constructs the kernel module.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod image_cache;
pub mod pdbscan;
pub mod stacker;
pub mod windows;
pub mod linux;
pub mod mac;
pub mod symbol_finder;

use std::path::Path;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::Context;
use crate::framework::plugins::OperatingSystem;
use crate::framework::symbols::intermed::SymbolFinder;

/// What automagic worked out about an image.
pub struct AutomagicResult {
    /// The layer holding physical memory.
    pub physical_layer: String,
    /// The layer holding kernel virtual memory, once paging is understood.
    pub kernel_layer: Option<String>,
    pub operating_system: OperatingSystem,
    /// Name of the module describing the kernel, if symbols were found.
    pub kernel_module: Option<String>,
    /// Human-readable notes about what was tried, for diagnosing failures.
    pub notes: Vec<String>,
}

/// Build the layer stack without identifying the operating system.
///
/// Plugins that read raw memory rather than kernel structures need only this,
/// and OS detection over a large image is expensive enough to be worth
/// avoiding when nothing will use the result.
pub fn stack_only(context: &Arc<Context>, image: &Path) -> Result<AutomagicResult> {
    let started = std::time::Instant::now();
    let stack = stacker::stack_image(&context.layers, image)?;
    log::debug!("Stacking layers took {:?}", started.elapsed());
    Ok(AutomagicResult {
        physical_layer: stack.top_layer.clone(),
        kernel_layer: None,
        operating_system: OperatingSystem::Any,
        kernel_module: None,
        notes: vec![format!("Stacked layers: {}", stack.created.join(" -> "))],
    })
}

/// Run the full automagic chain against an image.
///
/// Layer stacking always succeeds for a readable file. OS detection and symbol
/// loading may not, and the result records how far it got rather than failing
/// outright, so plugins that only need physical memory still run.
pub fn run(
    context: &Arc<Context>,
    image: &Path,
    finder: &SymbolFinder,
) -> Result<AutomagicResult> {
    let started = std::time::Instant::now();
    let stack = stacker::stack_image(&context.layers, image)?;
    log::debug!("Stacking layers took {:?}", started.elapsed());

    // What a previous run learned about this exact file, which saves searching
    // the whole image again for answers that cannot have changed.
    if let Some(identity) = image_cache::identity(image) {
        context.config.set(
            "automagic.image_identity",
            crate::framework::context::ConfigValue::Str(identity),
        );
    }

    let mut notes = vec![format!(
        "Stacked layers: {}",
        stack.created.join(" -> ")
    )];

    let mut result = AutomagicResult {
        physical_layer: stack.top_layer.clone(),
        kernel_layer: None,
        operating_system: OperatingSystem::Any,
        kernel_module: None,
        notes: Vec::new(),
    };

    // Try each operating system in turn. The first that recognises the image
    // wins. A failure here is informational, not fatal.
    // A crash dump states its own page directory base, so hand that to the
    // Windows detector instead of making it scan for one.
    if let Some(dtb) = stack.directory_table_base {
        context.config.set(
            "automagic.declared_dtb",
            crate::framework::context::ConfigValue::Int(dtb as i64),
        );
    }

    // An image that has been identified before says so, and its own detector
    // goes first. The others are only tried if it no longer recognises it.
    let known = context
        .config
        .get_string("automagic.image_identity")
        .and_then(|identity| image_cache::get(&identity))
        .map(|facts| facts.operating_system);

    if known.as_deref() == Some("linux") {
        match linux::detect(context, &stack.top_layer, finder) {
            Ok(Some(found)) => {
                result.operating_system = OperatingSystem::Linux;
                result.kernel_layer = Some(found.layer_name);
                result.kernel_module = found.module_name;
                notes.push("Identified a Linux image".to_string());
                result.notes = notes;
                return Ok(result);
            }
            Ok(None) => notes.push("Not a Linux image after all".to_string()),
            Err(error) => notes.push(format!("Linux detection failed: {error}")),
        }
    }

    let started = std::time::Instant::now();
    let windows = windows::detect(context, &stack.top_layer, finder);
    log::debug!("Windows detection took {:?}", started.elapsed());
    match windows {
        Ok(Some(found)) => {
            result.operating_system = OperatingSystem::Windows;
            result.kernel_layer = Some(found.layer_name);
            result.kernel_module = found.module_name;
            notes.push("Identified a Windows image".to_string());
            result.notes = notes;
            return Ok(result);
        }
        Ok(None) => notes.push("Not a Windows image".to_string()),
        Err(error) => notes.push(format!("Windows detection failed: {error}")),
    }

    match linux::detect(context, &stack.top_layer, finder) {
        Ok(Some(found)) => {
            result.operating_system = OperatingSystem::Linux;
            result.kernel_layer = Some(found.layer_name);
            result.kernel_module = found.module_name;
            notes.push("Identified a Linux image".to_string());
            result.notes = notes;
            return Ok(result);
        }
        Ok(None) => notes.push("Not a Linux image".to_string()),
        Err(error) => notes.push(format!("Linux detection failed: {error}")),
    }

    match mac::detect(context, &stack.top_layer, finder) {
        Ok(Some(found)) => {
            result.operating_system = OperatingSystem::Mac;
            result.kernel_layer = Some(found.layer_name);
            result.kernel_module = found.module_name;
            notes.push("Identified a Mac image".to_string());
            result.notes = notes;
            return Ok(result);
        }
        Ok(None) => notes.push("Not a Mac image".to_string()),
        Err(error) => notes.push(format!("Mac detection failed: {error}")),
    }

    notes.push(
        "Could not identify the operating system; only physical-layer plugins will run"
            .to_string(),
    );
    result.notes = notes;
    Ok(result)
}

/// What an OS detector found.
pub struct DetectedOs {
    /// The virtual layer built for the kernel.
    pub layer_name: String,
    /// The module registered for the kernel's symbols, if any were located.
    pub module_name: Option<String>,
}

/// Shared helper: confirm a layer looks like it holds a plausible amount of
/// memory before spending time scanning it.
pub fn sanity_check_layer(context: &Arc<Context>, layer_name: &str) -> Result<()> {
    let layer = context.layers.get(layer_name)?;
    if layer.maximum_address() < 0x1000 {
        return Err(VolatilityError::layer(
            layer_name,
            "Layer is too small to contain a memory image",
        ));
    }
    Ok(())
}
