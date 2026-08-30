//! Layer stacking: work out what an image file actually is, and build the
//! chain of layers needed to read it.
//!
//! Each format is tried in turn against the current top layer. When one
//! matches, its layer is stacked on top and the process repeats, so a LiME file
//! inside a raw file, or an ELF core holding a Windows crash dump, both resolve
//! without the caller knowing the format in advance.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::physical::FileLayer;
use crate::framework::layers::{avml, crash, elf, lime, qemu, vmware, DataLayer, LayerContainer};

/// How many times a format may be stacked before we conclude something is
/// looping. Real images need two or three levels at most.
const MAX_STACK_DEPTH: usize = 8;

/// The result of stacking: the name of the topmost physical layer.
pub struct StackResult {
    pub top_layer: String,
    /// The layers created, base first, for reporting.
    pub created: Vec<String>,
    /// The page directory base, when the image format stated it outright.
    ///
    /// A crash dump records this in its header, which saves scanning physical
    /// memory for a self-referential page table.
    pub directory_table_base: Option<u64>,
}

/// Build the layer stack for an image file.
///
/// Returns the name of the layer that exposes physical memory.
pub fn stack_image(layers: &LayerContainer, path: &std::path::Path) -> Result<StackResult> {
    // The names match the reference implementation's, since an image's
    // description reports them.
    let base_name = layers.free_name("base_layer");
    let file_layer = FileLayer::new(&base_name, path)?;
    layers.add(Arc::new(file_layer));

    let mut created = vec![base_name.clone()];
    let mut current = base_name;
    let mut directory_table_base = None;

    for _ in 0..MAX_STACK_DEPTH {
        match try_stack_one(layers, &current) {
            Some((next, dtb)) => {
                created.push(next.clone());
                current = next;
                directory_table_base = directory_table_base.or(dtb);
            }
            // Nothing else recognises this layer, so it is the physical layer.
            None => break,
        }
    }

    Ok(StackResult {
        top_layer: current,
        created,
        directory_table_base,
    })
}

/// The formats a run was told to try, if it named any.
fn stackers() -> &'static std::sync::RwLock<Vec<String>> {
    static STACKERS: std::sync::OnceLock<std::sync::RwLock<Vec<String>>> =
        std::sync::OnceLock::new();
    STACKERS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Limit stacking to the named formats.
pub fn set_stackers(names: Vec<String>) {
    *stackers().write().unwrap() = names;
}

fn chosen_stackers() -> Vec<String> {
    stackers().read().unwrap().clone()
}

/// Try every known format against `base`, stacking the first that matches.
///
/// Returns the new layer's name, and the page directory base if the format
/// declared one.
fn try_stack_one(layers: &LayerContainer, base: &str) -> Option<(String, Option<u64>)> {
    let wanted = chosen_stackers();
    let allowed = |format: &str| -> bool {
        wanted.is_empty()
            || wanted
                .iter()
                .any(|name| name.to_lowercase().contains(format))
    };

    // The crash dump is tried first because its header also yields the page
    // directory base, which saves a scan later.
    let name = layers.free_name("memory_layer");
    if allowed("crash") {
        match crash::build(layers, &name, base) {
            Ok((layer, header)) => {
                log::debug!("Stacked crash dump layer '{name}' on '{base}'");
                layers.add(Arc::new(layer));
                return Some((name, Some(header.directory_table_base)));
            }
            Err(error) => log::trace!("Format crash does not match layer {base}: {error}"),
        }
    }

    // Ordered so that formats with strong magic numbers are tried first. A raw
    // image matches nothing and ends the loop.
    let attempts: Vec<(&str, fn(&LayerContainer, &str, &str) -> Result<Arc<dyn DataLayer>>)> = vec![
        ("elf", stack_elf),
        ("lime", stack_lime),
        ("avml", stack_avml),
        ("qemu", stack_qemu),
        ("vmware", stack_vmware),
    ];

    for (format, builder) in attempts {
        // A run may name the formats it wants tried, and nothing else is.
        if !allowed(format) {
            continue;
        }
        let name = layers.free_name("memory_layer");
        match builder(layers, &name, base) {
            Ok(layer) => {
                log::debug!("Stacked {format} layer '{name}' on '{base}'");
                layers.add(layer);
                return Some((name, None));
            }
            Err(error) => {
                log::trace!("Format {format} does not match layer {base}: {error}");
            }
        }
    }
    None
}

fn stack_elf(layers: &LayerContainer, name: &str, base: &str) -> Result<Arc<dyn DataLayer>> {
    Ok(Arc::new(elf::build(layers, name, base)?))
}

fn stack_lime(layers: &LayerContainer, name: &str, base: &str) -> Result<Arc<dyn DataLayer>> {
    Ok(Arc::new(lime::build(layers, name, base)?))
}

fn stack_avml(layers: &LayerContainer, name: &str, base: &str) -> Result<Arc<dyn DataLayer>> {
    Ok(Arc::new(avml::AvmlLayer::build(layers, name, base)?))
}

fn stack_qemu(layers: &LayerContainer, name: &str, base: &str) -> Result<Arc<dyn DataLayer>> {
    Ok(Arc::new(qemu::QemuLayer::build(layers, name, base)?))
}

/// VMware needs a companion metadata file, so it only stacks when the base
/// layer is a file whose sibling `.vmss` or `.vmsn` exists.
fn stack_vmware(layers: &LayerContainer, name: &str, base: &str) -> Result<Arc<dyn DataLayer>> {
    let base_layer = layers.get(base)?;
    let file_layer = base_layer
        .as_any()
        .downcast_ref::<FileLayer>()
        .ok_or_else(|| VolatilityError::layer(base, "VMware requires a file-backed layer"))?;

    let location = file_layer.location();
    let mut meta_path = None;
    for extension in ["vmss", "vmsn"] {
        let candidate = location.with_extension(extension);
        if candidate.is_file() {
            meta_path = Some(candidate);
            break;
        }
    }
    let meta_path = meta_path
        .ok_or_else(|| VolatilityError::layer(base, "No companion .vmss or .vmsn file"))?;

    let meta_name = layers.free_name("meta_layer");
    layers.add(Arc::new(FileLayer::new(&meta_name, &meta_path)?));

    let result = vmware::build(layers, name, base, &meta_name);
    if result.is_err() {
        // Do not leave a stray metadata layer behind when the format did not
        // actually match.
        layers.remove(&meta_name);
    }
    Ok(Arc::new(result?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch_file(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("vol3-stack-{}-{name}", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(data).unwrap();
        path
    }

    #[test]
    fn a_raw_image_stacks_to_just_the_file_layer() {
        let path = scratch_file("raw.bin", &vec![0u8; 0x2000]);
        let layers = LayerContainer::new();
        let result = stack_image(&layers, &path).unwrap();

        assert_eq!(result.created.len(), 1);
        assert_eq!(result.top_layer, "base_layer");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_lime_image_stacks_a_lime_layer_on_the_file() {
        // One LiME record covering physical 0x1000..0x1fff.
        let mut data = Vec::new();
        data.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x1FFFu64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend(std::iter::repeat(0xABu8).take(0x1000));

        let path = scratch_file("image.lime", &data);
        let layers = LayerContainer::new();
        let result = stack_image(&layers, &path).unwrap();

        // Layers are named the way the reference implementation names them,
        // whatever format they turn out to hold.
        assert_eq!(result.top_layer, "memory_layer");
        let top = layers.get(&result.top_layer).unwrap();
        assert_eq!(top.minimum_address(), 0x1000);
        assert_eq!(
            top.read(&layers, 0x1000, 4, false).unwrap(),
            vec![0xAB, 0xAB, 0xAB, 0xAB]
        );
        std::fs::remove_file(&path).ok();
    }
}
