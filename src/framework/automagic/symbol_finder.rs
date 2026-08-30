//! Matching an image against the symbol files available on disk.
//!
//! Linux and Mac kernels embed a version banner in memory. The same banner is
//! recorded in the ISF file built from that kernel, so finding the banner in an
//! image and looking it up identifies the exact kernel build.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::Context;
use crate::framework::layers::scanners::{scan_layer_until, RegExScanner};
use crate::framework::symbols::intermed::{SymbolFinder, SymbolLocation};

/// A banner found in an image, with where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundBanner {
    pub banner: String,
    pub offset: u64,
}

/// The pattern a real kernel banner matches.
///
/// Requiring a version number after the prefix is what separates an actual
/// banner from the printk format string (`Linux version %s (%s)`) that also
/// lives in kernel memory and would otherwise be reported as one.
pub const BANNER_PATTERN: &str =
    r"(Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+";

/// The characters a banner may contain.
///
/// A candidate holding anything else is binary data that happened to match the
/// pattern, not a banner.
const BANNER_ALPHABET: &[u8] =
    b" #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~";

/// How far past a match to read while looking for the terminating NUL.
const BANNER_READ: usize = 0xFFF;

/// Scan a layer for kernel version banners.
///
/// Each match is extended to the following NUL and then validated against the
/// permitted alphabet, which is what keeps format strings and binary noise out
/// of the results.
pub fn scan_for_banners(
    context: &Arc<Context>,
    layer_name: &str,
) -> Result<Vec<FoundBanner>> {
    let mut banners = Vec::new();
    scan_banners(context, layer_name, |found| {
        banners.push(found);
        true
    })?;
    banners.sort_by_key(|banner: &FoundBanner| banner.offset);
    Ok(banners)
}

/// Scan for banners, handing each to `accept` in address order.
///
/// `accept` returns whether to keep scanning. Identifying an image needs one
/// banner that names symbols we have, so the scan stops as soon as it has one
/// rather than reading the rest of the image for banners nobody will use.
pub fn scan_banners<F>(context: &Arc<Context>, layer_name: &str, mut accept: F) -> Result<()>
where
    F: FnMut(FoundBanner) -> bool,
{
    let layer = context.layers.get(layer_name)?;
    let scanner = RegExScanner::new(BANNER_PATTERN)?;

    let mut error: Option<crate::error::VolatilityError> = None;
    scan_layer_until(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        let Some(found) = decode_banner(context, layer.as_ref(), offset) else {
            return true;
        };
        accept(found)
    })
    .or_else(|failure| {
        error = Some(failure);
        Ok::<(), crate::error::VolatilityError>(())
    })?;
    match error {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

/// Read the banner a match at `offset` belongs to, if it is really one.
fn decode_banner(
    context: &Arc<Context>,
    layer: &dyn crate::framework::layers::DataLayer,
    offset: u64,
) -> Option<FoundBanner> {
    {
        let Ok(data) = layer.read(&context.layers, offset, BANNER_READ, true) else {
            return None;
        };

        // The banner runs to the first NUL. Without one this is not a string.
        let Some(end) = data.iter().position(|&byte| byte == 0) else {
            return None;
        };
        if end == 0 {
            return None;
        }

        let candidate = &data[..end];
        let trimmed: &[u8] = {
            let start = candidate
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .unwrap_or(0);
            let stop = candidate
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .map(|position| position + 1)
                .unwrap_or(0);
            if stop > start {
                &candidate[start..stop]
            } else {
                &[]
            }
        };
        if trimmed.is_empty() {
            return None;
        }

        if trimmed.iter().any(|byte| !BANNER_ALPHABET.contains(byte)) {
            return None;
        }

        Some(FoundBanner {
            banner: String::from_utf8_lossy(trimmed).to_string(),
            offset,
        })
    }
}

/// Scan for banners belonging to one operating system.
pub fn scan_for_os_banners(
    context: &Arc<Context>,
    layer_name: &str,
    prefix: &str,
) -> Result<Vec<FoundBanner>> {
    Ok(scan_for_banners(context, layer_name)?
        .into_iter()
        .filter(|found| found.banner.starts_with(prefix))
        .collect())
}

/// The first banner in address order that starts with `prefix` and that
/// `known` recognises, or none if the image holds no such banner.
pub fn first_known_banner(
    context: &Arc<Context>,
    layer_name: &str,
    prefix: &str,
    known: impl Fn(&str) -> bool,
) -> Result<Option<FoundBanner>> {
    let mut matched = None;
    scan_banners(context, layer_name, |found| {
        if !found.banner.starts_with(prefix) || !known(&found.banner) {
            return true;
        }
        matched = Some(found);
        false
    })?;
    Ok(matched)
}

/// An index from banner text to the symbol file that declares it.
pub struct BannerIndex {
    entries: HashMap<String, SymbolLocation>,
}

impl BannerIndex {
    /// Build an index by reading the banner symbol out of every symbol file
    /// under `sub_path`.
    ///
    /// This reads each file once, which is slow for a large symbol pack, so the
    /// caller is expected to build it only when an OS has already been
    /// tentatively identified.
    pub fn build(finder: &SymbolFinder, sub_path: &str) -> Self {
        let mut entries = HashMap::new();
        for (identifier, location) in finder.list(sub_path) {
            match location.banner() {
                Some(banner) => {
                    entries.insert(banner, location.clone());
                }
                None => log::debug!("No kernel banner in symbol file '{identifier}'"),
            }
        }
        Self { entries }
    }

    /// Find the symbol file matching a banner, trying an exact match first and
    /// then a prefix match, since a banner in memory may be truncated.
    pub fn lookup(&self, banner: &str) -> Option<&SymbolLocation> {
        let trimmed = banner.trim();
        if let Some(location) = self.entries.get(trimmed) {
            return Some(location);
        }
        self.entries
            .iter()
            .find(|(known, _)| known.starts_with(trimmed) || trimmed.starts_with(known.as_str()))
            .map(|(_, location)| location)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every known banner, for reporting what is available.
    pub fn banners(&self) -> Vec<&str> {
        let mut banners: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        banners.sort_unstable();
        banners
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;

    #[test]
    fn finds_and_trims_a_banner_in_memory() {
        let context = Arc::new(Context::new());
        let mut memory = vec![0u8; 0x4000];
        let banner = b"Linux version 5.15.0-generic (gcc 11)";
        memory[0x2000..0x2000 + banner.len()].copy_from_slice(banner);

        context.layers.add(Arc::new(BufferLayer::new("mem", memory)));
        let found = scan_for_banners(&context, "mem").unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].banner, "Linux version 5.15.0-generic (gcc 11)");
        assert_eq!(found[0].offset, 0x2000);
    }

    #[test]
    fn format_strings_are_not_reported_as_banners() {
        // The kernel's printk format string matches the prefix but has no
        // version number, so it must not be mistaken for a real banner.
        let context = Arc::new(Context::new());
        let mut memory = vec![0u8; 0x4000];
        let format = b"Linux version %s (%s)";
        memory[0x1000..0x1000 + format.len()].copy_from_slice(format);
        let real = b"Linux version 6.1.0-generic (gcc)";
        memory[0x2000..0x2000 + real.len()].copy_from_slice(real);

        context.layers.add(Arc::new(BufferLayer::new("mem", memory)));
        let found = scan_for_banners(&context, "mem").unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].banner, "Linux version 6.1.0-generic (gcc)");
    }

    #[test]
    fn every_occurrence_is_reported_with_its_offset() {
        let context = Arc::new(Context::new());
        let mut memory = vec![0u8; 0x8000];
        let banner = b"Linux version 6.1.0";
        for at in [0x1000usize, 0x3000, 0x5000] {
            memory[at..at + banner.len()].copy_from_slice(banner);
        }
        context.layers.add(Arc::new(BufferLayer::new("mem", memory)));

        // Upstream reports each occurrence rather than deduplicating them.
        let found = scan_for_banners(&context, "mem").unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].offset, 0x1000);
    }
}
