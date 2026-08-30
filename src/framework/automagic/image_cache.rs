//! Remembers what was learned about an image the first time it was opened.
//!
//! Identifying an image means finding its kernel banner and its idle task, and
//! both searches read a good part of the capture before they succeed. The
//! answers do not change while the file does not, so they are written down and
//! checked, not trusted, on the next run: the banner is re-read at the offset
//! it was found, and the shifts are re-derived from the task that gave them. A
//! file that no longer says the same thing simply misses the cache.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;
use std::path::{Path, PathBuf};

/// What one run learned about one image.
#[derive(Debug, Clone)]
pub struct ImageFacts {
    /// Which detector claimed the image.
    pub operating_system: String,
    /// Where the kernel banner was found, and what it said.
    pub banner_offset: u64,
    pub banner: String,
    /// The symbol file that banner selected, for reporting only.
    pub symbols: String,
    /// Where the idle task was found, which is what gives the shifts below.
    pub task_offset: u64,
    pub physical_shift: u64,
    pub virtual_shift: u64,
    /// Where a Windows kernel was found, and the page directory base its
    /// address space was built on. Both are zero for an image identified any
    /// other way.
    pub kernel_offset: u64,
    pub dtb: u64,
}

impl ImageFacts {
    fn encode(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.operating_system,
            self.banner_offset,
            self.symbols,
            self.task_offset,
            self.physical_shift,
            self.virtual_shift,
            self.kernel_offset,
            self.dtb,
            self.banner,
        )
    }

    fn decode(line: &str) -> Option<Self> {
        // The banner comes last because it is the only field that may itself
        // contain anything.
        let mut fields = line.splitn(9, '\t');
        Some(Self {
            operating_system: fields.next()?.to_string(),
            banner_offset: fields.next()?.parse().ok()?,
            symbols: fields.next()?.to_string(),
            task_offset: fields.next()?.parse().ok()?,
            physical_shift: fields.next()?.parse().ok()?,
            virtual_shift: fields.next()?.parse().ok()?,
            kernel_offset: fields.next()?.parse().ok()?,
            dtb: fields.next()?.parse().ok()?,
            banner: fields.next()?.to_string(),
        })
    }
}

/// What an image looked like, so a changed file is never mistaken for it.
pub fn identity(image: &Path) -> Option<String> {
    let data = std::fs::metadata(image).ok()?;
    let modified = data
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(format!("{}|{}|{modified}", image.display(), data.len()))
}

fn cache_path() -> Option<PathBuf> {
    crate::framework::cache::entry("images.tsv")
}

/// What was learned about the image with this identity, if anything.
pub fn get(identity: &str) -> Option<ImageFacts> {
    let text = std::fs::read_to_string(cache_path()?).ok()?;
    // Later lines win, so a re-identified image supersedes what it replaced.
    text.lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(key, _)| *key == identity)
        .filter_map(|(_, rest)| ImageFacts::decode(rest))
        .next_back()
}

/// Write down what this run learned.
pub fn put(identity: &str, facts: &ImageFacts) {
    let Some(path) = cache_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{identity}\t{}", facts.encode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_survive_a_round_trip() {
        let facts = ImageFacts {
            operating_system: "linux".to_string(),
            banner_offset: 0x1234,
            banner: "Linux version 6.8.0 (a\\tb)".to_string(),
            symbols: "/symbols/kernel.json.xz".to_string(),
            task_offset: 0x5678,
            physical_shift: 0x5f400000,
            virtual_shift: 0x29800000,
            kernel_offset: 0,
            dtb: 0,
        };
        let decoded = ImageFacts::decode(&facts.encode()).unwrap();
        assert_eq!(decoded.banner, facts.banner);
        assert_eq!(decoded.physical_shift, facts.physical_shift);
        assert_eq!(decoded.symbols, facts.symbols);
    }
}
