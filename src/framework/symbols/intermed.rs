//! Locating and loading ISF symbol files from disk.
//!
//! Symbol files are looked up by name under a set of base directories, and may
//! be stored plain, compressed (`.gz`, `.xz`, `.bz2`), or inside a `.zip`.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::symbols::isf::IsfFile;
use crate::framework::symbols::native::native_table_for_pointer_size;
use crate::framework::symbols::SymbolTable;

/// Extensions an ISF file may carry, in the order they are tried.
pub const ISF_EXTENSIONS: &[&str] = &[".json", ".json.xz", ".json.gz", ".json.bz2"];

/// The directories searched for symbol files.
///
/// Symbol packs live in one place: this tool's own data directory. Not borrowed
/// from another installation, and not relative to wherever the command was run
/// from, so which symbol file a run finds never depends on where you were
/// standing when you ran it. A pack somewhere else is named outright, either
/// with `--symbol-dirs` or through the environment.
pub fn default_symbol_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(configured) = std::env::var(SYMBOL_PATH_VARIABLE) {
        for entry in configured.split(':').filter(|entry| !entry.is_empty()) {
            paths.push(PathBuf::from(entry));
        }
    }
    if let Some(data) = data_directory() {
        paths.push(data.join("symbols"));
    }

    // Absolute, so that two runs started from different directories agree on
    // what they found, which is also what lets them share a cache entry.
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .map(|path| path.canonicalize().unwrap_or(path))
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

/// The environment variable that overrides where symbols are looked for.
pub const SYMBOL_PATH_VARIABLE: &str = "VOLRS_SYMBOL_PATH";

/// This tool's own data directory, which is where symbol packs are kept.
pub fn data_directory() -> Option<PathBuf> {
    if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(data).join("vol-rs"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/vol-rs"))
}

/// Decompress according to the file's extension.
fn decompress(path: &Path, raw: Vec<u8>) -> Result<Vec<u8>> {
    let name = path.to_string_lossy();
    let mut output = Vec::new();

    if name.ends_with(".gz") {
        flate2::read::GzDecoder::new(&raw[..])
            .read_to_end(&mut output)
            .map_err(|e| VolatilityError::Io(format!("Could not decompress {name}: {e}")))?;
    } else if name.ends_with(".xz") {
        xz2::read::XzDecoder::new(&raw[..])
            .read_to_end(&mut output)
            .map_err(|e| VolatilityError::Io(format!("Could not decompress {name}: {e}")))?;
    } else if name.ends_with(".bz2") {
        bzip2::read::BzDecoder::new(&raw[..])
            .read_to_end(&mut output)
            .map_err(|e| VolatilityError::Io(format!("Could not decompress {name}: {e}")))?;
    } else {
        output = raw;
    }
    Ok(output)
}

/// Read an ISF file from a path, decompressing if needed.
pub fn load_isf_file(path: &Path) -> Result<IsfFile> {
    if let Some(cached) = parsed_cache::get(path) {
        return Ok(cached);
    }

    let started = std::time::Instant::now();
    let raw = std::fs::read(path)
        .map_err(|e| VolatilityError::Io(format!("Could not read {}: {e}", path.display())))?;
    let json = decompress(path, raw)?;
    log::debug!("Reading and decompressing took {:?}", started.elapsed());
    let started = std::time::Instant::now();
    let file = IsfFile::from_slice(&json)?;
    log::debug!("Parsing {} took {:?}", path.display(), started.elapsed());

    // Only a file big enough to be worth it: the small bundled ones parse in
    // less time than reading a cache would take.
    if json.len() >= parsed_cache::WORTH_CACHING {
        parsed_cache::put(path, &file);
    }
    Ok(file)
}

/// Read an ISF file stored inside a zip archive.
pub fn load_isf_from_zip(archive_path: &Path, entry_name: &str) -> Result<IsfFile> {
    let file = std::fs::File::open(archive_path).map_err(|e| {
        VolatilityError::Io(format!("Could not open {}: {e}", archive_path.display()))
    })?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| VolatilityError::Io(format!("Not a valid zip archive: {e}")))?;
    let mut entry = archive
        .by_name(entry_name)
        .map_err(|e| VolatilityError::Io(format!("No entry '{entry_name}' in archive: {e}")))?;

    let mut raw = Vec::new();
    entry
        .read_to_end(&mut raw)
        .map_err(|e| VolatilityError::Io(format!("Could not read '{entry_name}': {e}")))?;

    let json = decompress(Path::new(entry_name), raw)?;
    IsfFile::from_slice(&json)
}

/// A located symbol file: either a path on disk or an entry inside a zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolLocation {
    File(PathBuf),
    ZipEntry { archive: PathBuf, entry: String },
}

impl SymbolLocation {
    /// A short identifier suitable for reporting to the user.
    pub fn display(&self) -> String {
        match self {
            SymbolLocation::File(path) => path.display().to_string(),
            SymbolLocation::ZipEntry { archive, entry } => {
                format!("{}!{entry}", archive.display())
            }
        }
    }

    /// Where this file is, as a URL, which is how an image's description
    /// reports the symbols it used.
    pub fn url(&self) -> String {
        match self {
            SymbolLocation::File(path) => format!("file://{}", path.display()),
            SymbolLocation::ZipEntry { archive, entry } => {
                format!("jar:file://{}!/{entry}", archive.display())
            }
        }
    }

    /// The kernel banner this symbol file declares, read without parsing it.
    ///
    /// Matching an image to its symbols means reading the banner out of every
    /// installed file, and parsing each one in full to recover a single string
    /// costs seconds. The banner is lifted straight out of the raw JSON
    /// instead. A file that resists is parsed properly rather than skipped.
    pub fn banner(&self) -> Option<String> {
        if let Some(cached) = banner_cache::get(self) {
            return cached.into();
        }
        let banner = self.banner_uncached();
        banner_cache::put(self, banner.as_deref());
        banner
    }

    /// The banner, read from the file itself.
    fn banner_uncached(&self) -> Option<String> {
        let raw = self.raw()?;
        banner_from_json(&raw).or_else(|| {
            let isf = IsfFile::from_slice(&raw).ok()?;
            banner_of(&isf)
        })
    }

    /// The file's decompressed bytes.
    fn raw(&self) -> Option<Vec<u8>> {
        match self {
            SymbolLocation::File(path) => decompress(path, std::fs::read(path).ok()?).ok(),
            SymbolLocation::ZipEntry { archive, entry } => {
                let file = std::fs::File::open(archive).ok()?;
                let mut zip = zip::ZipArchive::new(file).ok()?;
                let mut member = zip.by_name(entry).ok()?;
                let mut raw = Vec::new();
                member.read_to_end(&mut raw).ok()?;
                decompress(Path::new(entry), raw).ok()
            }
        }
    }

    pub fn load(&self) -> Result<IsfFile> {
        match self {
            SymbolLocation::File(path) => load_isf_file(path),
            SymbolLocation::ZipEntry { archive, entry } => load_isf_from_zip(archive, entry),
        }
    }
}

/// Finds symbol files under a set of base directories.
pub struct SymbolFinder {
    base_paths: Vec<PathBuf>,
}

impl SymbolFinder {
    pub fn new(base_paths: Vec<PathBuf>) -> Self {
        Self { base_paths }
    }

    pub fn with_defaults() -> Self {
        Self::new(default_symbol_paths())
    }

    pub fn base_paths(&self) -> &[PathBuf] {
        &self.base_paths
    }

    pub fn add_path(&mut self, path: PathBuf) {
        if !self.base_paths.contains(&path) {
            self.base_paths.insert(0, path);
        }
    }

    /// Find a symbol file named `filename` under `sub_path` (`windows`,
    /// `linux`, `mac`, or `generic`).
    pub fn find(&self, sub_path: &str, filename: &str) -> Option<SymbolLocation> {
        for base in &self.base_paths {
            let directory = base.join(sub_path);
            for extension in ISF_EXTENSIONS {
                let candidate = directory.join(format!("{filename}{extension}"));
                if candidate.is_file() {
                    return Some(SymbolLocation::File(candidate));
                }
            }
        }

        // Fall back to searching inside zip archives, which is how large symbol
        // packs are usually distributed.
        for base in &self.base_paths {
            let directory = base.join(sub_path);
            if let Some(found) = self.search_archives(&directory, filename) {
                return Some(found);
            }
        }
        None
    }

    fn search_archives(&self, directory: &Path, filename: &str) -> Option<SymbolLocation> {
        let entries = std::fs::read_dir(directory).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("zip") {
                continue;
            }
            let Ok(file) = std::fs::File::open(&path) else {
                continue;
            };
            let Ok(mut archive) = zip::ZipArchive::new(file) else {
                continue;
            };
            for index in 0..archive.len() {
                let Ok(zip_entry) = archive.by_index(index) else {
                    continue;
                };
                let name = zip_entry.name().to_string();
                // Zip paths always use forward slashes regardless of platform.
                let matches = ISF_EXTENSIONS.iter().any(|extension| {
                    name.ends_with(&format!("{filename}{extension}"))
                });
                if matches {
                    return Some(SymbolLocation::ZipEntry {
                        archive: path.clone(),
                        entry: name,
                    });
                }
            }
        }
        None
    }

    /// Every symbol file available under `sub_path`, as `(identifier, location)`.
    pub fn list(&self, sub_path: &str) -> Vec<(String, SymbolLocation)> {
        let mut found = Vec::new();
        for base in &self.base_paths {
            let directory = base.join(sub_path);
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if let Some(extension) = ISF_EXTENSIONS
                    .iter()
                    .find(|extension| name.ends_with(**extension))
                {
                    let identifier = name.trim_end_matches(extension).to_string();
                    found.push((identifier, SymbolLocation::File(path.clone())));
                }
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found.dedup_by(|a, b| a.0 == b.0);
        found
    }
}

/// Build a symbol table from a located ISF file.
///
/// The native table is chosen from the file's own pointer width, so a 32-bit
/// kernel gets 32-bit defaults for any base type it leaves undefined.
pub fn create_table(name: impl Into<String>, isf: IsfFile) -> Arc<SymbolTable> {
    let pointer_size = isf
        .base_types
        .get("pointer")
        .map(|base| base.size)
        .unwrap_or(8);
    let native = native_table_for_pointer_size(pointer_size);
    Arc::new(SymbolTable::new(name, isf, native))
}

/// Load a symbol table by name, searching the finder's paths.
pub fn create_from_file(
    finder: &SymbolFinder,
    table_name: impl Into<String>,
    sub_path: &str,
    filename: &str,
) -> Result<Arc<SymbolTable>> {
    let location = finder.find(sub_path, filename).ok_or_else(|| {
        VolatilityError::SymbolSpace(format!(
            "Could not find symbol file '{filename}' under '{sub_path}' in any of: {}",
            finder
                .base_paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<String>>()
                .join(", ")
        ))
    })?;
    log::debug!("Loading symbols from {}", location.display());
    Ok(create_table(table_name, location.load()?))
}

/// A cache of already-loaded ISF files, keyed by location.
#[derive(Default)]
pub struct SymbolCache {
    entries: std::sync::RwLock<HashMap<String, Arc<IsfFile>>>,
}

impl SymbolCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a file, reusing an earlier parse of the same location.
    pub fn load(&self, location: &SymbolLocation) -> Result<Arc<IsfFile>> {
        let key = location.display();
        if let Some(cached) = self.entries.read().unwrap().get(&key) {
            return Ok(cached.clone());
        }
        let isf = Arc::new(location.load()?);
        self.entries.write().unwrap().insert(key, isf.clone());
        Ok(isf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch() -> PathBuf {
        let base = std::env::temp_dir().join(format!("vol3-isf-{}", std::process::id()));
        std::fs::create_dir_all(base.join("windows")).unwrap();
        base
    }

    const MINIMAL: &str = r#"{"metadata":{"format":"6.2.0"},"base_types":{"pointer":{"size":4,"signed":false,"kind":"int","endian":"little"}},"user_types":{},"enums":{},"symbols":{}}"#;

    #[test]
    fn finds_plain_and_compressed_files() {
        let base = scratch();
        let plain = base.join("windows").join("plain.json");
        std::fs::write(&plain, MINIMAL).unwrap();

        let gzipped = base.join("windows").join("packed.json.gz");
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(MINIMAL.as_bytes()).unwrap();
        std::fs::write(&gzipped, encoder.finish().unwrap()).unwrap();

        let finder = SymbolFinder::new(vec![base.clone()]);
        assert_eq!(finder.find("windows", "plain"), Some(SymbolLocation::File(plain)));

        // The compressed file round-trips through the decompressor.
        let location = finder.find("windows", "packed").unwrap();
        let isf = location.load().unwrap();
        assert_eq!(isf.base_types["pointer"].size, 4);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn native_table_follows_the_file_pointer_width() {
        let isf = IsfFile::from_slice(MINIMAL.as_bytes()).unwrap();
        let table = create_table("test", isf);
        assert_eq!(table.pointer_size(), 4);
    }
}

/// The banner a parsed symbol file declares.
///
/// The banner is constant data on a symbol whose name varies between
/// producers, so any of the known spellings is accepted.
pub fn banner_of(isf: &IsfFile) -> Option<String> {
    for name in BANNER_SYMBOLS {
        if let Some(data) = isf
            .symbols
            .get(*name)
            .and_then(|symbol| symbol.constant_data.as_ref())
        {
            if let Some(banner) = banner_text(data) {
                return Some(banner);
            }
        }
    }
    None
}

/// Symbols that may hold the kernel banner.
pub const BANNER_SYMBOLS: &[&str] = &["linux_banner", "version", "_version"];

/// Pull the banner out of the raw JSON without building a document from it.
fn banner_from_json(json: &[u8]) -> Option<String> {
    for name in BANNER_SYMBOLS {
        let key = format!("\"{name}\":{{");
        let Some(start) = find(json, key.as_bytes()) else {
            continue;
        };
        // Only within this symbol's own object: the field must appear before
        // the object ends, or it belongs to something else entirely.
        let rest = &json[start + key.len()..];
        let end = find(rest, b"}").unwrap_or(rest.len());
        let Some(field) = find(rest, b"\"constant_data\":\"") else {
            continue;
        };
        if field > end {
            continue;
        }
        let value = &rest[field + b"\"constant_data\":\"".len()..];
        let Some(quote) = find(value, b"\"") else {
            continue;
        };
        let encoded = std::str::from_utf8(&value[..quote]).ok()?;
        if let Some(banner) = crate::framework::symbols::isf::decode_base64(encoded)
            .as_deref()
            .and_then(banner_text)
        {
            return Some(banner);
        }
    }
    None
}

/// The printable banner held in a symbol's constant data.
fn banner_text(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    let banner = String::from_utf8_lossy(&data[..end]).trim().to_string();
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

/// The first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // A byte-at-a-time search over a symbol file costs seconds. This is the
    // same search done the fast way.
    memchr::memmem::find(haystack, needle)
}

/// Remembers which banner each symbol file declares.
///
/// Every run has to match the image's banner against the installed symbol
/// files, and reading them to find out costs as much as the rest of startup.
/// The answer only changes when a file does, so it is kept on disk and keyed by
/// what the file looked like when it was read.
mod banner_cache {
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{OnceLock, RwLock};

    use super::SymbolLocation;

    /// A file's identity: nothing is trusted from a file that has changed.
    fn stamp(location: &SymbolLocation) -> Option<String> {
        let path = match location {
            SymbolLocation::File(path) => path.clone(),
            SymbolLocation::ZipEntry { archive, .. } => archive.clone(),
        };
        let data = std::fs::metadata(&path).ok()?;
        let modified = data
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let entry = match location {
            SymbolLocation::File(_) => String::new(),
            SymbolLocation::ZipEntry { entry, .. } => entry.clone(),
        };
        Some(format!("{}\t{entry}\t{modified}\t{}", path.display(), data.len()))
    }

    fn cache_path() -> Option<PathBuf> {
        crate::framework::cache::entry("banners.tsv")
    }

    /// The cache as it was on disk, read once per run.
    fn table() -> &'static RwLock<HashMap<String, String>> {
        static TABLE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut entries = HashMap::new();
            if let Some(path) = cache_path() {
                if let Ok(text) = std::fs::read_to_string(path) {
                    for line in text.lines() {
                        // Four fields identify the file. The rest is the
                        // banner, which is empty when the file declared none.
                        let mut parts = line.splitn(5, '\t');
                        let key: Vec<&str> = (&mut parts).take(4).collect();
                        if key.len() == 4 {
                            entries.insert(
                                key.join("\t"),
                                parts.next().unwrap_or_default().to_string(),
                            );
                        }
                    }
                }
            }
            RwLock::new(entries)
        })
    }

    /// What this file declared last time, if it has not changed since.
    ///
    /// The outer option says whether the answer is known. The inner one is the
    /// answer, since "this file has no banner" is worth remembering too.
    pub fn get(location: &SymbolLocation) -> Option<Option<String>> {
        let key = stamp(location)?;
        let found = table().read().ok()?.get(&key).cloned()?;
        Some(if found.is_empty() { None } else { Some(found) })
    }

    /// Record what a file declared.
    pub fn put(location: &SymbolLocation, banner: Option<&str>) {
        let Some(key) = stamp(location) else { return };
        let banner = banner.unwrap_or_default().to_string();
        if let Ok(mut entries) = table().write() {
            if entries.insert(key.clone(), banner.clone()) == Some(banner.clone()) {
                return;
            }
        }
        // Appended rather than rewritten: a stale line is simply never matched
        // again, and two runs at once cannot lose each other's work.
        let Some(path) = cache_path() else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(file, "{key}\t{banner}");
        }
    }
}

/// Keeps symbol files in the form they are actually used in.
///
/// A kernel's symbol file is tens of megabytes of JSON describing hundreds of
/// thousands of types and symbols, and turning it back into structures is the
/// single largest cost of starting up. The result is the same every time, so it
/// is written out once and read back on later runs.
mod parsed_cache {
    use std::path::{Path, PathBuf};

    use crate::framework::symbols::isf::IsfFile;

    /// Files smaller than this parse faster than a cache could be read.
    pub const WORTH_CACHING: usize = 4 * 1024 * 1024;

    /// Bumped whenever the stored shape changes, so an old cache is ignored
    /// rather than misread.
    const FORMAT: u32 = 3;

    fn encoding() -> impl bincode::config::Config {
        bincode::config::standard()
    }

    /// Where a given symbol file's parsed form lives.
    ///
    /// The name carries what the file looked like when it was parsed, so a
    /// changed or replaced symbol file simply misses the cache.
    fn path_for(source: &Path) -> Option<PathBuf> {
        let data = std::fs::metadata(source).ok()?;
        let modified = data
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let stem = source.file_name()?.to_string_lossy().replace(
            |character: char| !character.is_ascii_alphanumeric() && character != '.',
            "_",
        );
        Some(
            crate::framework::cache::entry("symbols")?
                .join(format!("{stem}-{modified}-{}-v{FORMAT}.bin", data.len())),
        )
    }

    /// The sections a stored file is written in, in order.
    ///
    /// They are laid out one after another behind a table of their lengths, so
    /// each can be read straight out of the bytes on disk without first being
    /// copied out of a wrapper.
    const SECTIONS: usize = 5;

    pub fn get(source: &Path) -> Option<IsfFile> {
        let path = path_for(source)?;
        let started = std::time::Instant::now();
        let data = match std::fs::read(&path) {
            Ok(data) => data,
            Err(error) => {
                log::debug!("No parsed symbol file at {}: {error}", path.display());
                return None;
            }
        };

        let Some(sections) = split(&data) else {
            log::debug!("Ignoring a stored symbol file that is not laid out as expected");
            return None;
        };

        let (user_types, enums, symbols) = (
            section(sections[2]),
            section(sections[3]),
            section(sections[4]),
        );
        let file = IsfFile {
            metadata: section(sections[0])?,
            base_types: section(sections[1])?,
            user_types: user_types?,
            enums: enums?,
            symbols: symbols?,
        };
        log::debug!("Reading the stored symbol file took {:?}", started.elapsed());
        Some(file)
    }

    /// The sections of a stored file, as views into it.
    fn split(data: &[u8]) -> Option<[&[u8]; SECTIONS]> {
        let header = SECTIONS * 8;
        if data.len() < header {
            return None;
        }
        let mut lengths = [0usize; SECTIONS];
        for (index, length) in lengths.iter_mut().enumerate() {
            let start = index * 8;
            *length = u64::from_le_bytes(data[start..start + 8].try_into().ok()?) as usize;
        }

        let mut sections = [&data[..0]; SECTIONS];
        let mut position = header;
        for (index, length) in lengths.iter().enumerate() {
            let end = position.checked_add(*length)?;
            if end > data.len() {
                return None;
            }
            sections[index] = &data[position..end];
            position = end;
        }
        Some(sections)
    }

    /// Write the file out a section at a time, behind their lengths.
    fn store(file: &IsfFile) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let sections = [
            bincode::serde::encode_to_vec(&file.metadata, encoding())?,
            bincode::serde::encode_to_vec(&file.base_types, encoding())?,
            bincode::serde::encode_to_vec(&file.user_types, encoding())?,
            bincode::serde::encode_to_vec(&file.enums, encoding())?,
            bincode::serde::encode_to_vec(&file.symbols, encoding())?,
        ];
        let mut data = Vec::with_capacity(
            SECTIONS * 8 + sections.iter().map(|section| section.len()).sum::<usize>(),
        );
        for section in &sections {
            data.extend_from_slice(&(section.len() as u64).to_le_bytes());
        }
        for section in &sections {
            data.extend_from_slice(section);
        }
        Ok(data)
    }

    /// One stored section, read back into the shape it was written from.
    fn section<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
        bincode::serde::decode_from_slice(data, encoding())
            .ok()
            .map(|(value, _)| value)
    }

    pub fn put(source: &Path, file: &IsfFile) {
        let Some(path) = path_for(source) else { return };
        let Ok(data) = store(file) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Written beside the target and renamed, so a run that is interrupted
        // leaves no half-written cache for the next one to read.
        let temporary = path.with_extension("partial");
        if std::fs::write(&temporary, &data).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }
}
