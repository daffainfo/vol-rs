//! Reading public symbols out of a program database.
//!
//! Windows binaries carry no symbol names of their own beyond what they
//! export, but every Microsoft binary names the database that describes it, and
//! that database can be fetched by the identifier the binary carries. Only the
//! public symbols are read here: a name and the address it sits at, which is
//! what attributing an address to a function needs.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use crate::error::{Result, VolatilityError};

/// Where Microsoft publishes the databases for its own binaries.
const SYMBOL_SERVER: &str = "http://msdl.microsoft.com/download/symbols";

/// The header every database of this generation begins with.
const MSF_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// The public symbols a database describes.
pub struct PublicSymbols {
    /// Each symbol's address, relative to the image's base.
    addresses: HashMap<String, u32>,
}

impl PublicSymbols {
    /// The address a name sits at, relative to the image's base.
    pub fn address_of(&self, name: &str) -> Option<u32> {
        self.addresses.get(name).copied()
    }

    /// The name sitting at an address, relative to the image's base.
    ///
    /// Several names can share an address, so the symbols are ordered by
    /// address and then by name and the first is reported, which is what
    /// looking a location up in a symbol table gives.
    pub fn name_at(&self, address: u32) -> Option<&str> {
        self.addresses
            .iter()
            .filter(|(_, at)| **at == address)
            .map(|(name, _)| name.as_str())
            .min()
    }

    /// How many symbols were read.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// Fetch the database a binary names, from the cache or from the server.
///
/// The identifier is the one the binary carries, so a database fetched once is
/// good for every image built from the same binary.
pub fn fetch(name: &str, guid: &str, age: u32) -> Result<Vec<u8>> {
    // Asked to stay offline, the fetch does not happen at all.
    if crate::framework::cache::offline() {
        return Err(VolatilityError::Other(
            "Symbols are not available offline".to_string(),
        ));
    }
    // The name is always spelled as a database, whatever the binary is called.
    let stem = name.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(name);
    let file = format!("{stem}.pdb");
    let identifier = format!("{}{age}", guid.to_uppercase());

    let cached = cache_directory()?.join(&file).join(&identifier).join(&file);
    if let Ok(data) = std::fs::read(&cached) {
        return Ok(data);
    }

    // The server may be somewhere else entirely.
    let server = crate::framework::cache::remote_url()
        .unwrap_or_else(|| SYMBOL_SERVER.to_string());
    let url = format!("{server}/{file}/{identifier}/{file}");
    log::debug!("Fetching {url}");
    let mut response = ureq::get(&url)
        .call()
        .map_err(|error| VolatilityError::Other(format!("Could not fetch {url}: {error}")))?;

    let mut data = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut data)
        .map_err(|error| VolatilityError::Other(format!("Could not read {url}: {error}")))?;

    if let Some(directory) = cached.parent() {
        let _ = std::fs::create_dir_all(directory);
        let _ = std::fs::write(&cached, &data);
    }
    Ok(data)
}

/// Where fetched databases are kept between runs.
fn cache_directory() -> Result<PathBuf> {
    crate::framework::cache::entry("pdb")
        .ok_or_else(|| VolatilityError::Other("No cache directory is available".to_string()))
}

/// Read the public symbols out of a database.
pub fn public_symbols(data: &[u8]) -> Result<PublicSymbols> {
    let file = MultiStreamFile::parse(data)?;

    // The stream describing the build names the streams holding the symbols
    // and the section headers.
    let debug = file.stream(3)?;
    if debug.len() < 64 {
        return Err(VolatilityError::Other(
            "The database describes no build information".to_string(),
        ));
    }
    let symbol_stream = read_u16(&debug, 20)? as usize;
    let module_size = read_u32(&debug, 24)? as usize;
    let section_contribution_size = read_u32(&debug, 28)? as usize;
    let section_map_size = read_u32(&debug, 32)? as usize;
    let source_size = read_u32(&debug, 36)? as usize;
    let type_server_size = read_u32(&debug, 40)? as usize;
    let optional_size = read_u32(&debug, 48)? as usize;
    let ec_size = read_u32(&debug, 52)? as usize;

    // The optional headers come last, and the sixth of them names the stream
    // holding the image's section headers.
    let optional_at = 64
        + module_size
        + section_contribution_size
        + section_map_size
        + source_size
        + type_server_size
        + ec_size;
    if optional_size < 12 || optional_at + optional_size > debug.len() {
        return Err(VolatilityError::Other(
            "The database describes no section headers".to_string(),
        ));
    }
    let section_stream = read_u16(&debug, optional_at + 10)?;
    let sections = image_sections(&file.stream(section_stream as usize)?);

    // Every public symbol names a section and an offset within it.
    let symbols = file.stream(symbol_stream)?;
    let mut addresses = HashMap::new();
    let mut at = 0usize;
    while at + 4 <= symbols.len() {
        let length = read_u16(&symbols, at)? as usize;
        if length < 2 || at + 2 + length > symbols.len() {
            break;
        }
        let kind = read_u16(&symbols, at + 2)?;
        // S_PUB32: flags, offset, segment, then the name.
        const PUBLIC_SYMBOL: u16 = 0x110E;
        if kind == PUBLIC_SYMBOL && length >= 12 {
            let offset = read_u32(&symbols, at + 8)?;
            let segment = read_u16(&symbols, at + 12)? as usize;
            let name_at = at + 14;
            let end = symbols[name_at..at + 2 + length]
                .iter()
                .position(|byte| *byte == 0)
                .map(|position| name_at + position)
                .unwrap_or(at + 2 + length);
            if segment >= 1 && segment <= sections.len() {
                let name = String::from_utf8_lossy(&symbols[name_at..end]).to_string();
                addresses
                    .entry(name)
                    .or_insert(sections[segment - 1] + offset);
            }
        }
        at += 2 + length;
        // Records are four-byte aligned.
        at = (at + 3) & !3;
    }

    Ok(PublicSymbols { addresses })
}

/// Where each section of the image begins, relative to its base.
fn image_sections(data: &[u8]) -> Vec<u32> {
    let mut found = Vec::new();
    let mut at = 0usize;
    while at + 40 <= data.len() {
        match read_u32(data, at + 12) {
            Ok(address) => found.push(address),
            Err(_) => break,
        }
        at += 40;
    }
    found
}

/// A database is a file of fixed-size blocks, with a directory saying which
/// blocks make up each stream.
struct MultiStreamFile<'a> {
    data: &'a [u8],
    block_size: usize,
    /// The blocks of each stream, and its length in bytes.
    streams: Vec<(usize, Vec<u32>)>,
}

impl<'a> MultiStreamFile<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 56 || !data.starts_with(MSF_MAGIC) {
            return Err(VolatilityError::Other(
                "Not a program database of a readable generation".to_string(),
            ));
        }
        let block_size = read_u32(data, 32)? as usize;
        let directory_bytes = read_u32(data, 44)? as usize;
        let directory_map = read_u32(data, 52)? as usize;
        if block_size == 0 {
            return Err(VolatilityError::Other(
                "The database describes blocks of no size".to_string(),
            ));
        }

        // The map itself is a list of the blocks holding the directory.
        let blocks_needed = directory_bytes.div_ceil(block_size);
        let map_at = directory_map * block_size;
        let mut directory_blocks = Vec::with_capacity(blocks_needed);
        for index in 0..blocks_needed {
            directory_blocks.push(read_u32(data, map_at + index * 4)?);
        }
        let directory = gather(data, block_size, &directory_blocks, directory_bytes);

        let count = read_u32(&directory, 0)? as usize;
        let mut streams = Vec::with_capacity(count);
        let mut sizes = Vec::with_capacity(count);
        for index in 0..count {
            sizes.push(read_u32(&directory, 4 + index * 4)?);
        }
        let mut at = 4 + count * 4;
        for size in sizes {
            // A stream of no length has no blocks at all.
            let length = if size == u32::MAX { 0 } else { size as usize };
            let blocks_needed = length.div_ceil(block_size);
            let mut blocks = Vec::with_capacity(blocks_needed);
            for _ in 0..blocks_needed {
                blocks.push(read_u32(&directory, at)?);
                at += 4;
            }
            streams.push((length, blocks));
        }

        Ok(Self {
            data,
            block_size,
            streams,
        })
    }

    /// The bytes of one stream, gathered from its blocks.
    fn stream(&self, index: usize) -> Result<Vec<u8>> {
        let (length, blocks) = self
            .streams
            .get(index)
            .ok_or_else(|| VolatilityError::Other(format!("The database has no stream {index}")))?;
        Ok(gather(self.data, self.block_size, blocks, *length))
    }
}

/// Read a stream's blocks into one run of bytes.
fn gather(data: &[u8], block_size: usize, blocks: &[u32], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    for block in blocks {
        let at = *block as usize * block_size;
        let end = (at + block_size).min(data.len());
        if at >= data.len() {
            break;
        }
        result.extend_from_slice(&data[at..end]);
    }
    result.truncate(length);
    result
}

fn read_u16(data: &[u8], at: usize) -> Result<u16> {
    data.get(at..at + 2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| VolatilityError::Other("The database ends mid-record".to_string()))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| VolatilityError::Other("The database ends mid-record".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's own database is the one every Windows image needs, so it is
    /// the natural thing to read as a check.
    #[test]
    #[ignore = "reaches the symbol server"]
    fn the_kernel_database_names_its_symbols() {
        let data = fetch("ntkrnlmp.pdb", "89284D0CA6ACC8274B9A44BD5AF9290B", 1).unwrap();
        let symbols = public_symbols(&data).unwrap();
        assert!(symbols.len() > 1000);
        // The address is the one the kernel's own symbol file records.
        assert_eq!(symbols.address_of("PsLoadedModuleList"), Some(12_755_632));
    }
}
