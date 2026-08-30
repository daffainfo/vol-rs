//! QEMU suspend-to-disk (`QEVM`) layer.
//!
//! A QEMU savevm stream is a sequence of sections. The `ram` section carries
//! guest memory as a list of pages, each prefixed by an address word whose low
//! bits are flags. Pages may be stored verbatim, or as a single repeated byte.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::any::Any;
use std::collections::HashMap;

use crate::error::{Result, VolatilityError};
use crate::framework::layers::{DataLayer, LayerContainer, MappingEntry};

const PAGE_SIZE: u64 = 0x1000;
const QEVM_MAGIC: &[u8; 4] = b"QEVM";
const QEVM_VERSION: u32 = 3;

// Section markers within the savevm stream.
const QEVM_EOF: u8 = 0x00;
const QEVM_SECTION_START: u8 = 0x01;
const QEVM_SECTION_PART: u8 = 0x02;
const QEVM_SECTION_END: u8 = 0x03;
const QEVM_SECTION_FULL: u8 = 0x04;
const QEVM_SUBSECTION: u8 = 0x05;
const QEVM_VMDESCRIPTION: u8 = 0x06;
const QEVM_CONFIGURATION: u8 = 0x07;
const QEVM_SECTION_FOOTER: u8 = 0x7E;

// Flags packed into the low bits of a RAM page's address word.
const FLAG_COMPRESS: u64 = 0x02;
const FLAG_MEM_SIZE: u64 = 0x04;
const FLAG_PAGE: u64 = 0x08;
const FLAG_EOS: u64 = 0x10;
const FLAG_CONTINUE: u64 = 0x20;
const FLAG_XBZRLE: u64 = 0x40;
const FLAG_HOOK: u64 = 0x80;

/// How a page's bytes are stored in the file.
#[derive(Debug, Clone, Copy)]
enum PageSource {
    /// Verbatim bytes at this file offset.
    Raw(u64),
    /// A whole page of this repeated byte.
    Fill(u8),
}

#[derive(Debug, Clone, Copy)]
struct Page {
    address: u64,
    source: PageSource,
}

/// A QEMU suspend-to-disk layer over the savevm file.
pub struct QemuLayer {
    name: String,
    base_layer: String,
    /// Sorted by guest physical address.
    pages: Vec<Page>,
    minimum_address: u64,
    maximum_address: u64,
}

/// Verify the savevm header.
pub fn check(layers: &LayerContainer, layer: &str) -> Result<()> {
    let header = layers.read(layer, 0, 8, false)?;
    if &header[0..4] != QEVM_MAGIC {
        return Err(VolatilityError::layer(layer, "No QEMU magic bytes"));
    }
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    if version != QEVM_VERSION {
        return Err(VolatilityError::layer(
            layer,
            format!("Unsupported QEMU savevm version {version}"),
        ));
    }
    Ok(())
}

/// Reads big-endian values sequentially from the base layer.
struct Reader<'a> {
    layers: &'a LayerContainer,
    layer: &'a str,
    offset: u64,
    limit: u64,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let data = self.layers.read(self.layer, self.offset, length, false)?;
        self.offset += length as u64;
        Ok(data)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    /// A length-prefixed name string.
    fn name(&mut self) -> Result<String> {
        let length = self.u8()? as usize;
        let data = self.bytes(length)?;
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    fn at_end(&self) -> bool {
        self.offset >= self.limit
    }
}

impl QemuLayer {
    pub fn build(
        layers: &LayerContainer,
        name: impl Into<String>,
        base_layer: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        let base_layer = base_layer.into();
        check(layers, &base_layer)?;

        let limit = layers.get(&base_layer)?.maximum_address();
        let mut reader = Reader {
            layers,
            layer: &base_layer,
            offset: 8,
            limit,
        };

        let mut pages: Vec<Page> = Vec::new();
        // The RAM stream names each block once. Later pages reuse the last name
        // via the CONTINUE flag.
        let mut current_block = String::new();
        let mut block_bases: HashMap<String, u64> = HashMap::new();

        while !reader.at_end() {
            let section_type = reader.u8()?;
            match section_type {
                QEVM_EOF => break,
                QEVM_CONFIGURATION => {
                    let length = reader.u32()? as usize;
                    reader.bytes(length)?;
                }
                QEVM_SECTION_START | QEVM_SECTION_FULL => {
                    let _section_id = reader.u32()?;
                    let section_name = reader.name()?;
                    let _instance_id = reader.u32()?;
                    let _version_id = reader.u32()?;

                    if section_name == "ram" {
                        Self::read_ram_section(
                            &mut reader,
                            &mut pages,
                            &mut current_block,
                            &mut block_bases,
                        )?;
                    } else {
                        // Other devices are skipped by scanning forward to the
                        // next recognisable marker.
                        Self::skip_to_footer(&mut reader)?;
                    }
                }
                QEVM_SECTION_PART | QEVM_SECTION_END => {
                    let _section_id = reader.u32()?;
                    Self::read_ram_section(
                        &mut reader,
                        &mut pages,
                        &mut current_block,
                        &mut block_bases,
                    )?;
                }
                QEVM_SECTION_FOOTER => {
                    let _section_id = reader.u32()?;
                }
                QEVM_VMDESCRIPTION => {
                    let length = reader.u32()? as usize;
                    reader.bytes(length)?;
                }
                QEVM_SUBSECTION => {
                    let _name = reader.name()?;
                    let _version = reader.u32()?;
                }
                _ => break,
            }
        }

        if pages.is_empty() {
            return Err(VolatilityError::layer(&name, "No QEMU RAM pages found"));
        }

        pages.sort_unstable_by_key(|page| page.address);
        pages.dedup_by_key(|page| page.address);
        let minimum_address = pages.first().unwrap().address;
        let maximum_address = pages.last().unwrap().address + PAGE_SIZE - 1;

        Ok(Self {
            name,
            base_layer,
            pages,
            minimum_address,
            maximum_address,
        })
    }

    /// Consume the pages of a RAM section until the end-of-stream flag.
    fn read_ram_section(
        reader: &mut Reader<'_>,
        pages: &mut Vec<Page>,
        current_block: &mut String,
        block_bases: &mut HashMap<String, u64>,
    ) -> Result<()> {
        loop {
            if reader.at_end() {
                return Ok(());
            }
            let addr = reader.u64()?;
            let flags = addr & (PAGE_SIZE - 1);
            let address = addr & !(PAGE_SIZE - 1);

            if flags & FLAG_MEM_SIZE != 0 {
                // A table of block name/length pairs totalling `address` bytes.
                let mut remaining = address;
                while remaining > 0 {
                    let block_name = reader.name()?;
                    let length = reader.u64()?;
                    remaining = remaining.saturating_sub(length);
                    block_bases.entry(block_name).or_insert(0);
                }
                continue;
            }

            if flags & FLAG_EOS != 0 {
                return Ok(());
            }

            if flags & FLAG_CONTINUE == 0 {
                *current_block = reader.name()?;
            }

            // RAM blocks other than main memory are device windows we do not map.
            let is_main = current_block == "pc.ram" || current_block.is_empty();

            if flags & FLAG_COMPRESS != 0 {
                let fill = reader.u8()?;
                if is_main {
                    pages.push(Page {
                        address,
                        source: PageSource::Fill(fill),
                    });
                }
            } else if flags & FLAG_PAGE != 0 {
                let at = reader.offset;
                reader.bytes(PAGE_SIZE as usize)?;
                if is_main {
                    pages.push(Page {
                        address,
                        source: PageSource::Raw(at),
                    });
                }
            } else if flags & (FLAG_XBZRLE | FLAG_HOOK) != 0 {
                // Delta-encoded and hook pages only appear in live migration
                // streams, not in a suspend-to-disk image.
                return Err(VolatilityError::Other(
                    "QEMU XBZRLE/hook pages are not supported".to_string(),
                ));
            } else if flags == 0 {
                // A bare address with no flags ends the RAM stream.
                return Ok(());
            }
        }
    }

    /// Skip a device section by scanning for its footer marker.
    fn skip_to_footer(reader: &mut Reader<'_>) -> Result<()> {
        while !reader.at_end() {
            if reader.u8()? == QEVM_SECTION_FOOTER {
                let _section_id = reader.u32()?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn find_page(&self, address: u64) -> Option<&Page> {
        let aligned = address & !(PAGE_SIZE - 1);
        self.pages
            .binary_search_by_key(&aligned, |page| page.address)
            .ok()
            .map(|index| &self.pages[index])
    }
}

impl DataLayer for QemuLayer {
    fn kind(&self) -> &'static str {
        "QemuSuspendLayer"
    }

    fn class_module(&self) -> &'static str {
        "volatility3.framework.layers.qemu"
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        self.minimum_address
    }

    fn maximum_address(&self) -> u64 {
        self.maximum_address
    }

    fn is_valid(&self, _layers: &LayerContainer, offset: u64, length: u64) -> bool {
        let end = offset.saturating_add(length.max(1) - 1);
        (offset..=end)
            .step_by(PAGE_SIZE as usize)
            .chain(std::iter::once(end))
            .all(|address| self.find_page(address).is_some())
    }

    fn dependencies(&self) -> Vec<String> {
        vec![self.base_layer.clone()]
    }

    fn is_linear(&self) -> bool {
        false
    }

    fn mapping(
        &self,
        _layers: &LayerContainer,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Result<Vec<MappingEntry>> {
        let mut result = Vec::new();
        let end = offset.saturating_add(length.max(1));
        let mut current = offset;

        while current < end {
            match self.find_page(current) {
                Some(page) => {
                    let page_offset = current & (PAGE_SIZE - 1);
                    let chunk = (PAGE_SIZE - page_offset).min(end - current);
                    if let PageSource::Raw(at) = page.source {
                        result.push(MappingEntry {
                            offset: current,
                            size: chunk,
                            mapped_offset: at + page_offset,
                            mapped_size: chunk,
                            layer: self.base_layer.clone(),
                        });
                    }
                    // Fill pages have no bytes in the file, so they are
                    // synthesised during read rather than mapped.
                    current += chunk;
                }
                None => {
                    if !ignore_errors {
                        return Err(VolatilityError::invalid_address(
                            &self.name,
                            current,
                            "Page is not present in the QEMU image",
                        ));
                    }
                    current = (current & !(PAGE_SIZE - 1)) + PAGE_SIZE;
                }
            }
        }
        Ok(result)
    }

    fn read(&self, layers: &LayerContainer, offset: u64, length: usize, pad: bool) -> Result<Vec<u8>> {
        let mut output = vec![0u8; length];
        let mut current = offset;
        let end = offset + length as u64;

        while current < end {
            let page_offset = current & (PAGE_SIZE - 1);
            let chunk = ((PAGE_SIZE - page_offset) as usize).min((end - current) as usize);
            let destination = (current - offset) as usize;

            match self.find_page(current) {
                Some(page) => match page.source {
                    PageSource::Raw(at) => {
                        let data = layers.read(&self.base_layer, at + page_offset, chunk, pad)?;
                        output[destination..destination + chunk].copy_from_slice(&data);
                    }
                    PageSource::Fill(byte) => {
                        output[destination..destination + chunk].fill(byte);
                    }
                },
                None if !pad => {
                    return Err(VolatilityError::invalid_address(
                        &self.name,
                        current,
                        "Page is not present in the QEMU image",
                    ))
                }
                None => {}
            }
            current += chunk as u64;
        }
        Ok(output)
    }

    fn metadata(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
