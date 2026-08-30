//! Scan memory for NTFS Master File Table records.
//!
//! An MFT record describes one file: its timestamps, its names, and where its
//! data lives. Records are self-identifying (each opens with `FILE`, or with
//! `BAAD` when the filesystem marked it corrupt), so they can be recovered from
//! memory without the filesystem being mounted.
//!
//! A record is a header followed by a chain of attributes, each naming its own
//! kind and length. The three views here read the same chain and report
//! different parts of it: the timestamps and names, the streams hidden beside
//! a file, and the content small enough to live inside the record itself.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, MultiStringScanner};
use crate::framework::plugins::windows::physical_layer;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::conversion::wintime_unsigned_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct MftScan;

/// What a record's first bytes look like. The fifth byte is where the update
/// sequence begins, and only two placements of it are ever seen, so searching
/// for them together rejects most text that happens to read `FILE`.
const SIGNATURES: [&[u8]; 3] = [b"FILE0", b"FILE*", b"BAAD"];

/// How much of a record is read at a time. Records are 1KB in practice. The
/// window grows if an attribute chain runs past what was read.
const WINDOW: usize = 0x1000;

/// The furthest a chain is followed before it is treated as nonsense.
const MAX_WINDOW: usize = 0x10000;

/// How far into an attribute its content begins.
const ATTRIBUTE_DATA: u64 = 24;

/// The kinds an attribute can be. The description these come from stores the
/// kind in a single byte, so the one code that does not fit in one is not
/// reachable and is not listed.
const ATTRIBUTE_TYPES: &[(u8, &str)] = &[
    (16, "STANDARD_INFORMATION"),
    (32, "ATTRIBUTE_LIST"),
    (48, "FILE_NAME"),
    (64, "OBJECT_ID"),
    (80, "SECURITY_DESCRIPTOR"),
    (96, "VOLUME_NAME"),
    (112, "VOLUME_INFORMATION"),
    (114, "INDEX_ROOT"),
    (128, "DATA"),
    (160, "INDEX_ALLOCATION"),
    (176, "BITMAP"),
    (192, "REPARSE_POINT"),
    (208, "EA_INFORMATION"),
    (224, "EA"),
    (240, "PROPERTY_SET"),
];

/// What a record says it is.
const RECORD_FLAGS: &[(u8, &str)] = &[
    (0, "Removed"),
    (1, "File"),
    (2, "Directory"),
    (3, "DirInUse"),
];

/// The permissions a name attribute records. As above, only the values that
/// fit in a byte can ever be matched.
const PERMISSION_FLAGS: &[(u8, &str)] = &[
    (1, "ReadOnly"),
    (2, "Hidden"),
    (4, "System"),
    (32, "Archive"),
    (34, "ArchiveHidden"),
    (36, "ArchiveSystem"),
    (38, "ArchiveHiddenSystem"),
    (60, "Device"),
    (128, "Normal"),
];

/// The largest content or name a record is believed about. A record claiming
/// more than this has been smeared.
const MAX_RESIDENT: u32 = 0x400000;

impl Plugin for MftScan {
    fn name(&self) -> &'static str {
        "windows.mftscan.MFTScan"
    }

    fn description(&self) -> &'static str {
        "Scans for MFT FILE objects present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Record Type"),
            Column::int("Record Number"),
            Column::int("Link Count"),
            Column::string("MFT Type"),
            Column::string("Permissions"),
            Column::string("Attribute Type"),
            Column::datetime("Created"),
            Column::datetime("Modified"),
            Column::datetime("Updated"),
            Column::datetime("Accessed"),
            Column::string("Filename"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};

        let layer = physical_layer(config);
        let mut timeline = Timeline::new();

        for mut record in enumerate_records(&context, &layer).ok()? {
            // The record's own timestamps are described by the longest of the
            // names it carries, which is the one closest to a full path.
            // A record with no names at all is still described, by the word
            // the reference implementation prints for a missing name.
            let name = record
                .longest_file_name(&context, &layer)
                .unwrap_or_else(|| "None".to_string());
            for attribute in record.attributes_of(&context, &layer, "STANDARD_INFORMATION") {
                let Some(times) = record.timestamps(&attribute, 0) else {
                    continue;
                };
                let description = format!("MFT STANDARD_INFORMATION entry for {name}");
                for (kind, when) in [
                    (TimeKind::Created, times[0]),
                    (TimeKind::Modified, times[1]),
                    (TimeKind::Changed, times[2]),
                    (TimeKind::Accessed, times[3]),
                ] {
                    timeline.push(description.clone(), kind, wintime_unsigned_value(when));
                }
            }

            for attribute in record.attributes_of(&context, &layer, "FILE_NAME") {
                let Some(times) = record.timestamps(&attribute, 8) else {
                    continue;
                };
                let Some(filename) = record.file_name(&context, &layer, &attribute) else {
                    continue;
                };
                let description = format!("MFT FILE_NAME entry for {filename}");
                for (kind, when) in [
                    (TimeKind::Created, times[0]),
                    (TimeKind::Modified, times[1]),
                    (TimeKind::Changed, times[2]),
                    (TimeKind::Accessed, times[3]),
                ] {
                    timeline.push(description.clone(), kind, wintime_unsigned_value(when));
                }
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let layer = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        for mut record in enumerate_records(&context, &layer)? {
            let kind = lookup(RECORD_FLAGS, record.flags);

            // The timestamps the filesystem keeps for the record itself come
            // first, and the names hanging off it are reported beneath.
            for attribute in record.attributes_of(&context, &layer, "STANDARD_INFORMATION") {
                let Some(times) = record.timestamps(&attribute, 0) else {
                    continue;
                };
                grid.push(
                    0,
                    vec![
                        Value::hex(attribute.offset + ATTRIBUTE_DATA),
                        Value::string(record.signature.clone()),
                        Value::int(record.record_number as i64),
                        Value::int(record.link_count as i64),
                        Value::string(kind.clone()),
                        Value::not_applicable(),
                        Value::string("STANDARD_INFORMATION"),
                        wintime_unsigned_value(times[0]),
                        wintime_unsigned_value(times[1]),
                        wintime_unsigned_value(times[2]),
                        wintime_unsigned_value(times[3]),
                        Value::not_applicable(),
                    ],
                )?;
            }

            for attribute in record.attributes_of(&context, &layer, "FILE_NAME") {
                let Some(times) = record.timestamps(&attribute, 8) else {
                    continue;
                };
                let permissions = record
                    .byte_at(&attribute, 56)
                    .map(|flags| lookup(PERMISSION_FLAGS, flags))
                    .unwrap_or_else(|| "0x0".to_string());
                grid.push(
                    1,
                    vec![
                        Value::hex(attribute.offset + ATTRIBUTE_DATA),
                        Value::string(record.signature.clone()),
                        Value::int(record.record_number as i64),
                        Value::int(record.link_count as i64),
                        Value::string(kind.clone()),
                        Value::string(permissions),
                        Value::string("FILE_NAME"),
                        wintime_unsigned_value(times[0]),
                        wintime_unsigned_value(times[1]),
                        wintime_unsigned_value(times[2]),
                        wintime_unsigned_value(times[3]),
                        record
                            .file_name(&context, &layer, &attribute)
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Reports the streams a file carries beside its own content.
///
/// NTFS lets a file hold any number of named streams, which no ordinary
/// listing shows. Hiding a payload in one is a long-standing technique.
pub struct Ads;

impl Plugin for Ads {
    fn name(&self) -> &'static str {
        "windows.mftscan.ADS"
    }

    fn description(&self) -> &'static str {
        "Scans for Alternate Data Stream"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Record Type"),
            Column::int("Record Number"),
            Column::string("MFT Type"),
            Column::string("Filename"),
            Column::string("ADS Filename"),
            Column::bytes("Hexdump"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let layer = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        for mut record in enumerate_records(&context, &layer)? {
            for attribute in record.data_attributes(&context, &layer, true) {
                // A record whose names are all empty has none worth reporting.
                let file_name = record
                    .longest_file_name(&context, &layer)
                    .filter(|name| !name.is_empty());
                grid.push(
                    0,
                    vec![
                        Value::hex(attribute.offset + ATTRIBUTE_DATA),
                        Value::string(record.signature.clone()),
                        Value::int(record.record_number as i64),
                        Value::string("DATA"),
                        file_name.map(Value::string).unwrap_or_else(Value::not_available),
                        record
                            .stream_name(&attribute)
                            .map(Value::string)
                            .unwrap_or_else(Value::not_available),
                        resident_content(&context, &layer, &attribute)
                            .unwrap_or_else(Value::not_available),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Reports file content small enough to be stored inside its MFT record.
///
/// NTFS keeps a small file's content in the record itself rather than
/// allocating clusters for it, so those files can be recovered whole from the
/// record alone.
pub struct ResidentData;

impl Plugin for ResidentData {
    fn name(&self) -> &'static str {
        "windows.mftscan.ResidentData"
    }

    fn description(&self) -> &'static str {
        "Scans for MFT Records with Resident Data"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Record Type"),
            Column::int("Record Number"),
            Column::string("MFT Type"),
            Column::string("Filename"),
            Column::bytes("Hexdump"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let layer = physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());

        for mut record in enumerate_records(&context, &layer)? {
            // Only the file's own stream, and only the first of them.
            let Some(attribute) = record.data_attributes(&context, &layer, false).into_iter().next()
            else {
                continue;
            };
            let file_name = record
                .longest_file_name(&context, &layer)
                .filter(|name| !name.is_empty());
            grid.push(
                0,
                vec![
                    Value::hex(attribute.offset + ATTRIBUTE_DATA),
                    Value::string(record.signature.clone()),
                    Value::int(record.record_number as i64),
                    Value::string("DATA"),
                    // The name is written out as text whether or not there is
                    // one, so a record with none says so in words.
                    Value::string(file_name.unwrap_or_else(|| "N/A".to_string())),
                    resident_content(&context, &layer, &attribute)
                        .unwrap_or_else(Value::not_available),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// One attribute of a record.
pub struct Attribute {
    /// Where the attribute itself begins.
    pub offset: u64,
    pub kind: u8,
    pub length: u32,
    pub non_resident: u8,
    pub name_length: u8,
    pub name_offset: u16,
    pub content_length: u32,
    pub content_offset: u16,
}

/// One MFT record, with as much of it as has been read so far.
pub struct MftRecord {
    pub offset: u64,
    pub signature: String,
    pub link_count: u16,
    pub flags: u8,
    pub record_number: u32,
    first_attribute: u16,
    /// The bytes read starting at `offset`.
    window: Vec<u8>,
}

/// Find every record in the layer and read its header.
fn enumerate_records(context: &Arc<Context>, layer_name: &str) -> Result<Vec<MftRecord>> {
    let layer = context.layers.get(layer_name)?;
    // The search upstream uses does not hold back matches that fall in the
    // region a chunk repeats, so a record that lands there is reported once
    // for each chunk that sees it.
    let scanner = MultiStringScanner::new(SIGNATURES.iter().map(|s| s.to_vec()).collect())?
        .reporting_overlap();

    let mut offsets: Vec<u64> = Vec::new();
    scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        offsets.push(offset)
    })?;

    let mut records = Vec::with_capacity(offsets.len());
    for offset in offsets {
        if let Some(record) = MftRecord::read(context, layer_name, offset) {
            records.push(record);
        }
    }
    Ok(records)
}

impl MftRecord {
    /// Read a record's header at `offset`.
    fn read(context: &Arc<Context>, layer: &str, offset: u64) -> Option<Self> {
        let window = read_window(context, layer, offset, WINDOW)?;
        if window.len() < 48 {
            return None;
        }
        Some(MftRecord {
            offset,
            signature: latin1(&window[0..4]),
            link_count: u16::from_le_bytes(window[18..20].try_into().unwrap()),
            first_attribute: u16::from_le_bytes(window[20..22].try_into().unwrap()),
            flags: window[22],
            record_number: u32::from_le_bytes(window[44..48].try_into().unwrap()),
            window,
        })
    }

    /// Walk the record's attribute chain.
    ///
    /// The chain has no count: it runs until an attribute names a kind that
    /// does not exist, and a zero-length attribute ends it too, since it would
    /// otherwise never advance.
    fn attributes(&mut self, context: &Arc<Context>, layer: &str) -> Vec<Attribute> {
        let mut found = Vec::new();
        let mut at = self.first_attribute as usize;

        loop {
            if !self.ensure(context, layer, at + 24) {
                break;
            }
            let header = &self.window[at..at + 24];
            let kind = header[0];
            if !ATTRIBUTE_TYPES.iter().any(|(code, _)| *code == kind) {
                break;
            }
            let length = u32::from_le_bytes(header[4..8].try_into().unwrap());
            found.push(Attribute {
                offset: self.offset + at as u64,
                kind,
                length,
                non_resident: header[8],
                name_length: header[9],
                name_offset: u16::from_le_bytes(header[10..12].try_into().unwrap()),
                content_length: u32::from_le_bytes(header[16..20].try_into().unwrap()),
                content_offset: u16::from_le_bytes(header[20..22].try_into().unwrap()),
            });
            if length == 0 {
                break;
            }
            at += length as usize;
            if at > MAX_WINDOW {
                break;
            }
        }
        found
    }

    /// The attributes of one kind, in the order the chain gives them.
    fn attributes_of(
        &mut self,
        context: &Arc<Context>,
        layer: &str,
        wanted: &str,
    ) -> Vec<Attribute> {
        self.attributes(context, layer)
            .into_iter()
            .filter(|attribute| name_of(ATTRIBUTE_TYPES, attribute.kind) == Some(wanted))
            .collect()
    }

    /// The resident `$DATA` attributes, either the named ones or the unnamed.
    fn data_attributes(
        &mut self,
        context: &Arc<Context>,
        layer: &str,
        named: bool,
    ) -> Vec<Attribute> {
        self.attributes(context, layer)
            .into_iter()
            .filter(|attribute| {
                name_of(ATTRIBUTE_TYPES, attribute.kind) == Some("DATA")
                    && attribute.non_resident == 0
                    && (attribute.name_length != 0) == named
            })
            .collect()
    }

    /// The four timestamps an attribute's content begins with, `from` bytes in.
    fn timestamps(&self, attribute: &Attribute, from: usize) -> Option<[u64; 4]> {
        let at = (attribute.offset - self.offset) as usize + ATTRIBUTE_DATA as usize + from;
        let bytes = self.window.get(at..at + 32)?;
        let mut times = [0u64; 4];
        for (index, time) in times.iter_mut().enumerate() {
            *time = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        }
        Some(times)
    }

    /// One byte of an attribute's content.
    fn byte_at(&self, attribute: &Attribute, from: usize) -> Option<u8> {
        let at = (attribute.offset - self.offset) as usize + ATTRIBUTE_DATA as usize + from;
        self.window.get(at).copied()
    }

    /// The name a `FILE_NAME` attribute carries.
    ///
    /// A name can be longer than the record's own bytes on a smeared record,
    /// so more is read where the name asks for it.
    fn file_name(
        &mut self,
        context: &Arc<Context>,
        layer: &str,
        attribute: &Attribute,
    ) -> Option<String> {
        let base = (attribute.offset - self.offset) as usize + ATTRIBUTE_DATA as usize;
        let length = *self.window.get(base + 64)? as usize * 2;
        // The name is read where it sits rather than out of the record's own
        // bytes, since a record whose tail is not in the image can still have
        // a readable name.
        match self.window.get(base + 66..base + 66 + length) {
            Some(bytes) => Some(decode_utf16(bytes)),
            None => context
                .layers
                .read(layer, attribute.offset + ATTRIBUTE_DATA + 66, length, false)
                .ok()
                .map(|bytes| decode_utf16(&bytes)),
        }
    }

    /// The longest of the record's names, which is the one that is not the
    /// shortened form the filesystem also keeps.
    fn longest_file_name(&mut self, context: &Arc<Context>, layer: &str) -> Option<String> {
        let attributes = self.attributes_of(context, layer, "FILE_NAME");
        // Where two names are the same length the first is kept, which is the
        // one the record lists first.
        let mut longest: Option<String> = None;
        for attribute in &attributes {
            let Some(name) = self.file_name(context, layer, attribute) else {
                continue;
            };
            let better = longest
                .as_ref()
                .map(|held| name.chars().count() > held.chars().count())
                .unwrap_or(true);
            if better {
                longest = Some(name);
            }
        }
        longest
    }

    /// The name of a stream, which sits between an attribute's header and its
    /// content.
    fn stream_name(&self, attribute: &Attribute) -> Option<String> {
        if attribute.content_offset as u32 > MAX_RESIDENT || attribute.name_length as u32 > 512 {
            return None;
        }
        let base = (attribute.offset - self.offset) as usize + attribute.name_offset as usize;
        let length = attribute.name_length as usize * 2;
        let bytes = self.window.get(base..base + length)?;
        Some(decode_utf16(bytes))
    }

    /// Read further into the record if an attribute reaches past what is held.
    fn ensure(&mut self, context: &Arc<Context>, layer: &str, upto: usize) -> bool {
        if upto <= self.window.len() {
            return true;
        }
        if upto > MAX_WINDOW {
            return false;
        }
        let wanted = upto.next_multiple_of(WINDOW);
        match read_window(context, layer, self.offset, wanted) {
            Some(window) if window.len() >= upto => {
                self.window = window;
                true
            }
            _ => false,
        }
    }
}

/// The content stored inside an attribute, as the layer holds it.
fn resident_content(
    context: &Arc<Context>,
    layer: &str,
    attribute: &Attribute,
) -> Option<Value> {
    if attribute.content_offset as u32 > MAX_RESIDENT || attribute.content_length > MAX_RESIDENT {
        return None;
    }
    crate::framework::plugins::layer_data(
        context,
        layer,
        attribute.offset + attribute.content_offset as u64,
        attribute.content_length as u64,
    )
}

/// Read up to `length` bytes, settling for less where the layer ends.
fn read_window(context: &Arc<Context>, layer: &str, offset: u64, length: usize) -> Option<Vec<u8>> {
    let mut wanted = length;
    while wanted >= 0x40 {
        if let Ok(data) = context.layers.read(layer, offset, wanted, false) {
            return Some(data);
        }
        wanted /= 2;
    }
    None
}

/// The name a code has in a set, or the code itself where it has none.
fn lookup(names: &'static [(u8, &'static str)], code: u8) -> String {
    name_of(names, code)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{code:#x}"))
}

/// The name a code has in a set.
fn name_of(names: &'static [(u8, &'static str)], code: u8) -> Option<&'static str> {
    names
        .iter()
        .find(|(value, _)| *value == code)
        .map(|(_, name)| *name)
}

/// Decode four bytes of signature the way a byte-per-character encoding would.
fn latin1(bytes: &[u8]) -> String {
    let text: String = bytes.iter().map(|byte| *byte as char).collect();
    match text.find('\0') {
        Some(end) => text[..end].to_string(),
        None => text,
    }
}

/// Decode a wide string, cutting it at the first terminator.
fn decode_utf16(bytes: &[u8]) -> String {
    // A leading mark says which way round the pairs are. Without one they are
    // little-endian.
    let (bytes, big_endian) = match bytes {
        [0xFF, 0xFE, rest @ ..] => (rest, false),
        [0xFE, 0xFF, rest @ ..] => (rest, true),
        _ => (bytes, false),
    };
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_le_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    let mut text = String::from_utf16_lossy(&units);
    // An odd trailing byte cannot be half of anything.
    if bytes.len() % 2 == 1 {
        text.push('\u{FFFD}');
    }
    match text.find('\0') {
        Some(end) => text[..end].to_string(),
        None => text,
    }
}
