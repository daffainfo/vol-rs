//! Layer scanners that return locations of particular values from within the
//! data.
//!
//! These are designed to be given a chunk of data and return a generator which
//! yields any found items. They should NOT perform complex/time-consuming
//! tasks, these should be carried out by the consumer of the generator on the
//! items returned.
//!
//! They will be provided all *available* data (therefore not necessarily
//! contiguous) in ascending offset order, in chunks no larger than
//! `chunk_size + overlap` where overlap is the amount of data read twice, once
//! at the end of an earlier chunk and once at the start of the next chunk.
//!
//! It should be noted that the scanner can maintain state if necessary.
//! Scanners should balance the size of chunk based on the amount of time
//! scanning the chunk will take (ie, do not set an excessively large chunksize
//! and try not to take a significant amount of time in the call method).
//!
//! Scanners must NOT return results found *after* `chunk_size` (ie, entirely
//! contained within the overlap). It is the responsibility of the scanner not
//! to return such duplicate results.
//!
//! Scanners can mark themselves as thread safe, if they do not require state
//! in either their own class or the context. This will allow the scanner to be
//! run in parallel against multiple blocks.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use regex::bytes::Regex;

use crate::constants::{SCAN_CHUNK_SIZE, SCAN_OVERLAP};
use crate::error::Result;
use crate::framework::layers::{coalesce_sections, DataLayer, LayerContainer};

/// Searches through a chunk of data for a particular value/pattern/etc.
///
/// Always returns an iterator of the same type of object. `data` is the chunk
/// of data to search through, and the data offset is the offset within the
/// layer that the data being searched starts at.
pub trait Scanner: Send + Sync {
    /// Bytes of fresh data offered per call.
    fn chunk_size(&self) -> usize {
        SCAN_CHUNK_SIZE
    }

    /// Bytes of the previous chunk repeated at the start of the next.
    fn overlap(&self) -> usize {
        SCAN_OVERLAP
    }

    /// Examine `data`, which begins at absolute offset `data_offset`, and
    /// return the absolute offsets of any hits.
    fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64>;

    /// Whether hits inside the repeated region are the scanner's to report.
    ///
    /// Almost every scanner stays silent there so that a match straddling a
    /// boundary is reported once, by the chunk that holds all of it. A scanner
    /// that says otherwise takes responsibility for the region, and the driver
    /// stops holding its hits back, including the ones two chunks both see.
    fn reports_overlap(&self) -> bool {
        false
    }
}

/// Finds every occurrence of a single byte string.
pub struct BytesScanner {
    needle: Vec<u8>,
}

impl BytesScanner {
    pub fn new(needle: impl Into<Vec<u8>>) -> Self {
        Self {
            needle: needle.into(),
        }
    }
}

impl Scanner for BytesScanner {
    fn overlap(&self) -> usize {
        // Enough overlap that a needle spanning a chunk boundary is seen whole.
        SCAN_OVERLAP.max(self.needle.len())
    }

    fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        if self.needle.is_empty() || data.len() < self.needle.len() {
            return Vec::new();
        }
        let limit = self.chunk_size().min(data.len());
        let mut hits = Vec::new();
        let first = self.needle[0];
        let mut position = 0usize;
        while position + self.needle.len() <= data.len() {
            match data[position..].iter().position(|&byte| byte == first) {
                Some(delta) => {
                    let at = position + delta;
                    if at >= limit {
                        break;
                    }
                    if data[at..].starts_with(&self.needle) {
                        hits.push(data_offset + at as u64);
                    }
                    position = at + 1;
                }
                None => break,
            }
        }
        hits
    }
}

/// Finds any of several byte strings in one pass.
///
/// An algorithm for multi-string matching.
pub struct MultiStringScanner {
    automaton: AhoCorasick,
    patterns: Vec<Vec<u8>>,
    longest: usize,
    /// Whether a match in the repeated region is reported again.
    ///
    /// A scanner normally stays silent there so the next chunk reports it
    /// once. Some searches upstream does not filter, and a caller matching
    /// them has to report the region twice as well.
    report_overlap: bool,
}

impl MultiStringScanner {
    pub fn new(patterns: Vec<Vec<u8>>) -> Result<Self> {
        let longest = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let automaton = AhoCorasick::new(&patterns)
            .map_err(|e| crate::error::VolatilityError::Other(format!("Bad pattern set: {e}")))?;
        Ok(Self {
            automaton,
            patterns,
            longest,
            report_overlap: false,
        })
    }

    /// Report matches in the repeated region as well, which reports anything
    /// found there twice.
    pub fn reporting_overlap(mut self) -> Self {
        self.report_overlap = true;
        self
    }

    /// Where in a chunk matches stop being reported.
    fn limit(&self, data: &[u8]) -> usize {
        if self.report_overlap {
            data.len()
        } else {
            self.chunk_size().min(data.len())
        }
    }

    /// Scan and report which pattern matched alongside its offset.
    pub fn scan_with_patterns(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let limit = self.limit(data);
        self.automaton
            .find_overlapping_iter(data)
            .filter(|m| m.start() < limit)
            .map(|m| {
                (
                    data_offset + m.start() as u64,
                    self.patterns[m.pattern().as_usize()].clone(),
                )
            })
            .collect()
    }
}

impl Scanner for MultiStringScanner {
    fn overlap(&self) -> usize {
        SCAN_OVERLAP.max(self.longest)
    }

    fn reports_overlap(&self) -> bool {
        self.report_overlap
    }

    fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        let limit = self.limit(data);
        self.automaton
            .find_overlapping_iter(data)
            .filter(|m| m.start() < limit)
            .map(|m| data_offset + m.start() as u64)
            .collect()
    }
}

/// A scanner that can be provided with a bytes-object regular expression
/// pattern. The scanner will scan all blocks for the regular expression and
/// report the absolute offset of any finds.
///
/// The default flags include DOTALL, since the searches are through binary
/// data and the newline character should have no specific significance in
/// such searches.
pub struct RegExScanner {
    pattern: Regex,
}

impl RegExScanner {
    pub fn new(pattern: &str) -> Result<Self> {
        Ok(Self {
            pattern: Regex::new(pattern).map_err(|e| {
                crate::error::VolatilityError::Other(format!("Bad regular expression: {e}"))
            })?,
        })
    }

    /// The first match anywhere in `data`.
    ///
    /// Applying the pattern again to what was read at a hit is how the match
    /// itself is recovered once the scan has only reported where it begins.
    pub fn first_match(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.pattern.find(data).map(|found| found.as_bytes().to_vec())
    }

    /// The match starting at the very beginning of `data`, if there is one.
    ///
    /// Applying the pattern again at a hit is how the match itself is recovered
    /// once the scan has only reported where it begins.
    pub fn match_at_start(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.pattern
            .find(data)
            .filter(|found| found.start() == 0)
            .map(|found| found.as_bytes().to_vec())
    }

    /// Scan and return the matched bytes alongside each offset.
    pub fn scan_with_matches(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let limit = self.chunk_size().min(data.len());
        self.pattern
            .find_iter(data)
            .filter(|m| m.start() < limit)
            .map(|m| (data_offset + m.start() as u64, m.as_bytes().to_vec()))
            .collect()
    }
}

impl Scanner for RegExScanner {
    fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        let limit = self.chunk_size().min(data.len());
        self.pattern
            .find_iter(data)
            .filter(|m| m.start() < limit)
            .map(|m| data_offset + m.start() as u64)
            .collect()
    }
}

/// Scans a layer by chunk, invoking `on_hit` for every offset found.
///
/// Note: this will skip missing/unmappable chunks of memory.
///
/// # Args
///
/// * `scanner` - The constructed Scanner object to be applied
/// * `sections` - A list of (start, size) tuples defining the portions of the
///   layer to scan
///
/// Unreadable regions are skipped rather than aborting the scan, since a memory
/// image is expected to have holes.
pub fn scan_layer<F>(
    layer: &dyn DataLayer,
    layers: &LayerContainer,
    scanner: &dyn Scanner,
    sections: Option<&[(u64, u64)]>,
    mut on_hit: F,
) -> Result<()>
where
    F: FnMut(u64),
{
    scan_layer_until(layer, layers, scanner, sections, |hit| {
        on_hit(hit);
        true
    })
}

/// As [`scan_layer`], but the caller may stop the scan.
///
/// `on_hit` returns whether to keep going. A search for one thing (the kernel
/// banner, the idle task) is answered by the first hit that validates, and
/// stopping there saves reading the rest of the image, which for a multi-
/// gigabyte capture is most of the run.
pub fn scan_layer_until<F>(
    layer: &dyn DataLayer,
    layers: &LayerContainer,
    scanner: &dyn Scanner,
    sections: Option<&[(u64, u64)]>,
    mut on_hit: F,
) -> Result<()>
where
    F: FnMut(u64) -> bool,
{
    // With nothing asked for, the whole layer is the section, which is what
    // upstream takes as its default.
    let whole = [(
        layer.minimum_address(),
        layer.maximum_address().saturating_sub(layer.minimum_address()),
    )];
    let sections = coalesce_sections(
        sections.unwrap_or(&whole),
        layer.minimum_address(),
        layer.maximum_address(),
    );

    let chunk_size = scanner.chunk_size();
    let overlap = scanner.overlap();

    // Indicates which blocks in the layer are to be read for the scanning.
    // This is a list of blocks (potentially in lower layers) that make up this
    // chunk contiguously. Chunks can be no bigger than
    // scanner.chunk_size + scanner.overlap, and data layers by default are
    // assumed to have no holes.
    //
    // Upstream ships one chunk per run of addresses the layer maps contiguously
    // onto the one beneath it, and never reads across the boundary between two
    // runs, so a match that straddles one is not found. A layer that maps
    // nothing of its own returns one run per section, which is the same as
    // chunking the section.
    //
    // The chunks are laid out first so the scan itself is a plain map over
    // them, which is what lets it run on every core at once.
    let mut chunks: Vec<Chunk> = Vec::new();
    for (section_start, section_length) in sections {
        let blocks = layer
            .mapping(layers, section_start, section_length, true)
            .unwrap_or_default();
        for block in blocks {
            // A run of a linearly mapped layer lands on one run of the layer
            // beneath it, so the bytes can be taken from there and the tables
            // walked once for the run instead of once per page. A layer that
            // does not map linearly has to be read through, because the
            // offsets either side are not a fixed distance apart.
            let source = if layer.is_linear() && block.size == block.mapped_size {
                layers
                    .get(&block.layer)
                    .ok()
                    .map(|lower| (lower, block.mapped_offset))
            } else {
                None
            };
            let end = block.offset.saturating_add(block.size);
            let mut offset = block.offset;
            while offset < end {
                let want = ((chunk_size + overlap) as u64).min(end - offset) as usize;
                chunks.push(Chunk {
                    offset,
                    want,
                    // Carried forward by the same distance the run was shifted.
                    source: source
                        .as_ref()
                        .map(|(lower, at)| (lower.clone(), at + (offset - block.offset))),
                });
                // Advance by the fresh portion only, so the overlap is
                // re-read as the start of the next chunk.
                offset += chunk_size as u64;
            }
        }
    }

    // Chunks are scanned a batch at a time rather than all at once, so a
    // caller that stops early reads only a little past the hit it wanted while
    // every core still works on the batch in hand.
    let batch_size = (rayon::current_num_threads() * 4).max(1);
    let mut reported: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for batch in chunks.chunks(batch_size) {
        let found: Vec<Vec<u64>> = batch
            .par_iter()
            .map(|chunk| {
                // The overlap exists so a match straddling the boundary is
                // seen. A hit that starts inside it belongs to the next chunk,
                // which reads the same bytes, so reporting it here would
                // report it twice. This is the rule each of upstream's own
                // scanners applies to what it finds.
                let fresh_end = chunk.offset + chunk_size as u64;
                let keep_overlap = scanner.reports_overlap();
                let mut hits = Vec::new();

                // Padding keeps a chunk that straddles a hole usable. The
                // zeroes it introduces will simply not match. The bytes are
                // borrowed where the layer can lend them, which for a scan of
                // a whole image saves copying every byte of it.
                // Read from beneath where those are the same bytes. A hit is
                // still reported against the layer being scanned either way.
                let (reader, at) = match &chunk.source {
                    Some((lower, at)) => (lower.as_ref(), *at),
                    None => (layer, chunk.offset),
                };
                let examined = reader.with_bytes(
                    layers,
                    at,
                    chunk.want,
                    true,
                    &mut |data: &[u8]| {
                        hits = scanner
                            .scan(data, chunk.offset)
                            .into_iter()
                            .filter(|hit| keep_overlap || *hit < fresh_end)
                            .collect();
                    },
                );
                if let Err(error) = examined {
                    log::debug!(
                        "Skipping unreadable region at {:#x} in {}: {error}",
                        chunk.offset,
                        layer.name()
                    );
                    return Vec::new();
                }
                hits
            })
            .collect();

        // Reported in address order, whatever order they were found in. A hit
        // is a place, not an event: two sections that abut, or a scanner that
        // matches on more than one needle at once, must not report it twice.
        for hits in found {
            for hit in hits {
                // A scanner that owns the repeated region reports what it
                // finds there, so the same place can legitimately come up
                // twice and is passed on both times.
                if scanner.reports_overlap() {
                    if !on_hit(hit) {
                        return Ok(());
                    }
                } else if reported.insert(hit) && !on_hit(hit) {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// One unit of scanning work: where to read and how much.
struct Chunk {
    /// Where the chunk begins in the layer being scanned, which is what a hit
    /// found inside it is reported against.
    offset: u64,
    want: usize,
    /// Where the same bytes can be read without translating them again.
    ///
    /// Upstream's `LinearlyMappedLayer` scans with `linear` set, which has the
    /// iterator hand back the layer underneath and the offset already
    /// converted, so reading a chunk does not walk the tables a second time
    /// for every page of it.
    source: Option<(Arc<dyn DataLayer>, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::layers::segmented::{Segment, SegmentedLayer};
    use std::collections::HashMap;

    #[test]
    fn bytes_scanner_finds_every_occurrence() {
        let scanner = BytesScanner::new(b"NEEDLE".to_vec());
        let mut data = vec![0u8; 100];
        data[10..16].copy_from_slice(b"NEEDLE");
        data[60..66].copy_from_slice(b"NEEDLE");
        assert_eq!(scanner.scan(&data, 0x1000), vec![0x100A, 0x103C]);
    }

    #[test]
    fn multi_string_scanner_reports_the_matching_pattern() {
        let scanner =
            MultiStringScanner::new(vec![b"alpha".to_vec(), b"beta".to_vec()]).unwrap();
        let data = b"..alpha....beta..".to_vec();
        let hits = scanner.scan_with_patterns(&data, 0);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], (2, b"alpha".to_vec()));
        assert_eq!(hits[1], (11, b"beta".to_vec()));
    }

    #[test]
    fn scan_layer_walks_the_whole_layer() {
        let layers = LayerContainer::new();
        let mut data = vec![0u8; 0x2000];
        data[0x1500..0x1504].copy_from_slice(b"FIND");
        let layer = BufferLayer::new("base", data);

        let scanner = BytesScanner::new(b"FIND".to_vec());
        let mut hits = Vec::new();
        scan_layer(&layer, &layers, &scanner, None, |offset| hits.push(offset)).unwrap();
        assert_eq!(hits, vec![0x1500]);
    }

    /// Two runs that sit next to each other in this layer but come from
    /// places far apart in the one beneath it.
    ///
    /// The second run's bytes are stored before the first's, so a read that
    /// forgot to convert the offset would come back with the wrong half and
    /// the needle planted in each run would be reported at the wrong place.
    fn two_run_layer(prepare: impl Fn(&mut [u8])) -> (LayerContainer, Arc<dyn DataLayer>) {
        let mut data = vec![0u8; 0x3000];
        prepare(&mut data);
        let layers = LayerContainer::new();
        layers.add(Arc::new(BufferLayer::new("base", data)));
        let segments = vec![
            // 0x0000..0x1000 of this layer is 0x2000..0x3000 of the base
            Segment::linear(0x0000, 0x2000, 0x1000),
            // 0x1000..0x2000 of this layer is 0x0000..0x1000 of the base
            Segment::linear(0x1000, 0x0000, 0x1000),
        ];
        let layer = SegmentedLayer::new("over", "base", segments, HashMap::new()).unwrap();
        (layers, Arc::new(layer))
    }

    #[test]
    fn a_hit_in_each_run_is_reported_where_it_sits_in_the_scanned_layer() {
        // Planted at 0x2010 and 0x0020 of the base, which are 0x0010 and
        // 0x1020 of the layer being scanned.
        let (layers, layer) = two_run_layer(|data| {
            data[0x2010..0x2014].copy_from_slice(b"FIND");
            data[0x0020..0x0024].copy_from_slice(b"FIND");
        });

        let scanner = BytesScanner::new(b"FIND".to_vec());
        let mut hits = Vec::new();
        scan_layer(layer.as_ref(), &layers, &scanner, None, |offset| {
            hits.push(offset)
        })
        .unwrap();
        hits.sort_unstable();
        assert_eq!(hits, vec![0x0010, 0x1020]);
    }

    #[test]
    fn a_hit_lying_across_two_runs_is_not_reported() {
        // Upstream hands the scanner one run at a time and never reads across
        // the boundary between two of them, so a needle that begins in one and
        // ends in the next is not found. Joining the runs would find it, and
        // would report matches this port's reference implementation does not.
        let (layers, layer) = two_run_layer(|data| {
            // The last two bytes of the base's 0x2000..0x3000 run, which is
            // the end of the first run of the layer above.
            data[0x2ffe..0x3000].copy_from_slice(b"FI");
            // The first two bytes of the base's 0x0000..0x1000 run, which
            // carries straight on from it in the layer above.
            data[0x0000..0x0002].copy_from_slice(b"ND");
        });

        let scanner = BytesScanner::new(b"FIND".to_vec());
        let mut hits = Vec::new();
        scan_layer(layer.as_ref(), &layers, &scanner, None, |offset| {
            hits.push(offset)
        })
        .unwrap();
        assert!(
            hits.is_empty(),
            "a needle split across two runs must not be found, got {hits:?}"
        );
    }
}

