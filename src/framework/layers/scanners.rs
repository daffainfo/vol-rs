//! Scanners: cheap predicates applied to chunks of a layer to locate candidate
//! offsets, which the caller then validates properly.
//!
//! Scanners see the layer's data in ascending offset order, in chunks of at
//! most `chunk_size + overlap`. The overlap is re-presented at the start of the
//! next chunk so a match straddling a boundary is still found. A scanner must
//! therefore not report anything that begins beyond `chunk_size`, or the match
//! would be reported twice.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use regex::bytes::Regex;

use crate::constants::{SCAN_CHUNK_SIZE, SCAN_OVERLAP};
use crate::error::Result;
use crate::framework::layers::{coalesce_sections, DataLayer, LayerContainer};

/// Applied to successive chunks of a layer, yielding absolute offsets.
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

/// Finds matches of a regular expression over raw bytes.
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

/// Runs `scanner` across `sections` of `layer`, invoking `on_hit` for every
/// offset found.
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
    // A scan only ever looks at memory the layer actually maps: asking for a
    // region the layer has nothing behind reads zeroes at the cost of a page
    // walk per page, and a process's reserved-but-unused ranges are vast.
    let mapped = layer.mapped_regions(layers);
    let sections = match sections {
        Some(requested) => intersect_sections(requested, &mapped),
        None => mapped.clone(),
    };
    let sections = coalesce_sections(&sections, layer.minimum_address(), layer.maximum_address());

    let chunk_size = scanner.chunk_size();
    let overlap = scanner.overlap();

    // The chunks are laid out first so the scan itself is a plain map over
    // them, which is what lets it run on every core at once. Each chunk knows
    // whether it is the last of its section, since only that one may report a
    // hit that starts inside the overlap.
    let mut chunks: Vec<Chunk> = Vec::new();
    for (section_start, section_length) in sections {
        let end = section_start + section_length;
        let mut offset = section_start;
        while offset < end {
            let want = ((chunk_size + overlap) as u64).min(end - offset) as usize;
            chunks.push(Chunk {
                offset,
                want,
                last: offset + chunk_size as u64 >= end,
            });
            // Advance by the fresh portion only, so the overlap is re-read.
            offset += chunk_size as u64;
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
                // seen. Reporting hits that start inside it would report them
                // twice, once per chunk. The final chunk has no successor, so
                // it reports all.
                let fresh_end = chunk.offset + chunk_size as u64;
                let keep_overlap = scanner.reports_overlap();
                let mut hits = Vec::new();

                // Padding keeps a chunk that straddles a hole usable. The
                // zeroes it introduces will simply not match. The bytes are
                // borrowed where the layer can lend them, which for a scan of
                // a whole image saves copying every byte of it.
                let examined = layer.with_bytes(
                    layers,
                    chunk.offset,
                    chunk.want,
                    true,
                    &mut |data: &[u8]| {
                        hits = scanner
                            .scan(data, chunk.offset)
                            .into_iter()
                            .filter(|hit| chunk.last || keep_overlap || *hit < fresh_end)
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

/// One unit of scanning work: where to read, how much, and whether anything
/// follows it in the same section.
struct Chunk {
    offset: u64,
    want: usize,
    last: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;

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
}

/// The parts of the wanted regions that the layer actually maps.
fn intersect_sections(wanted: &[(u64, u64)], mapped: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for (start, length) in wanted {
        let end = start.saturating_add(*length);
        for (mapped_start, mapped_length) in mapped {
            let mapped_end = mapped_start.saturating_add(*mapped_length);
            let overlap_start = (*start).max(*mapped_start);
            let overlap_end = end.min(mapped_end);
            if overlap_start < overlap_end {
                result.push((overlap_start, overlap_end - overlap_start));
            }
        }
    }
    result
}
