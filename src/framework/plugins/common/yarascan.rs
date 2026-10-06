//! Both the Windows and Linux scanning plugins take the same options (a rule
//! file, an inline rule, or a bare string to match), so the compilation and
//! matching live here and each plugin supplies only the regions to scan.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::error::{Result, VolatilityError};
use crate::framework::context::Configuration;
use crate::framework::plugins::{Requirement, RequirementKind};

/// One pattern match within a scanned region.
pub struct Match {
    /// The rule that matched.
    pub rule: String,
    /// The pattern within the rule, which YARA calls a string identifier.
    pub component: String,
    /// Offset of the match within the region scanned.
    pub offset: usize,
    /// The bytes that matched.
    pub data: Vec<u8>,
}

/// The options every YARA-scanning plugin accepts.
pub fn requirements() -> Vec<Requirement> {
    vec![
        Requirement::new(
            "insensitive",
            "Makes the search case insensitive",
            RequirementKind::Bool,
        )
        .with_default(crate::framework::context::ConfigValue::Bool(false)),
        Requirement::new(
            "wide",
            "Match wide (unicode) strings",
            RequirementKind::Bool,
        )
        .with_default(crate::framework::context::ConfigValue::Bool(false)),
        Requirement::new(
            "yara_string",
            "Yara rules (as a string)",
            RequirementKind::String,
        ),
        Requirement::new(
            "yara_file",
            "Yara rules (as a file)",
            RequirementKind::String,
        ),
        Requirement::new(
            "yara_compiled_file",
            "Yara compiled rules (as a file)",
            RequirementKind::String,
        ),
        Requirement::new(
            "max_size",
            "Set the maximum size (default is 1GB)",
            RequirementKind::Int,
        )
        .with_default(crate::framework::context::ConfigValue::Int(0x4000_0000)),
    ]
}

/// Compiled rules, ready to scan with.
pub struct Rules {
    /// Held for as long as the process runs so that each thread can keep a
    /// scanner borrowing it. One rule set is built per run of a plugin, so
    /// nothing accumulates.
    rules: &'static yara_x::Rules,
}

impl Rules {
    /// Build the rules from whichever option the caller supplied.
    pub fn from_config(config: &Configuration) -> Result<Self> {
        // The options are considered in the order the reference implementation
        // considers them, so supplying more than one is not ambiguous.
        let source = if let Some(text) = config.get_string("yara_string") {
            wrap_string(
                &text,
                config.get_bool("insensitive").unwrap_or(false),
                config.get_bool("wide").unwrap_or(false),
            )
        } else if let Some(path) = config.get_string("yara_file") {
            std::fs::read_to_string(&path).map_err(|e| {
                VolatilityError::Io(format!("Could not read YARA rules from {path}: {e}"))
            })?
        } else if let Some(path) = config.get_string("yara_compiled_file") {
            std::fs::read_to_string(&path).map_err(|e| {
                VolatilityError::Io(format!("Could not read YARA rules from {path}: {e}"))
            })?
        } else {
            return Err(VolatilityError::Other(
                "No yara rules, nor yara rules file were specified".to_string(),
            ));
        };

        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source.as_str())
            .map_err(|e| VolatilityError::Other(format!("Could not compile YARA rules: {e}")))?;

        Ok(Self {
            rules: Box::leak(Box::new(compiler.build())),
        })
    }

    /// Scan one region, returning every pattern match within it.
    ///
    /// A virtual address space is mapped a page at a time and the pieces are
    /// scanned one by one, so this is called hundreds of thousands of times
    /// for one image. Building a scanner costs about as much as scanning a
    /// whole page, so each thread keeps the one it built and hands it the next
    /// region rather than building another. Which bytes are examined does not
    /// change, only how often a scanner is constructed.
    pub fn scan(&self, data: &[u8]) -> Vec<Match> {
        thread_local! {
            static SCANNERS: std::cell::RefCell<
                std::collections::HashMap<usize, yara_x::Scanner<'static>>,
            > = std::cell::RefCell::new(std::collections::HashMap::new());
        }

        // Keyed by the rules themselves, so a run that compiles more than one
        // set keeps a scanner for each rather than rebuilding on every call.
        let key = self.rules as *const yara_x::Rules as usize;
        SCANNERS.with(|held| {
            let mut held = held.borrow_mut();
            let scanner = held
                .entry(key)
                .or_insert_with(|| yara_x::Scanner::new(self.rules));

            let Ok(results) = scanner.scan(data) else {
                // A region that cannot be scanned yields nothing rather than
                // aborting the walk over the remaining regions.
                return Vec::new();
            };

            let mut matches = Vec::new();
            for rule in results.matching_rules() {
                for pattern in rule.patterns() {
                    for found in pattern.matches() {
                        let range = found.range();
                        matches.push(Match {
                            rule: rule.identifier().to_string(),
                            component: pattern.identifier().to_string(),
                            offset: range.start,
                            data: found.data().to_vec(),
                        });
                    }
                }
            }
            matches
        })
    }
}

/// Wrap what the caller gave into the one-string rule the reference
/// implementation builds.
///
/// A value that already opens with a brace or a slash is a byte sequence or a
/// regular expression and is used as it stands. Anything else is a plain
/// string and is quoted.
fn wrap_string(text: &str, insensitive: bool, wide: bool) -> String {
    let mut pattern = match text.chars().next() {
        Some('{') | Some('/') => text.to_string(),
        _ => format!("\"{text}\""),
    };
    if insensitive {
        pattern.push_str(" nocase");
    }
    if wide {
        pattern.push_str(" wide ascii");
    }
    format!("rule r1 {{strings: $a = {pattern} condition: $a}}")
}

/// A scanner that applies compiled rules to each chunk of a layer.
///
/// The reference implementation's scanner does not hold back matches that fall
/// in the region a chunk repeats, so anything found there is reported once per
/// chunk that sees it.
pub struct YaraScanner<'rules> {
    rules: &'rules Rules,
}

impl<'rules> YaraScanner<'rules> {
    pub fn new(rules: &'rules Rules) -> Self {
        Self { rules }
    }
}

impl crate::framework::layers::scanners::Scanner for YaraScanner<'_> {
    fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        self.rules
            .scan(data)
            .into_iter()
            .map(|found| data_offset + found.offset as u64)
            .collect()
    }

    fn reports_overlap(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_string_compiles_and_matches() {
        let config = Configuration::new();
        config.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("secret".to_string()),
        );

        let rules = Rules::from_config(&config).unwrap();
        let ascii = rules.scan(b"a secret value");
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].rule, "r1");
        assert_eq!(ascii[0].component, "$a");
        assert_eq!(ascii[0].data, b"secret");
    }

    #[test]
    fn asking_for_wide_matches_the_wide_encoding_too() {
        let config = Configuration::new();
        config.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("secret".to_string()),
        );
        config.set("wide", crate::framework::context::ConfigValue::Bool(true));

        let rules = Rules::from_config(&config).unwrap();
        let wide: Vec<u8> = "secret".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(rules.scan(&wide).len(), 1);
    }

    #[test]
    fn a_byte_sequence_is_taken_as_one_rather_than_quoted() {
        let config = Configuration::new();
        config.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("{ DE AD BE EF }".to_string()),
        );

        let rules = Rules::from_config(&config).unwrap();
        let found = rules.scan(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, 1);
    }

    #[test]
    fn no_rules_is_an_error_rather_than_an_empty_scan() {
        let config = Configuration::new();
        assert!(Rules::from_config(&config).is_err());
    }

    /// A scanner is kept per thread and handed one region after another, so a
    /// scan must not be affected by what the scanner was shown before it.
    #[test]
    fn repeated_scans_do_not_affect_one_another() {
        let config = Configuration::new();
        config.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("secret".to_string()),
        );
        let rules = Rules::from_config(&config).unwrap();

        // A region that matches, then one that does not, then the first again.
        let hit = b"a secret value";
        let miss = b"nothing of interest here";
        for _ in 0..4 {
            let first = rules.scan(hit);
            assert_eq!(first.len(), 1, "a match must be found every time");
            assert_eq!(first[0].offset, 2);
            assert_eq!(first[0].data, b"secret");

            assert!(
                rules.scan(miss).is_empty(),
                "a region with nothing in it must report nothing, whatever came before"
            );
        }
    }

    /// Two rule sets live at once, and each has to keep its own scanner.
    #[test]
    fn two_rule_sets_do_not_share_a_scanner() {
        let first = Configuration::new();
        first.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("alpha".to_string()),
        );
        let second = Configuration::new();
        second.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("beta".to_string()),
        );

        let alpha = Rules::from_config(&first).unwrap();
        let beta = Rules::from_config(&second).unwrap();

        let data = b"..alpha....beta..";
        for _ in 0..3 {
            let a = alpha.scan(data);
            let b = beta.scan(data);
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].data, b"alpha");
            assert_eq!(b.len(), 1);
            assert_eq!(b[0].data, b"beta");
        }
    }

    /// The same rules scanned from several threads at once, which is how a
    /// layer scan uses them.
    #[test]
    fn scanning_from_several_threads_gives_the_same_answer() {
        let config = Configuration::new();
        config.set(
            "yara_string",
            crate::framework::context::ConfigValue::Str("secret".to_string()),
        );
        let rules = std::sync::Arc::new(Rules::from_config(&config).unwrap());

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let rules = rules.clone();
                std::thread::spawn(move || {
                    (0..50)
                        .map(|_| rules.scan(b"a secret value").len())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.join().unwrap().iter().all(|found| *found == 1));
        }
    }
}
