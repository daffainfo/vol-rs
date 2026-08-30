//! The names Windows gives well-known security identifiers and privileges.
//!
//! These are data, not code: a table of fixed identifiers, a table of the
//! service accounts Windows installs, a handful of patterns for identifiers
//! that carry a domain in the middle, and the names of the privileges a token
//! can hold. They ship as one file so that the tool needs nothing installed
//! beside it to name what it finds.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

/// The file as it is written, which is also how the reference implementation
/// stores it.
#[derive(Deserialize)]
struct SidData {
    #[serde(rename = "well known")]
    well_known: HashMap<String, String>,
    #[serde(rename = "service sids")]
    service_sids: HashMap<String, String>,
    #[serde(rename = "sids re")]
    patterns: Vec<Vec<String>>,
    privileges: HashMap<String, Vec<String>>,
}

struct Tables {
    well_known: HashMap<String, String>,
    service_sids: HashMap<String, String>,
    patterns: Vec<(Regex, String)>,
    privileges: HashMap<u64, (String, String)>,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let data: SidData = serde_json::from_str(include_str!(
            "../../../../data/sids_and_privileges.json"
        ))
        .expect("the bundled identifier table is valid");

        Tables {
            well_known: data.well_known,
            service_sids: data.service_sids,
            patterns: data
                .patterns
                .into_iter()
                .filter_map(|entry| {
                    let mut entry = entry.into_iter();
                    let pattern = Regex::new(&entry.next()?).ok()?;
                    Some((pattern, entry.next()?))
                })
                .collect(),
            privileges: data
                .privileges
                .into_iter()
                .filter_map(|(number, names)| {
                    let mut names = names.into_iter();
                    Some((number.parse().ok()?, (names.next()?, names.next()?)))
                })
                .collect(),
        }
    })
}

/// The name of a fixed identifier, if it has one.
pub fn well_known(sid: &str) -> Option<&'static str> {
    tables().well_known.get(sid).map(String::as_str)
}

/// The name of a service account, if this is one.
pub fn service(sid: &str) -> Option<&'static str> {
    tables().service_sids.get(sid).map(String::as_str)
}

/// Whether a name is one the well-known service identifiers already covers.
pub fn is_known_service(name: &str) -> bool {
    tables()
        .service_sids
        .values()
        .any(|known| known == name)
}

/// The name for an identifier that carries a domain in the middle.
pub fn by_pattern(sid: &str) -> Option<&'static str> {
    tables()
        .patterns
        .iter()
        .find(|(pattern, _)| pattern.is_match(sid))
        .map(|(_, name)| name.as_str())
}

/// A privilege's name and description.
pub fn privilege(number: u64) -> Option<(&'static str, &'static str)> {
    tables()
        .privileges
        .get(&number)
        .map(|(name, description)| (name.as_str(), description.as_str()))
}
