//! List the ISF symbol files available to this installation.
//!
//! This describes the tool's own installation rather than any memory image, so
//! what it reports is necessarily about *this* port: the files on its symbol
//! path and what each of them holds. The columns are the ones the reference
//! implementation declares, so anything reading the table by name still works.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::{Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct IsfInfo;

impl Plugin for IsfInfo {
    fn name(&self) -> &'static str {
        "isfinfo.IsfInfo"
    }

    fn description(&self) -> &'static str {
        "Determines information about the currently available ISF files, or a specific one"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new(
                "filter",
                "String that must be present in the file URI to display the ISF",
                RequirementKind::List(Box::new(RequirementKind::String)),
            ),
            Requirement::new(
                "isf",
                "Specific ISF file to process",
                RequirementKind::String,
            ),
            Requirement::new(
                "validate",
                "Validate against schema if possible",
                RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "live",
                "Traverse all files, rather than use the cache",
                RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("URI"),
            Column::string("Valid"),
            Column::uint("Number of base_types"),
            Column::uint("Number of types"),
            Column::uint("Number of symbols"),
            Column::uint("Number of enums"),
            Column::string("Identifying information"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let finder = context.symbol_finder();
        let filters = config
            .get("filter")
            .and_then(|value| value.as_list().map(<[_]>::to_vec))
            .unwrap_or_default()
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect::<Vec<String>>();
        let mut grid = TreeGrid::new(self.columns());

        // Every symbol file under every directory searched, whichever
        // operating system it describes.
        let mut listed: Vec<(String, crate::framework::symbols::intermed::SymbolLocation)> =
            Vec::new();
        if let Some(single) = config.get_string("isf") {
            if let Some(found) = finder.list("").into_iter().find(|(name, location)| {
                *name == single || location.display() == single
            }) {
                listed.push(found);
            }
        } else {
            for sub_path in ["windows", "linux", "mac", "generic", "generic/vmcs"] {
                listed.extend(finder.list(sub_path));
            }
        }

        for (_, location) in listed {
            let uri = location.url();
            if !filters.is_empty() && !filters.iter().any(|filter| uri.contains(filter.as_str())) {
                continue;
            }

            // A file that cannot be read is still listed, with nothing to say
            // about what is in it.
            let Ok(isf) = location.load() else {
                grid.push(
                    0,
                    vec![
                        Value::string(uri),
                        Value::string("Unknown"),
                        Value::unreadable(),
                        Value::unreadable(),
                        Value::unreadable(),
                        Value::unreadable(),
                        Value::unreadable(),
                    ],
                )?;
                continue;
            };

            // What the file says it describes: the kernel banner for a Linux
            // or Mac file, the database it was converted from for a Windows
            // one.
            let identity = match (&isf.metadata.pdb_database, &isf.metadata.pdb_guid) {
                (Some(database), Some(guid)) => Value::string(format!(
                    "{database}|{guid}|{}",
                    isf.metadata.pdb_age.unwrap_or(0)
                )),
                _ => isf
                    .symbols
                    .get("linux_banner")
                    .or_else(|| isf.symbols.get("version"))
                    .and_then(|symbol| symbol.constant_data.clone())
                    .map(|data| Value::string(String::from_utf8_lossy(&data).to_string()))
                    .unwrap_or_else(Value::not_available),
            };

            grid.push(
                0,
                vec![
                    Value::string(uri),
                    // Validating against the schema is not implemented, and
                    // upstream says the same when it is not asked to.
                    Value::string("Unknown"),
                    Value::uint(isf.base_types.len() as u64),
                    Value::uint(isf.user_types.len() as u64),
                    Value::uint(isf.symbols.len() as u64),
                    Value::uint(isf.enums.len() as u64),
                    identity,
                ],
            )?;
        }
        Ok(grid)
    }
}
