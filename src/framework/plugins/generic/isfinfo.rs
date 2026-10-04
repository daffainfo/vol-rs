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

/// Determines information about the currently available ISF files, or a
/// specific one
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

        // Lists all the ISF files that can be found, under every directory
        // searched, whichever operating system each describes. By ending with
        // an extension (and therefore, not /), we should not return any
        // directories.
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

        // Without `--live` the reference implementation lists only what its
        // identifier cache knows about, which is the files that name the
        // kernel they describe. The helper files the tool ships, which name
        // nothing, appear only when every file is asked for.
        let live = config.get_bool("live").unwrap_or(false);

        for (_, location) in listed {
            let uri = location.url();
            if !filters.is_empty() && !filters.iter().any(|filter| uri.contains(filter.as_str())) {
                continue;
            }

            // Try to open the file, load it as JSON, read the data from it. A
            // file that cannot be read is still listed, with nothing to say
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
            // one. It is bytes upstream, and what reaches the table is its
            // representation rather than its contents.
            use crate::framework::objects::utility::python_bytes_repr;
            let identity = match (&isf.metadata.pdb_database, &isf.metadata.pdb_guid) {
                (Some(database), Some(guid)) => Some(python_bytes_repr(
                    format!("{database}|{guid}|{}", isf.metadata.pdb_age.unwrap_or(0)).as_bytes(),
                )),
                _ => isf
                    .symbols
                    .get("linux_banner")
                    .or_else(|| isf.symbols.get("version"))
                    .and_then(|symbol| symbol.constant_data.clone())
                    .map(|data| python_bytes_repr(&data)),
            };
            // A file that names nothing is not in the cache, so it is listed
            // only when every file was asked for.
            if identity.is_none() && !live {
                continue;
            }
            let identity = match identity {
                Some(identity) => Value::string(identity),
                None => Value::not_available(),
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
