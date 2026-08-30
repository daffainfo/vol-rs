//! List the certificates the registry's certificate stores hold.
//!
//! Each store keeps one key per certificate, named after the certificate's
//! thumbprint, whose values carry the certificate itself and the name it is
//! displayed under. Reading them says which roots a machine trusts, which is
//! how a planted certificate is found.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{
    read_key, subkeys, values, RegistryKey, ValueType,
};

/// Where the stores sit, in the two hives that carry them.
const STORE_PATHS: &[&str] = &[
    "Microsoft\\SystemCertificates",
    "Software\\Microsoft\\SystemCertificates",
];

/// The property holding a certificate's display name.
const PROPERTY_NAME: u64 = 0x1_0000_000B;

/// The property holding the certificate itself.
const PROPERTY_CERTIFICATE: u64 = 0x1_0000_0020;

pub struct Certificates;

impl Plugin for Certificates {
    fn name(&self) -> &'static str {
        "windows.registry.certificates.Certificates"
    }

    fn description(&self) -> &'static str {
        "Lists the certificates in the registry's Certificate Store."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "dump",
                "Extract listed certificates",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Certificate path"),
            Column::string("Certificate section"),
            Column::string("Certificate ID"),
            Column::string("Certificate name"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let dump = config.get_bool("dump").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        for hive_object in super::list_hives(&context, &kernel)? {
            let hive_offset = hive_object.offset();
            let Ok(hive) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            let hive_name = hive.hive_name().unwrap_or("[NONAME]").to_string();

            for top_key in STORE_PATHS {
                let Some(node) = find_key(&context, &hive, &table, top_key) else {
                    continue;
                };
                // The path a row reports is the one the walk built, which
                // starts at the hive rather than at the store.
                let path = format!("{hive_name}\\{top_key}");
                let mut rows = Vec::new();
                collect(
                    &context,
                    &hive,
                    &table,
                    &node,
                    &path,
                    top_key,
                    hive_offset,
                    dump,
                    &mut rows,
                );
                for row in rows {
                    grid.push(0, row)?;
                }
            }
        }
        Ok(grid)
    }
}

/// Walk one store, reporting every certificate it holds.
///
/// A key's own subkeys are walked before its values, which is the order the
/// stores are laid out in and so the order the certificates are reported.
#[allow(clippy::too_many_arguments)]
fn collect(
    context: &Arc<Context>,
    hive: &Arc<RegistryHive>,
    table: &str,
    node: &RegistryKey,
    path: &str,
    top_key: &str,
    hive_offset: u64,
    dump: bool,
    rows: &mut Vec<Vec<Value>>,
) {
    for child in subkeys(context, hive, table, node).unwrap_or_default() {
        let Ok(name) = child.name() else { continue };
        collect(
            context,
            hive,
            table,
            &child,
            &format!("{path}\\{name}"),
            top_key,
            hive_offset,
            dump,
            rows,
        );
    }

    for value in values(context, hive, table, node).unwrap_or_default() {
        if value.value_type() != ValueType::Binary {
            continue;
        }
        let Ok(data) = value.data(hive) else { continue };
        let (name, certificate) = parse_properties(&data);

        // The store the certificate belongs to, and the thumbprint naming it,
        // are both read out of the path the walk arrived by.
        let Some(start) = path
            .to_lowercase()
            .find(&top_key.to_lowercase())
            .map(|at| at + top_key.len() + 1)
        else {
            continue;
        };
        let Some(section) = path
            .get(start..)
            .and_then(|rest| rest.find('\\').map(|end| &path[start..start + end]))
        else {
            continue;
        };
        let Some(hash) = path.rsplit('\\').next() else {
            continue;
        };

        if dump {
            if let Some(certificate) = &certificate {
                let file = format!("{hive_offset}-{section}-{hash}.crt");
                let _ = crate::framework::plugins::write_extracted(&file, certificate);
            }
        }

        rows.push(vec![
            Value::string(top_key),
            Value::string(section),
            Value::string(hash),
            name.map(Value::string).unwrap_or_else(Value::not_available),
        ]);
    }
}

/// Read the properties a certificate's value carries.
///
/// The value is a run of length-prefixed properties. Only the display name and
/// the certificate itself are of interest, and a value carrying neither is
/// reported as having neither.
fn parse_properties(data: &[u8]) -> (Option<String>, Option<Vec<u8>>) {
    let mut name = None;
    let mut certificate = None;
    let mut rest = data;

    while rest.len() > 12 {
        let kind = u64::from_le_bytes(rest[0..8].try_into().unwrap());
        let length = u32::from_le_bytes(rest[8..12].try_into().unwrap()) as usize;
        let end = (12 + length).min(rest.len());
        let value = &rest[12..end];
        match kind {
            PROPERTY_NAME => {
                name = Some(
                    crate::framework::symbols::windows::registry::decode_utf16(value)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            }
            PROPERTY_CERTIFICATE => certificate = Some(value.to_vec()),
            _ => {}
        }
        rest = &rest[end..];
    }
    (name, certificate)
}

/// Descend to a key by path, comparing names the way the registry does.
fn find_key(
    context: &Arc<Context>,
    hive: &Arc<RegistryHive>,
    table: &str,
    path: &str,
) -> Option<RegistryKey> {
    let mut node = read_key(context, hive, table, hive.root_cell_offset(), String::new()).ok()?;
    for component in path.trim_end_matches('\\').split('\\') {
        // Registry keys are not case sensitive.
        let child = subkeys(context, hive, table, &node)
            .ok()?
            .into_iter()
            .find(|child| {
                child
                    .name()
                    .map(|name| name.eq_ignore_ascii_case(component))
                    .unwrap_or(false)
            })?;
        node = child;
    }
    Some(node)
}
