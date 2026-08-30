//! Command line parsing.
//!
//! Plugin options are not known until the plugin is chosen, so they are taken
//! as free-form `--name value` pairs after the plugin name and validated
//! against that plugin's declared requirements.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::path::PathBuf;

use crate::error::{Result, VolatilityError};
use crate::framework::context::ConfigValue;
use crate::framework::plugins::{Plugin, RequirementKind};

/// How output should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Quick,
    None,
    Csv,
    Pretty,
    Json,
    JsonLines,
    /// Formats the reference implementation offers only when its optional
    /// table library is installed.
    Arrow,
    Parquet,
}

impl OutputFormat {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "quick" => OutputFormat::Quick,
            "none" => OutputFormat::None,
            "csv" => OutputFormat::Csv,
            "pretty" => OutputFormat::Pretty,
            "json" => OutputFormat::Json,
            "jsonl" => OutputFormat::JsonLines,
            "arrow" => OutputFormat::Arrow,
            "parquet" => OutputFormat::Parquet,
            _ => return None,
        })
    }

    /// Whether the format is meant to be read by another program, in which case
    /// the banner is kept out of the output stream.
    pub fn structured(&self) -> bool {
        !matches!(self, OutputFormat::Quick | OutputFormat::None | OutputFormat::Pretty)
    }
}

/// What the user asked for.
#[derive(Debug, Clone)]
pub struct Arguments {
    pub image: Option<String>,
    pub plugin: Option<String>,
    pub plugin_args: Vec<(String, String)>,
    /// Directories to search for symbol files, in the order given.
    pub symbol_paths: Vec<PathBuf>,
    /// Directories to search for plugins, which this port has no use for but
    /// still accepts.
    pub plugin_dirs: Vec<PathBuf>,
    pub format: OutputFormat,
    pub verbosity: u8,
    pub list_plugins: bool,
    pub show_help: bool,
    pub show_version: bool,
    /// A configuration file to read the plugin's settings from.
    pub config: Option<PathBuf>,
    /// Settings given directly on the command line, as `path=value`.
    pub extend: Vec<String>,
    /// Where to write a configuration file, if asked for.
    pub save_config: Option<PathBuf>,
    pub write_config: bool,
    /// Where files the plugins produce are written.
    pub output_dir: PathBuf,
    /// A file to copy the log to.
    pub log: Option<PathBuf>,
    pub quiet: bool,
    pub clear_cache: bool,
    pub cache_path: Option<PathBuf>,
    pub offline: bool,
    pub remote_isf_url: Option<String>,
    pub parallelism: Option<String>,
    /// Rows to keep or drop, as `[+-]column,pattern[!]`.
    pub filters: Vec<String>,
    /// Column name prefixes to leave out of the output.
    pub hide_columns: Option<Vec<String>>,
    /// The image to open, as a URL rather than a path.
    pub single_location: Option<String>,
    pub stackers: Vec<String>,
    pub single_swap_locations: Vec<String>,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            image: None,
            plugin: None,
            plugin_args: Vec::new(),
            symbol_paths: Vec::new(),
            plugin_dirs: Vec::new(),
            format: OutputFormat::Quick,
            verbosity: 0,
            list_plugins: false,
            show_help: false,
            show_version: false,
            config: None,
            extend: Vec::new(),
            save_config: None,
            write_config: false,
            output_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            log: None,
            quiet: false,
            clear_cache: false,
            cache_path: None,
            offline: false,
            remote_isf_url: None,
            parallelism: None,
            filters: Vec::new(),
            hide_columns: None,
            single_location: None,
            stackers: Vec::new(),
            single_swap_locations: Vec::new(),
        }
    }
}

/// Parse the command line.
///
/// Framework options come before the plugin name. Everything after it belongs
/// to the plugin.
pub fn parse(argv: &[String]) -> Result<Arguments> {
    parse_with(argv, |_| false)
}

/// The same, told which names are plugins.
///
/// An option that takes any number of values would otherwise swallow the plugin
/// name that follows them.
pub fn parse_with(argv: &[String], is_plugin: impl Fn(&str) -> bool) -> Result<Arguments> {
    let mut args = Arguments::default();
    let mut index = 0;

    // Framework options.
    while index < argv.len() {
        let argument = &argv[index];
        if !argument.starts_with('-') {
            break;
        }

        // `--flag=value` must match on the flag alone. The value is taken off
        // the original argument afterwards.
        let flag = match argument.split_once('=') {
            Some((flag, _)) => flag,
            None => argument.as_str(),
        };

        match flag {
            "-h" | "--help" => {
                args.show_help = true;
                index += 1;
            }
            "-V" | "--version" => {
                args.show_version = true;
                index += 1;
            }
            "--list-plugins" => {
                args.list_plugins = true;
                index += 1;
            }
            "-f" | "--file" => {
                args.image = Some(take_value(argv, &mut index, argument)?);
            }
            "-s" | "--symbol-dirs" => {
                // Several directories are given at once, separated the way the
                // reference implementation separates them.
                let value = take_value(argv, &mut index, argument)?;
                args.symbol_paths
                    .extend(value.split(';').filter(|part| !part.is_empty()).map(PathBuf::from));
            }
            "-p" | "--plugin-dirs" => {
                let value = take_value(argv, &mut index, argument)?;
                args.plugin_dirs
                    .extend(value.split(';').filter(|part| !part.is_empty()).map(PathBuf::from));
            }
            "-r" | "--renderer" => {
                let value = take_value(argv, &mut index, argument)?;
                args.format = OutputFormat::parse(&value).ok_or_else(|| {
                    VolatilityError::Other(format!(
                        "argument -r/--renderer: invalid choice: '{value}' (choose from \
                         quick, none, csv, pretty, json, jsonl, arrow, parquet)"
                    ))
                })?;
            }
            "-q" | "--quiet" => {
                args.quiet = true;
                index += 1;
            }
            "-c" | "--config" => {
                args.config = Some(PathBuf::from(take_value(argv, &mut index, argument)?));
            }
            "-e" | "--extend" => {
                let value = take_value(argv, &mut index, argument)?;
                args.extend.push(value);
            }
            "-l" | "--log" => {
                args.log = Some(PathBuf::from(take_value(argv, &mut index, argument)?));
            }
            "-o" | "--output-dir" => {
                args.output_dir = PathBuf::from(take_value(argv, &mut index, argument)?);
            }
            "--write-config" => {
                args.write_config = true;
                index += 1;
            }
            "--save-config" => {
                args.save_config = Some(PathBuf::from(take_value(argv, &mut index, argument)?));
            }
            "--clear-cache" => {
                args.clear_cache = true;
                index += 1;
            }
            "--cache-path" => {
                args.cache_path = Some(PathBuf::from(take_value(argv, &mut index, argument)?));
            }
            "--offline" => {
                args.offline = true;
                index += 1;
            }
            "-u" | "--remote-isf-url" => {
                args.remote_isf_url = Some(take_value(argv, &mut index, argument)?);
            }
            "--parallelism" => {
                // The value is optional: without one, parallelism is enabled.
                if argument.contains('=') {
                    args.parallelism = Some(take_value(argv, &mut index, argument)?);
                } else if index + 1 < argv.len() && !argv[index + 1].starts_with('-') {
                    args.parallelism = Some(argv[index + 1].clone());
                    index += 2;
                } else {
                    args.parallelism = Some("processes".to_string());
                    index += 1;
                }
            }
            "--filters" => {
                let value = take_value(argv, &mut index, argument)?;
                args.filters.push(value);
            }
            "--hide-columns" => {
                // Takes any number of values, including none at all.
                let mut names = args.hide_columns.take().unwrap_or_default();
                if argument.contains('=') {
                    names.push(take_value(argv, &mut index, argument)?);
                } else {
                    index += 1;
                    while index < argv.len()
                        && !argv[index].starts_with('-')
                        && !is_plugin(&argv[index])
                    {
                        names.push(argv[index].clone());
                        index += 1;
                    }
                }
                args.hide_columns = Some(names);
            }
            "--single-location" => {
                args.single_location = Some(take_value(argv, &mut index, argument)?);
            }
            "--stackers" => {
                index += 1;
                while index < argv.len()
                    && !argv[index].starts_with('-')
                    && !is_plugin(&argv[index])
                {
                    args.stackers.push(argv[index].clone());
                    index += 1;
                }
            }
            "--single-swap-locations" => {
                index += 1;
                while index < argv.len()
                    && !argv[index].starts_with('-')
                    && !is_plugin(&argv[index])
                {
                    args.single_swap_locations.push(argv[index].clone());
                    index += 1;
                }
            }
            other if other.starts_with("-v") && other[1..].chars().all(|c| c == 'v') => {
                // -v, -vv, -vvv each add a level.
                args.verbosity += (other.len() - 1) as u8;
                index += 1;
            }
            other => {
                return Err(VolatilityError::Other(format!(
                    "unrecognized arguments: {other}"
                )))
            }
        }
    }

    // The plugin name, then its own options.
    if index < argv.len() {
        args.plugin = Some(argv[index].clone());
        index += 1;
    }

    while index < argv.len() {
        let argument = &argv[index];
        if argument == "--help" {
            args.show_help = true;
            index += 1;
        } else if let Some(name) = argument.strip_prefix("--") {
            // `--name=value` and `--name value` are both accepted. A flag with
            // no value becomes "true".
            if let Some((key, value)) = name.split_once('=') {
                args.plugin_args.push((key.to_string(), value.to_string()));
                index += 1;
            } else if index + 1 < argv.len() && !argv[index + 1].starts_with("--") {
                // An option may be given several values, as `--pid 4 8 12`.
                // Each becomes its own entry and the requirement's kind
                // decides whether repetition is meaningful.
                args.plugin_args
                    .push((name.to_string(), argv[index + 1].clone()));
                index += 2;
                while index < argv.len() && !argv[index].starts_with('-') {
                    args.plugin_args
                        .push((name.to_string(), argv[index].clone()));
                    index += 1;
                }
            } else {
                args.plugin_args.push((name.to_string(), "true".to_string()));
                index += 1;
            }
        } else if argument.starts_with('-') {
            // Framework flags are still accepted after the plugin name, since
            // that is where users naturally reach for `-v`.
            match argument.as_str() {
                "-q" => args.format = OutputFormat::Quick,
                "-h" => args.show_help = true,
                other if other.starts_with("-v") && other[1..].chars().all(|c| c == 'v') => {
                    args.verbosity += (other.len() - 1) as u8;
                }
                other => {
                    return Err(VolatilityError::Other(format!(
                        "Unknown option '{other}'. Plugin options use a double dash, as in --pid."
                    )))
                }
            }
            index += 1;
        } else {
            return Err(VolatilityError::Other(format!(
                "Unexpected argument '{argument}'"
            )));
        }
    }

    Ok(args)
}

fn take_value(argv: &[String], index: &mut usize, flag: &str) -> Result<String> {
    // Support both `--flag value` and `--flag=value`.
    if let Some((_, inline)) = argv[*index].split_once('=') {
        *index += 1;
        return Ok(inline.to_string());
    }
    // A value that looks like an option is not taken as one: it has to be
    // given with an equals sign instead.
    if argv
        .get(*index + 1)
        .is_some_and(|value| value.starts_with('-') && value.len() > 1)
    {
        return Err(VolatilityError::Other(format!(
            "argument {flag}: expected one argument"
        )));
    }
    if *index + 1 >= argv.len() {
        return Err(VolatilityError::Other(format!(
            "Option '{flag}' needs a value"
        )));
    }
    let value = argv[*index + 1].clone();
    *index += 2;
    Ok(value)
}

/// Convert the plugin's raw string arguments into typed configuration values,
/// checking them against the plugin's declared requirements.
pub fn build_plugin_config(
    plugin: &dyn Plugin,
    raw: &[(String, String)],
) -> Result<Vec<(String, ConfigValue)>> {
    let requirements = plugin.requirements();
    let mut resolved: Vec<(String, ConfigValue)> = Vec::new();

    for (name, value) in raw {
        // Some options are named with dashes and some with underscores, and a
        // command line may use either, so the two are compared alike.
        let normalised = name.replace('-', "_");
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.name.replace('-', "_") == normalised);

        let Some(requirement) = requirement else {
            return Err(VolatilityError::Other(format!(
                "Plugin '{}' does not accept option '--{name}'. Accepted: {}",
                plugin.name(),
                requirements
                    .iter()
                    .map(|r| format!("--{}", r.name))
                    .collect::<Vec<String>>()
                    .join(", ")
            )));
        };

        // Stored under the name the plugin declared, whichever spelling the
        // command line used.
        let normalised = requirement.name.clone();
        let parsed = parse_value(&requirement.kind, value, name)?;
        // Repeating an option extends a list. Anything else takes the last
        // value given, as a command line conventionally does.
        match resolved.iter_mut().find(|(existing, _)| *existing == normalised) {
            Some((_, ConfigValue::List(existing))) => {
                if let ConfigValue::List(more) = parsed {
                    existing.extend(more);
                }
            }
            Some((_, existing)) => *existing = parsed,
            None => resolved.push((normalised, parsed)),
        }
    }

    // Apply defaults, and report anything mandatory that is still missing.
    let mut missing = Vec::new();
    for requirement in &requirements {
        if resolved.iter().any(|(name, _)| *name == requirement.name) {
            continue;
        }
        if let Some(default) = &requirement.default {
            resolved.push((requirement.name.clone(), default.clone()));
        } else if !requirement.optional
            && !matches!(
                requirement.kind,
                // These are filled in by automagic, not by the user.
                RequirementKind::Kernel | RequirementKind::TranslationLayer
            )
        {
            missing.push(requirement.name.clone());
        }
    }

    if !missing.is_empty() {
        return Err(VolatilityError::Unsatisfied(missing));
    }
    Ok(resolved)
}

fn parse_value(kind: &RequirementKind, value: &str, name: &str) -> Result<ConfigValue> {
    Ok(match kind {
        RequirementKind::Int => {
            let parsed = parse_integer(value).ok_or_else(|| {
                VolatilityError::Other(format!("Option '--{name}' needs an integer, got '{value}'"))
            })?;
            ConfigValue::Int(parsed)
        }
        RequirementKind::Bool => ConfigValue::Bool(matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "1"
        )),
        RequirementKind::Bytes => ConfigValue::Bytes(
            hex::decode(value).map_err(|_| {
                VolatilityError::Other(format!("Option '--{name}' needs hex bytes"))
            })?,
        ),
        RequirementKind::List(inner) => ConfigValue::List(
            value
                .split(',')
                .filter(|entry| !entry.is_empty())
                .map(|entry| parse_value(inner, entry.trim(), name))
                .collect::<Result<Vec<ConfigValue>>>()?,
        ),
        RequirementKind::Choice(choices) => {
            if !choices.iter().any(|choice| choice == value) {
                return Err(VolatilityError::Other(format!(
                    "Option '--{name}' must be one of: {}",
                    choices.join(", ")
                )));
            }
            ConfigValue::Str(value.to_string())
        }
        _ => ConfigValue::Str(value.to_string()),
    })
}

/// Parse an integer, accepting decimal and `0x`-prefixed hexadecimal.
fn parse_integer(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn separates_framework_options_from_plugin_options() {
        let parsed = parse(&argv(&[
            "-f", "memory.raw", "-vv", "windows.pslist.PsList", "--pid", "4,8",
        ]))
        .unwrap();

        assert_eq!(parsed.image.as_deref(), Some("memory.raw"));
        assert_eq!(parsed.verbosity, 2);
        assert_eq!(parsed.plugin.as_deref(), Some("windows.pslist.PsList"));
        assert_eq!(parsed.plugin_args, vec![("pid".to_string(), "4,8".to_string())]);
    }

    #[test]
    fn accepts_equals_and_bare_flags() {
        let parsed = parse(&argv(&["-f=image.lime", "some.Plugin", "--dump", "--pid=7"]))
            .unwrap();
        assert_eq!(parsed.image.as_deref(), Some("image.lime"));
        assert_eq!(
            parsed.plugin_args,
            vec![
                ("dump".to_string(), "true".to_string()),
                ("pid".to_string(), "7".to_string())
            ]
        );
    }

    #[test]
    fn framework_flags_are_accepted_after_the_plugin_name() {
        let parsed = parse(&argv(&["-f", "image.raw", "banners.Banners", "-vv"])).unwrap();
        assert_eq!(parsed.verbosity, 2);
        assert!(parsed.plugin_args.is_empty());
    }

    #[test]
    fn integers_accept_hexadecimal() {
        assert_eq!(parse_integer("4096"), Some(4096));
        assert_eq!(parse_integer("0x1000"), Some(4096));
        assert_eq!(parse_integer("nonsense"), None);
    }

    #[test]
    fn unknown_plugin_options_are_rejected_with_a_hint() {
        struct Dummy;
        impl Plugin for Dummy {
            fn name(&self) -> &'static str {
                "test.Dummy"
            }
            fn description(&self) -> &'static str {
                "test"
            }
            fn requirements(&self) -> Vec<crate::framework::plugins::Requirement> {
                vec![crate::framework::plugins::Requirement::pid_filter("Filter on specific process IDs")]
            }
            fn columns(&self) -> Vec<crate::framework::renderers::Column> {
                Vec::new()
            }
            fn run(
                &self,
                _context: std::sync::Arc<crate::framework::context::Context>,
                _config: &crate::framework::context::Configuration,
            ) -> Result<crate::framework::renderers::TreeGrid> {
                unimplemented!()
            }
        }

        let error = build_plugin_config(&Dummy, &[("nope".to_string(), "1".to_string())])
            .unwrap_err();
        assert!(error.to_string().contains("--pid"));

        // Dashes in option names map onto underscores in requirement names.
        let ok = build_plugin_config(&Dummy, &[("pid".to_string(), "4,8".to_string())]).unwrap();
        assert_eq!(
            ok[0].1,
            ConfigValue::List(vec![ConfigValue::Int(4), ConfigValue::Int(8)])
        );
    }
}
