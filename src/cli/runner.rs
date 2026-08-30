//! Wiring the pieces together: parse arguments, stack the image, run the
//! plugin, render the result.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::automagic;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::{OperatingSystem, PluginRegistry};
use crate::framework::renderers::csv::CsvRenderer;
use crate::framework::renderers::json::JsonRenderer;
use crate::framework::renderers::text::{PrettyTextRenderer, QuickTextRenderer};
use crate::framework::renderers::Renderer;
use crate::framework::symbols::intermed::SymbolFinder;

use super::args::{self, OutputFormat};

/// Entry point for the `vol` binary.
pub fn run_cli(argv: &[String]) -> Result<i32> {
    let registry = PluginRegistry::new();
    let arguments = args::parse_with(argv, |name| registry.get(name).is_some())?;
    configure_logging(arguments.verbosity, arguments.log.as_deref());

    // Where the caches live and whether the network may be used are settled
    // before anything reads them.
    if let Some(path) = &arguments.cache_path {
        crate::framework::cache::set(path.clone());
    }
    if arguments.clear_cache {
        crate::framework::cache::clear();
    }
    crate::framework::cache::set_offline(arguments.offline);
    if let Some(url) = &arguments.remote_isf_url {
        crate::framework::cache::set_remote_url(url.clone());
    }
    // Files plugins produce go where the caller asked for them.
    crate::framework::plugins::set_output_directory(arguments.output_dir.clone());

    // Work is spread across the machine's processors unless that was turned
    // off, in which case everything runs on one.
    if arguments.parallelism.as_deref() == Some("off") {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global()
            .ok();
    }

    if arguments.show_version {
        let (major, minor, patch) = crate::interface_version();
        // The port has its own version, and the framework version is the one
        // upstream stamps its output with.
        println!(
            "vol-rs {} (Volatility 3 framework {major}.{minor}.{patch})",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(0);
    }

    // `vol <plugin> --help` describes that plugin's own options.
    if arguments.show_help {
        if let Some(plugin) = arguments.plugin.as_deref().and_then(|name| registry.get(name)) {
            print!("{}", crate::cli::help::plugin_help(plugin.as_ref()));
            return Ok(0);
        }
    }

    if arguments.show_help {
        print!("{}", framework_help(&registry));
        return Ok(0);
    }

    if arguments.plugin.is_none() && !arguments.list_plugins {
        // The same complaint the reference implementation makes, with the same
        // usage block above it.
        eprint!("{}", crate::cli::help::framework_usage_block());
        eprintln!("vol: error: Please select a plugin to run (see 'vol --help' for options");
        return Ok(2);
    }

    if arguments.list_plugins {
        list_plugins(&registry, arguments.plugin.as_deref());
        return Ok(0);
    }

    let plugin_name = arguments.plugin.as_deref().unwrap();
    let plugin = registry.get(plugin_name).ok_or_else(|| {
        let suggestions = registry.search(plugin_name);
        if suggestions.is_empty() {
            VolatilityError::Other(format!(
                "No plugin named '{plugin_name}'. Use --list-plugins to see what is available."
            ))
        } else {
            VolatilityError::Other(format!(
                "No plugin named '{plugin_name}'. Did you mean: {}?",
                suggestions
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ))
        }
    })?;

    let context = Arc::new(Context::new());
    let config = Configuration::new();

    // A configuration file is read first, so anything given on the command line
    // takes precedence over it.
    if let Some(path) = &arguments.config {
        apply_configuration_file(plugin.as_ref(), &config, path)?;
    }

    // Plugin options first, so a failure here is reported before the expensive
    // work of stacking and scanning an image.
    for (name, value) in args::build_plugin_config(plugin.as_ref(), &arguments.plugin_args)? {
        config.set(name, value);
    }

    // Settings given directly on the command line, as `path=value`.
    for extension in &arguments.extend {
        let Some((path, value)) = extension.split_once('=') else {
            return Err(VolatilityError::Other(
                "Invalid extension (extensions must be of the format \"conf.path.value='value'\")"
                    .to_string(),
            ));
        };
        if let Some(value) = json_to_config(&serde_json::from_str(value).map_err(|error| {
            VolatilityError::Other(format!("Could not read the setting '{extension}': {error}"))
        })?) {
            config.set(setting_name(path), value);
        }
    }

    let mut finder = SymbolFinder::with_defaults();
    for path in &arguments.symbol_paths {
        finder.add_path(path.clone());
    }
    // Plugins that need one of the bundled symbol files load it themselves, so
    // the context has to know where to look.
    context.set_symbol_paths(finder.base_paths().to_vec());

    // `--single-location` names the image as a URL. `-f` is shorthand for the
    // same thing and gives way to it.
    let image = arguments
        .single_location
        .as_deref()
        .map(location_to_path)
        .transpose()?
        .or_else(|| arguments.image.as_deref().map(std::path::PathBuf::from));

    // A run may name which image formats to try.
    if !arguments.stackers.is_empty() {
        crate::framework::automagic::stacker::set_stackers(arguments.stackers.clone());
    }

    // Swap files are opened first, so the address spaces built below can read
    // the pages that were paged out to them.
    if !arguments.single_swap_locations.is_empty() {
        let mut names = Vec::new();
        for location in &arguments.single_swap_locations {
            let path = location_to_path(location)
                .unwrap_or_else(|_| std::path::PathBuf::from(location));
            let name = context.layers.free_name("swap_layer");
            context.layers.add(Arc::new(
                crate::framework::layers::physical::FileLayer::new(&name, &path)?,
            ));
            names.push(name);
        }
        crate::framework::layers::intel::set_swap_layers(names);
    }

    if let Some(image) = &image {
        if !image.is_file() {
            return Err(VolatilityError::Io(format!(
                "Image file '{}' does not exist",
                image.display()
            )));
        }

        // Identifying the operating system means scanning the whole image, and
        // a plugin that needs no kernel symbols gains nothing from it. Skipping
        // it there avoids two full passes over a multi-gigabyte capture.
        let needs_kernel = plugin.needs_kernel() || plugin.requirements().iter().any(|requirement| {
            matches!(
                requirement.kind,
                crate::framework::plugins::RequirementKind::Kernel
            ) || (matches!(
                requirement.kind,
                crate::framework::plugins::RequirementKind::TranslationLayer
            ) && requirement.architectures.is_some())
        });

        let result = if needs_kernel {
            automagic::run(&context, image, &finder)?
        } else {
            automagic::stack_only(&context, image)?
        };
        for note in &result.notes {
            log::info!("{note}");
        }

        // A plugin that names the layer it wants, rather than taking the
        // kernel's, has it registered under that name.
        let mut result = result;
        if let (Some(wanted), Some(built)) = (
            plugin.requirements().iter().find_map(|requirement| {
                (requirement.kind
                    == crate::framework::plugins::RequirementKind::TranslationLayer
                    && requirement.architectures.is_none())
                .then(|| requirement.name.clone())
            }),
            result.kernel_layer.clone(),
        ) {
            if wanted != built {
                context.layers.rename(&built, &wanted);
                result.kernel_layer = Some(wanted);
            }
        }

        // A plugin that runs others needs to know what kind of image this is,
        // since only plugins for that system can be satisfied.
        config.set(
            "operating_system",
            ConfigValue::Str(result.operating_system.as_str().to_string()),
        );
        config.set("physical_layer", ConfigValue::Str(result.physical_layer.clone()));
        if let Some(kernel_layer) = &result.kernel_layer {
            config.set("primary", ConfigValue::Str(kernel_layer.clone()));
        } else {
            config.set(
                "primary",
                ConfigValue::Str(result.physical_layer.clone()),
            );
        }
        if let Some(module) = &result.kernel_module {
            config.set("kernel", ConfigValue::Str(module.clone()));
        }

        // A plugin written for one OS cannot work on another, and saying so is
        // more useful than letting it fail on a missing symbol.
        let required = plugin.operating_system();
        if required != OperatingSystem::Any
            && result.operating_system != OperatingSystem::Any
            && required != result.operating_system
        {
            return Err(VolatilityError::Other(format!(
                "Plugin '{}' targets {} but the image was identified as {}",
                plugin.name(),
                required.as_str(),
                result.operating_system.as_str()
            )));
        }
        // Only a plugin that asked for the kernel is blocked by its absence.
        // One that reads raw memory runs regardless.
        if needs_kernel && required != OperatingSystem::Any && result.kernel_module.is_none() {
            // Without symbols the plugin cannot run at all, and the failure it
            // would otherwise report, an unsatisfied `--kernel` argument, says
            // nothing about what is actually missing.
            return Err(VolatilityError::Other(format!(
                "No symbols were found for this image, so '{}' cannot run.\n\
                 Put a symbol pack for the kernel in {}, pass --symbol-dirs, or set {}.\n\
                 Searched:\n  {}",
                plugin.name(),
                crate::framework::symbols::intermed::data_directory()
                    .map(|data| data.join("symbols").display().to_string())
                    .unwrap_or_else(|| "the symbols directory".to_string()),
                crate::framework::symbols::intermed::SYMBOL_PATH_VARIABLE,
                finder
                    .base_paths()
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n  "),
            )));
        }
    } else if plugin.requirements().iter().any(|requirement| {
        matches!(
            requirement.kind,
            crate::framework::plugins::RequirementKind::Kernel
                | crate::framework::plugins::RequirementKind::TranslationLayer
        )
    }) {
        return Err(VolatilityError::Other(format!(
            "Plugin '{}' needs an image; supply one with --file",
            plugin.name()
        )));
    }

    // A missing required option is reported before anything reaches standard
    // output, so a failed invocation writes no partial table.
    for requirement in plugin.requirements() {
        if !requirement.optional && config.get(&requirement.name).is_none() {
            return Err(VolatilityError::Other(format!(
                "the following arguments are required: --{}",
                requirement.name
            )));
        }
    }

    // Upstream announces itself before the table. Matching that keeps piped
    // output identical. A machine-readable format keeps its stream clean, so
    // the announcement goes to the error stream instead.
    let (major, minor, patch) = crate::interface_version();
    let banner = format!("Volatility 3 Framework {major}.{minor}.{patch}");
    if arguments.format.structured() {
        eprintln!("{banner}");
    } else {
        println!("{banner}");
    }

    // These two formats are the reference implementation's optional ones, which
    // it also refuses when its table library is absent.
    if matches!(arguments.format, OutputFormat::Arrow | OutputFormat::Parquet) {
        return Err(VolatilityError::Other(
            "This output format is not available in this build".to_string(),
        ));
    }

    // What the run was configured with, written where it was asked for.
    let save_config = arguments
        .save_config
        .clone()
        .or_else(|| arguments.write_config.then(|| std::path::PathBuf::from("config.json")));
    if let Some(path) = save_config {
        if path.exists() {
            return Err(VolatilityError::Other(format!(
                "Cannot write configuration: file {} already exists",
                path.display()
            )));
        }
        let named = vec![(String::new(), plugin.clone())];
        let document = crate::framework::plugins::generic::configwriter::record_configuration(
            &context, &config, &named,
        );
        std::fs::write(&path, format!("{document}\n"))
            .map_err(|error| VolatilityError::Io(format!("{error}")))?;
    }

    let grid = plugin.run(context, &config)?;

    // Which rows and columns to show is settled once the grid's columns are
    // known, since a filter may name a column.
    let mut options = crate::framework::renderers::filter::RenderOptions::default();
    options.hidden = arguments.hide_columns.clone();
    options.prepare(&grid, &arguments.filters);

    let renderer: Box<dyn Renderer> = match arguments.format {
        OutputFormat::Pretty => Box::new(PrettyTextRenderer { options }),
        OutputFormat::Quick => Box::new(QuickTextRenderer {
            options,
            ..Default::default()
        }),
        OutputFormat::Csv => Box::new(CsvRenderer {
            options,
            ..CsvRenderer::new()
        }),
        OutputFormat::Json => Box::new(JsonRenderer {
            lines: false,
            options,
        }),
        OutputFormat::JsonLines => Box::new(JsonRenderer {
            lines: true,
            options,
        }),
        // Nothing is written at all.
        OutputFormat::None => return Ok(0),
        OutputFormat::Arrow | OutputFormat::Parquet => unreachable!(),
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    renderer.render(&grid, &mut handle)?;
    handle.flush()?;

    Ok(0)
}

/// Read a configuration file and apply the settings it holds.
///
/// A file written by a previous run describes the whole configuration, most of
/// which this port works out for itself. The settings that name the plugin's
/// own options are the ones applied.
fn apply_configuration_file(
    plugin: &dyn crate::framework::plugins::Plugin,
    config: &Configuration,
    path: &std::path::Path,
) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| VolatilityError::Io(format!("{}: {error}", path.display())))?;
    let document: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| VolatilityError::Other(format!("{}: {error}", path.display())))?;
    let Some(settings) = document.as_object() else {
        return Err(VolatilityError::Other(format!(
            "{} does not hold a configuration",
            path.display()
        )));
    };

    let requirements = plugin.requirements();
    for (key, value) in settings {
        let name = setting_name(key);
        if !requirements
            .iter()
            .any(|requirement| requirement.name == name)
        {
            log::debug!("Ignoring the setting '{key}', which this plugin does not take");
            continue;
        }
        if let Some(value) = json_to_config(value) {
            config.set(name, value);
        }
    }
    Ok(())
}

/// The option a dotted setting path names.
fn setting_name(path: &str) -> String {
    path.rsplit('.').next().unwrap_or(path).to_string()
}

/// A setting's value, as the configuration holds it.
fn json_to_config(value: &serde_json::Value) -> Option<ConfigValue> {
    Some(match value {
        serde_json::Value::Bool(value) => ConfigValue::Bool(*value),
        serde_json::Value::Number(number) => ConfigValue::Int(number.as_i64()?),
        serde_json::Value::String(text) => ConfigValue::Str(text.clone()),
        serde_json::Value::Array(items) => {
            ConfigValue::List(items.iter().filter_map(json_to_config).collect())
        }
        _ => return None,
    })
}

/// The path a `file://` location names.
fn location_to_path(location: &str) -> Result<std::path::PathBuf> {
    match location.strip_prefix("file://") {
        Some(path) => Ok(std::path::PathBuf::from(path)),
        None => Err(VolatilityError::Other(format!(
            "Only file locations are supported, not '{location}'"
        ))),
    }
}

fn configure_logging(verbosity: u8, log: Option<&std::path::Path>) {
    let level = match verbosity {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(level)
        .format_timestamp(None)
        .format_target(false);
    // A log file receives everything, whatever the console was asked for.
    if let Some(path) = log {
        if let Ok(file) = std::fs::File::create(path) {
            builder
                .filter_level(log::LevelFilter::Trace)
                .target(env_logger::Target::Pipe(Box::new(file)));
        }
    }
    builder.try_init().ok();
}

/// The framework's own help page, with every plugin listed.
fn framework_help(registry: &PluginRegistry) -> String {
    let plugins: Vec<(String, String)> = registry
        .all()
        .iter()
        .map(|plugin| (plugin.name().to_string(), plugin.description().to_string()))
        .collect();
    crate::cli::help::framework_help(&plugins)
}

#[allow(dead_code)]
fn print_help(registry: &PluginRegistry) {
    println!(
        "\
Volatility 3 (Rust port) -- memory forensics framework

Usage:
  vol [options] <plugin> [plugin options]

Options:
  -f, --file <path>        The memory image to analyse
  -s, --symbol-dirs <dirs> Colon-separated directories to search for symbol files
  -r, --renderer <format>  Output format: text, quick, csv, json, pretty-json
  -q, --quiet              Shorthand for --renderer quick
  -v, -vv, -vvv            Increase logging verbosity
  -l, --list-plugins       List available plugins (optionally filtered)
  -V, --version            Print the framework version
  -h, --help               Show this message

{} plugins are available; run 'vol --list-plugins' to see them.

Examples:
  vol -f memory.raw windows.pslist.PsList
  vol -f memory.lime banners.Banners
  vol -f memory.raw --renderer csv windows.pslist.PsList --pid 4,8",
        registry.len()
    );
}

fn list_plugins(registry: &PluginRegistry, filter: Option<&str>) {
    let plugins = match filter {
        Some(needle) => registry.search(needle),
        None => registry.all().to_vec(),
    };

    if plugins.is_empty() {
        println!("No plugins matched.");
        return;
    }

    let width = plugins
        .iter()
        .map(|plugin| plugin.name().len())
        .max()
        .unwrap_or(0);

    for plugin in plugins {
        println!(
            "{:<width$}  {}",
            plugin.name(),
            plugin.description(),
            width = width
        );
    }
}
