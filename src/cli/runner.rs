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
        // Upstream announces itself as soon as the arguments have parsed and
        // only then complains that no plugin was named, so the announcement
        // comes out ahead of the complaint.
        announce(&arguments);
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
    // Any part of a plugin's name selects it, as long as only one plugin
    // carries that part. The complaints below are the ones the reference
    // implementation makes, with the same usage block above them.
    let candidates = registry.matching(plugin_name);
    let plugin = match candidates.as_slice() {
        [only] => (*only).clone(),
        [] => {
            let all: Vec<&str> = registry.all().iter().map(|p| p.name()).collect();
            eprint!("{}", crate::cli::help::framework_usage_block());
            eprintln!(
                "vol: error: argument PLUGIN: invalid choice {plugin_name} (choose from {})",
                all.join(", ")
            );
            return Ok(2);
        }
        several => {
            let names: Vec<&str> = several.iter().map(|p| p.name()).collect();
            eprint!("{}", crate::cli::help::framework_usage_block());
            eprintln!(
                "vol: error: argument PLUGIN: plugin {plugin_name} matches multiple plugins ({})",
                names.join(", ")
            );
            return Ok(2);
        }
    };

    let context = Arc::new(Context::new());
    let config = Configuration::new();

    // A configuration file is read first, so anything given on the command line
    // takes precedence over it.
    if let Some(path) = &arguments.config {
        apply_configuration_file(plugin.as_ref(), &config, path)?;
    }

    // Plugin options first, so a failure here is reported before the expensive
    // work of stacking and scanning an image. argparse refuses a missing
    // required option before anything else happens, the announcement included,
    // and names all of them in one complaint under the plugin's own usage.
    let settings = match args::build_plugin_config(plugin.as_ref(), &arguments.plugin_args) {
        Ok(settings) => settings,
        Err(VolatilityError::Unrecognised(names)) => {
            // Upstream's main parser is the one that complains, so the
            // framework's own usage block is the one shown, and the words are
            // the ones the command line carried.
            let mut words: Vec<String> = Vec::new();
            for name in &names {
                if let Some((_, tokens)) = arguments
                    .plugin_tokens
                    .iter()
                    .find(|(option, _)| option == name)
                {
                    words.extend(tokens.iter().cloned());
                } else {
                    words.push(format!("--{name}"));
                }
            }
            eprint!("{}", crate::cli::help::framework_usage_block());
            eprintln!("vol: error: unrecognized arguments: {}", words.join(" "));
            return Ok(2);
        }
        Err(VolatilityError::Unsatisfied(missing)) => {
            let named: Vec<String> = missing
                .iter()
                .map(|name| format!("--{}", name.replace('_', "-")))
                .collect();
            eprint!("{}", crate::cli::help::plugin_usage_block(plugin.as_ref()));
            eprintln!(
                "vol {}: error: the following arguments are required: {}",
                plugin.name(),
                named.join(", ")
            );
            return Ok(2);
        }
        Err(error) => return Err(error),
    };
    for (name, value) in settings {
        config.set(name, value);
    }

    // Upstream announces itself once the arguments are settled and before
    // anything is opened.
    announce(&arguments);

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
        if !image.exists() {
            // The reference implementation turns the name into a URL first, so
            // the path it names back is the absolute one.
            let full = std::fs::canonicalize(image)
                .unwrap_or_else(|_| {
                    std::env::current_dir()
                        .map(|cwd| cwd.join(image))
                        .unwrap_or_else(|_| image.clone())
                });
            eprint!("{}", crate::cli::help::framework_usage_block());
            eprintln!("vol: error: File does not exist: {}", full.display());
            return Ok(2);
        }

        // Whether the plugin can run at all without the kernel's symbols. One
        // that names a layer for a particular architecture needs the kernel's
        // address space to have been built, and so needs them too.
        let needs_kernel = plugin.needs_kernel()
            || plugin.requirements().iter().any(|requirement| {
                matches!(
                    requirement.kind,
                    crate::framework::plugins::RequirementKind::Kernel
                ) || (matches!(
                    requirement.kind,
                    crate::framework::plugins::RequirementKind::TranslationLayer
                ) && requirement.architectures.is_some())
            });

        // The whole chain runs whatever the plugin asked for. A plugin that
        // names a layer without saying which architecture it wants is still
        // given the topmost one that was built, so a plugin reading physical
        // memory only by convention still sees the kernel's address space,
        // and skipping the search here would hand it the file instead.
        let result = automagic::run(&context, image, &finder)?;
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
        // A plugin that names the architectures its layer may have cannot run
        // on an image of another one, and the requirement is reported as unmet
        // rather than the plugin failing part-way.
        if let Some(layer) = &result.kernel_layer {
            let architecture = context
                .layers
                .get(layer)
                .ok()
                .and_then(|handle| handle.metadata().get("architecture").cloned());
            let mismatched = plugin.requirements().iter().any(|requirement| {
                matches!(
                    requirement.kind,
                    crate::framework::plugins::RequirementKind::Kernel
                        | crate::framework::plugins::RequirementKind::TranslationLayer
                ) && match (requirement.architectures, &architecture) {
                    (Some(wanted), Some(found)) => !wanted.contains(&found.as_str()),
                    _ => false,
                }
            });
            if mismatched {
                return Err(report_unsatisfied(&plugin, false));
            }
        }

        // Only a plugin that asked for the kernel is blocked by its absence.
        // One that reads raw memory runs regardless.
        if needs_kernel && required != OperatingSystem::Any && result.kernel_module.is_none() {
            // Where the symbols were looked for is useful and upstream does
            // not say it, so it goes in the log rather than in the report.
            log::info!(
                "No symbols were found for this image. Searched: {}",
                finder
                    .base_paths()
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Err(report_unsatisfied(&plugin, false));
        }
    } else if plugin.requirements().iter().any(|requirement| {
        matches!(
            requirement.kind,
            crate::framework::plugins::RequirementKind::Kernel
                | crate::framework::plugins::RequirementKind::TranslationLayer
        )
    }) {
        // Nothing was opened, so nothing the plugin asked of an image can be
        // met. A plugin that asked for nothing runs regardless.
        return Err(report_unsatisfied(&plugin, true));
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

    // A failure from here on is a failure of the analysis rather than of the
    // arguments, and is described in full before the run gives up.
    let grid = match plugin.run(context, &config) {
        Ok(grid) => grid,
        Err(error) => {
            report_exception(&error);
            return Ok(1);
        }
    };

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
    if let Err(error) = renderer.render(&grid, &mut handle) {
        let _ = handle.flush();
        drop(handle);
        report_exception(&error);
        return Ok(1);
    }
    handle.flush()?;
    drop(handle);

    // A run that died part-way has already written everything it is going to
    // write, and says so only through its exit status.
    if grid.aborted() {
        return Ok(1);
    }

    // A listing that stopped on an error has already written the blank line
    // that follows it, and the failure itself is described afterwards.
    if grid.truncation() == crate::framework::renderers::Truncation::Reported {
        match grid.failure() {
            Some(error) => describe_exception(error),
            None => describe_exception(&VolatilityError::Other(String::new())),
        }
        return Ok(1);
    }

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

/// Report that a plugin's requirements could not be satisfied, the way the
/// reference implementation reports it.
///
/// The requirements are named by their path within the configuration, and each
/// kind that failed adds a block saying what to check. The announcement and
/// the blocks go to standard output, so a run that fails this way looks the
/// same whichever stream is being read.
fn report_unsatisfied(
    plugin: &Arc<dyn crate::framework::plugins::Plugin>,
    missing_location: bool,
) -> VolatilityError {
    use crate::framework::plugins::RequirementKind;

    // The configuration path a plugin's own settings live under is named for
    // the class, which is the last part of the plugin's name.
    let class = plugin.name().rsplit('.').next().unwrap_or(plugin.name());
    let base = format!("plugins.{class}");

    let mut paths: Vec<(String, String)> = Vec::new();
    let mut translation_failed = false;
    let mut symbols_failed = false;
    for requirement in plugin.requirements() {
        match requirement.kind {
            // A module requirement is two requirements underneath: the layer
            // the module sits in and the symbols describing it. Neither
            // carries a description of its own.
            RequirementKind::Kernel => {
                paths.push((format!("{base}.{}.layer_name", requirement.name), String::new()));
                paths.push((
                    format!("{base}.{}.symbol_table_name", requirement.name),
                    String::new(),
                ));
                translation_failed = true;
                symbols_failed = true;
            }
            RequirementKind::TranslationLayer => {
                paths.push((
                    format!("{base}.{}", requirement.name),
                    requirement.description.clone(),
                ));
                translation_failed = true;
            }
            _ => {}
        }
    }

    // The reference implementation starts the report with a blank line.
    let mut text = String::from("\n");
    for (path, description) in &paths {
        text.push_str(&format!("Unsatisfied requirement {path}: {description}\n"));
    }
    if translation_failed {
        text.push_str(
            "\nA translation layer requirement was not fulfilled.  Please verify that:\n\
             \tA file was provided to create this layer (by -f, --single-location or by config)\n\
             \tThe file exists and is readable\n\
             \tThe file is a valid memory image and was acquired cleanly\n",
        );
    }
    if symbols_failed {
        text.push_str(
            "\nA symbol table requirement was not fulfilled.  Please verify that:\n\
             \tThe associated translation layer requirement was fulfilled\n\
             \tYou have the correct symbol file for the requirement\n\
             \tThe symbol file is under the correct directory or zip file\n\
             \tThe symbol file is named appropriately or contains the correct banner\n\n",
        );
    }
    // This goes to standard output whatever the renderer, which is where the
    // reference implementation prints it.
    print!("{text}");

    // Without an image there was nothing for the stacking step to work on, and
    // the reference implementation says so before listing what went unmet.
    if missing_location {
        eprintln!(
            "WARNING  volatility3.framework.plugins: Automagic exception occurred: \
             ValueError: Unable to run LayerStacker, single_location parameter not provided"
        );
    }
    VolatilityError::Unsatisfied(paths.into_iter().map(|(path, _)| path).collect())
}

/// Report a failure the way the reference implementation reports one.
///
/// It names the kind of problem, gives what detail the failure carries, lists
/// what usually causes it, and says that nothing more will follow. The two
/// blank lines on standard output come first, so a half written table is
/// separated from the report that explains why it stopped.
pub fn report_exception(error: &VolatilityError) {
    print!("\n\n");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    describe_exception(error);
}

/// The description of a failure, written where the blank lines that precede it
/// have already gone out: a listing that stopped part-way has written them as
/// part of its own output.
pub fn describe_exception(error: &VolatilityError) {
    const BUG: &str = "Please re-run with -vvv and file a bug with the output at \
                       https://github.com/volatilityfoundation/volatility3/issues";
    use std::io::Write;
    let _ = std::io::stdout().flush();

    let (general, detail, causes): (String, String, Vec<String>) = match error {
        VolatilityError::InvalidAddress {
            layer,
            address,
            message,
            fault,
        } => {
            let general = "Volatility was unable to read a requested page:".to_string();
            match fault {
                crate::error::AddressFault::Swapped { .. } => (
                    general,
                    format!("Swap error {address:#x} in layer {layer} ({message})"),
                    vec![
                        "No suitable swap file having been provided (locate and provide the correct swap file)".to_string(),
                        "An intentionally invalid page (operating system protection)".to_string(),
                    ],
                ),
                crate::error::AddressFault::Paged { .. } => (
                    general,
                    format!("Page error {address:#x} in layer {layer} ({message})"),
                    vec![
                        "Memory smear during acquisition (try re-acquiring if possible)".to_string(),
                        "An intentionally invalid page lookup (operating system protection)".to_string(),
                        "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)".to_string(),
                    ],
                ),
                crate::error::AddressFault::Invalid => (
                    general,
                    format!("{address:#x} in layer {layer} ({message})"),
                    vec![
                        "The base memory file being incomplete (try re-acquiring if possible)".to_string(),
                        "Memory smear during acquisition (try re-acquiring if possible)".to_string(),
                        "An intentionally invalid page lookup (operating system protection)".to_string(),
                        "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)".to_string(),
                    ],
                ),
            }
        }
        VolatilityError::Symbol {
            table,
            name,
            message,
        } => (
            "Volatility experienced a symbol-related issue:".to_string(),
            format!(
                "{}!{}: {message}",
                table.clone().unwrap_or_default(),
                name.clone().unwrap_or_default()
            ),
            vec![
                "An invalid symbol table".to_string(),
                "A plugin requesting a bad symbol".to_string(),
                "A plugin requesting a symbol from the wrong table".to_string(),
            ],
        ),
        VolatilityError::SymbolSpace(message) => (
            "Volatility experienced an issue related to a symbol table:".to_string(),
            message.clone(),
            vec![
                "An invalid symbol table".to_string(),
                "A plugin requesting a bad symbol".to_string(),
                "A plugin requesting a symbol from the wrong table".to_string(),
            ],
        ),
        VolatilityError::Layer { layer, message } => (
            format!("Volatility experienced a layer-related issue: {layer}"),
            message.clone(),
            vec![format!("A faulty layer implementation. {BUG}")],
        ),
        VolatilityError::MissingModule(module) => (
            format!("Volatility could not import a necessary module: {module}"),
            format!("{error}"),
            vec![
                "A required python module is not installed (install the module and re-run)"
                    .to_string(),
            ],
        ),
        VolatilityError::Render(message) => (
            "Volatility experienced an issue when rendering the output:".to_string(),
            message.clone(),
            vec!["An invalid renderer option, such as no visible columns".to_string()],
        ),
        VolatilityError::VersionMismatch(message) => (
            "A version mismatch was detected between two components:".to_string(),
            message.clone(),
            vec![
                "An outdated API caller, such as a method.".to_string(),
                BUG.to_string(),
            ],
        ),
        _ => (
            "Volatility encountered an unexpected situation.".to_string(),
            String::new(),
            vec![BUG.to_string()],
        ),
    };

    eprintln!("{general}");
    eprintln!("{detail}\n");
    for cause in &causes {
        eprintln!("\t* {cause}");
    }
    eprintln!("\nNo further results will be produced");
}

/// Write the framework's own announcement.
///
/// A machine-readable format keeps its own stream clean, so the announcement
/// goes to the error stream instead, which is the choice upstream makes from
/// the renderer's `structured_output`.
fn announce(arguments: &args::Arguments) {
    let (major, minor, patch) = crate::interface_version();
    let banner = format!("Volatility 3 Framework {major}.{minor}.{patch}");
    if arguments.format.structured() {
        eprintln!("{banner}");
    } else {
        println!("{banner}");
    }
}
