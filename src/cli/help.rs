//! Plugin help, laid out the way the reference implementation's argparse does.
//!
//! `vol <plugin> --help` prints a usage line, the plugin's one line
//! description, its options and any trailing note. Reproducing that means
//! reproducing argparse's wrapping: the usage line packs whole options into
//! lines, help text is wrapped by Python's `textwrap` (which breaks words at
//! hyphens), and the help column sits at a position derived from the widest
//! option.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::framework::plugins::{Plugin, Requirement, RequirementKind};

/// argparse's ceiling on where the help column may start.
const MAX_HELP_POSITION: usize = 24;

/// One option as argparse sees it.
struct Action {
    /// The flags, as `-h, --help` or `--pid`.
    flags: Vec<String>,
    /// What follows the flag, empty for a switch.
    args: String,
    help: String,
    required: bool,
}

impl Action {
    /// The left hand side of the option's entry in the list.
    ///
    /// An option that takes a value repeats it after each of its names.
    fn invocation(&self) -> String {
        if self.args.is_empty() {
            return self.flags.join(", ");
        }
        self.flags
            .iter()
            .map(|flag| format!("{flag} {}", self.args))
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// How the option appears in the usage line.
    fn usage(&self) -> String {
        let mut part = self.flags[0].clone();
        if !self.args.is_empty() {
            part.push(' ');
            part.push_str(&self.args);
        }
        if self.required {
            part
        } else {
            format!("[{part}]")
        }
    }
}

/// The width argparse would lay text out to.
///
/// Python asks for the terminal's size, honouring `COLUMNS` first and falling
/// back to eighty columns when the output is not a terminal, then works two
/// columns narrower than that.
fn text_width() -> usize {
    let columns = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .or_else(terminal_columns)
        .unwrap_or(80);
    columns.saturating_sub(2).max(11)
}

#[cfg(unix)]
fn terminal_columns() -> Option<usize> {
    // TIOCGWINSZ against standard output, as Python's shutil does.
    #[repr(C)]
    struct WinSize {
        rows: u16,
        columns: u16,
        x_pixels: u16,
        y_pixels: u16,
    }
    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    const TIOCGWINSZ: u64 = 0x5413;
    let mut size = WinSize {
        rows: 0,
        columns: 0,
        x_pixels: 0,
        y_pixels: 0,
    };
    let result = unsafe { ioctl(1, TIOCGWINSZ, &mut size as *mut WinSize) };
    if result == 0 && size.columns > 0 {
        Some(size.columns as usize)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn terminal_columns() -> Option<usize> {
    None
}

/// The metavariable argparse would print for an option's value.
fn metavar(requirement: &Requirement) -> String {
    match &requirement.kind {
        RequirementKind::Choice(choices) => format!("{{{}}}", choices.join(",")),
        _ => requirement.name.to_uppercase(),
    }
}

/// Turn a plugin's requirements into the options argparse would offer.
fn actions(plugin: &dyn Plugin) -> Vec<Action> {
    let mut actions = vec![Action {
        flags: vec!["-h".to_string(), "--help".to_string()],
        args: String::new(),
        help: "show this help message and exit".to_string(),
        required: false,
    }];

    for requirement in plugin.requirements() {
        // Layers, modules and symbol tables are filled in by automagic and
        // never appear on the command line.
        let args = match &requirement.kind {
            RequirementKind::Kernel | RequirementKind::TranslationLayer => continue,
            RequirementKind::Bool => String::new(),
            RequirementKind::List(_) => {
                let name = metavar(&requirement);
                if requirement.optional {
                    format!("[{name} ...]")
                } else {
                    format!("{name} [{name} ...]")
                }
            }
            _ => metavar(&requirement),
        };

        actions.push(Action {
            flags: vec![format!("--{}", requirement.name.replace('_', "-"))],
            args,
            help: requirement.description.clone(),
            required: !requirement.optional,
        });
    }

    actions
}

/// The whole help page for a plugin.
pub fn plugin_help(plugin: &dyn Plugin) -> String {
    let width = text_width();
    let actions = actions(plugin);

    let mut help = format_usage(&format!("vol {}", plugin.name()), &actions, width);
    // A plugin upstream leaves undocumented has no description to print.
    if !plugin.description().is_empty() {
        help.push('\n');
        help.push_str(&fill(plugin.description(), width));
        help.push('\n');
    }
    help.push_str("\noptions:\n");
    help.push_str(&format_actions(&actions, width));
    if let Some(epilog) = plugin.epilog() {
        help.push('\n');
        help.push_str(&fill(epilog, width));
        help.push('\n');
    }
    help
}

/// The `usage:` line, wrapped by packing whole options onto each line.
fn format_usage(program: &str, actions: &[Action], width: usize) -> String {
    const PREFIX: &str = "usage: ";
    // An optional option stays together inside its brackets. A required one is
    // packed as separate words, which is how argparse splits the usage string
    // back up before wrapping it.
    let parts: Vec<String> = actions
        .iter()
        .flat_map(|action| {
            let usage = action.usage();
            if usage.starts_with('[') {
                vec![usage]
            } else {
                usage.split(' ').map(str::to_string).collect()
            }
        })
        .collect();
    let single = format!("{program} {}", parts.join(" "));

    if PREFIX.len() + single.len() <= width {
        return format!("{PREFIX}{single}\n");
    }

    // argparse keeps the options aligned under the program name, unless that
    // would leave too little room, in which case they start at the margin.
    let mut lines;
    if PREFIX.len() + program.len() <= (width * 3) / 4 {
        let indent = " ".repeat(PREFIX.len() + program.len() + 1);
        let mut all = vec![program.to_string()];
        all.extend(parts);
        lines = pack(&all, &indent, Some(PREFIX.len()), width);
        // The prefix takes the place of the first line's indent.
        lines[0] = lines[0][indent.len()..].to_string();
    } else {
        let indent = " ".repeat(PREFIX.len());
        lines = pack(&parts, &indent, None, width);
        lines.insert(0, program.to_string());
    }

    format!("{PREFIX}{}\n", lines.join("\n"))
}

/// Greedily fit whole parts onto lines of the given width.
fn pack(parts: &[String], indent: &str, prefix: Option<usize>, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line: Vec<&str> = Vec::new();
    let mut length = prefix.unwrap_or(indent.len()).saturating_sub(1);

    for part in parts {
        if length + 1 + part.len() > width && !line.is_empty() {
            lines.push(format!("{indent}{}", line.join(" ")));
            line.clear();
            length = indent.len().saturating_sub(1);
        }
        line.push(part);
        length += 1 + part.len();
    }
    if !line.is_empty() {
        lines.push(format!("{indent}{}", line.join(" ")));
    }
    lines
}

/// The option list, each entry with its help wrapped into the help column.
fn format_actions(actions: &[Action], width: usize) -> String {
    let longest = actions
        .iter()
        .map(|action| action.invocation().len() + 2)
        .max()
        .unwrap_or(0);
    let help_position = longest.saturating_add(2).min(MAX_HELP_POSITION);
    format_actions_at(actions, width, help_position, 2)
}

/// The same, with the help column and the indent given.
fn format_actions_at(
    actions: &[Action],
    width: usize,
    help_position: usize,
    indent: usize,
) -> String {
    let help_width = width.saturating_sub(help_position).max(11);
    let action_width = help_position.saturating_sub(indent + 2);
    let margin = " ".repeat(indent);

    let mut out = String::new();
    for action in actions {
        let invocation = action.invocation();
        // An option too wide for the column starts its help on the next line.
        let indent_first = if invocation.len() <= action_width {
            out.push_str(&format!("{margin}{invocation:action_width$}  "));
            0
        } else {
            out.push_str(&format!("{margin}{invocation}\n"));
            help_position
        };

        let lines = wrap(&action.help, help_width);
        if lines.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        out.push_str(&format!("{}{}\n", " ".repeat(indent_first), lines[0]));
        for line in &lines[1..] {
            out.push_str(&format!("{}{line}\n", " ".repeat(help_position)));
        }
    }
    out
}

/// Wrap text the way Python's `textwrap.fill` does.
fn fill(text: &str, width: usize) -> String {
    wrap(text, width).join("\n")
}

/// Wrap text into lines, breaking words at hyphens as Python does.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();

    for word in text.split_whitespace() {
        for (index, piece) in hyphen_pieces(word).into_iter().enumerate() {
            // Only the first piece of a word is preceded by a space. The rest
            // follow straight on from the hyphen they were split at.
            let separator = if line.is_empty() || index > 0 { 0 } else { 1 };
            if !line.is_empty() && line.len() + separator + piece.len() > width {
                lines.push(std::mem::take(&mut line));
            }
            if !line.is_empty() && index == 0 {
                line.push(' ');
            }
            line.push_str(&piece);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Split a word at the hyphens Python's `textwrap` would break it at.
///
/// A hyphen is a break only between letters: two letters before it, and a
/// letter (optionally followed by another hyphen and a letter) after it. The
/// hyphen stays with the piece to its left.
fn hyphen_pieces(word: &str) -> Vec<String> {
    let characters: Vec<char> = word.chars().collect();
    let letter = |index: usize| -> bool {
        characters
            .get(index)
            .is_some_and(|c| c.is_alphabetic() || *c == '_')
    };

    let mut pieces = Vec::new();
    let mut start = 0;
    for index in 0..characters.len() {
        if characters[index] != '-' {
            continue;
        }
        let before = (index >= 2 && letter(index - 1) && letter(index - 2))
            || (index >= 3 && letter(index - 1) && characters[index - 2] == '-' && letter(index - 3));
        let after = letter(index + 1)
            && (letter(index + 2) || (characters.get(index + 2) == Some(&'-') && letter(index + 3)));
        if before && after {
            pieces.push(characters[start..=index].iter().collect::<String>());
            start = index + 1;
        }
    }
    pieces.push(characters[start..].iter().collect::<String>());
    pieces
}

/// The options the framework itself takes, in the order the reference
/// implementation declares them.
fn framework_actions() -> Vec<Action> {
    let cache = crate::framework::cache::directory()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "the cache directory".to_string());

    let option = |flags: &[&str], args: &str, help: String| Action {
        flags: flags.iter().map(|flag| flag.to_string()).collect(),
        args: args.to_string(),
        help,
        required: false,
    };

    vec![
        option(
            &["-h", "--help"],
            "",
            "Show this help message and exit, for specific plugin options use \
             'vol <pluginname> --help'"
                .to_string(),
        ),
        option(
            &["-c", "--config"],
            "CONFIG",
            "Load the configuration from a json file".to_string(),
        ),
        option(
            &["--parallelism"],
            "[{processes,threads,off}]",
            "Enables parallelism (defaults to off if no argument given)".to_string(),
        ),
        option(
            &["-e", "--extend"],
            "EXTEND",
            "Extend the configuration with a new (or changed) setting".to_string(),
        ),
        option(
            &["-p", "--plugin-dirs"],
            "PLUGIN_DIRS",
            "Semi-colon separated list of paths to find plugins".to_string(),
        ),
        option(
            &["-s", "--symbol-dirs"],
            "SYMBOL_DIRS",
            "Semi-colon separated list of paths to find symbols".to_string(),
        ),
        option(
            &["-v", "--verbosity"],
            "",
            "Increase output verbosity".to_string(),
        ),
        option(
            &["-l", "--log"],
            "LOG",
            "Log output to a file as well as the console".to_string(),
        ),
        option(
            &["-o", "--output-dir"],
            "OUTPUT_DIR",
            "Directory in which to output any generated files".to_string(),
        ),
        option(&["-q", "--quiet"], "", "Remove progress feedback".to_string()),
        option(
            &["-f", "--file"],
            "FILE",
            "Shorthand for --single-location=file:// if single-location is not defined"
                .to_string(),
        ),
        option(
            &["--write-config"],
            "",
            "Write configuration JSON file out to config.json".to_string(),
        ),
        option(
            &["--save-config"],
            "SAVE_CONFIG",
            "Save configuration JSON file to a file".to_string(),
        ),
        option(
            &["--clear-cache"],
            "",
            "Clears out all short-term cached items".to_string(),
        ),
        option(
            &["--cache-path"],
            "CACHE_PATH",
            format!("Change the default path ({cache}) used to store the cache"),
        ),
        option(
            &["--offline"],
            "",
            "Do not search online for additional JSON files".to_string(),
        ),
        option(
            &["-u", "--remote-isf-url"],
            "URL",
            "Search online for ISF json files".to_string(),
        ),
        option(
            &["--filters"],
            "FILTERS",
            "List of filters to apply to the output (in the form of \
             [+-]columname,pattern[!])"
                .to_string(),
        ),
        option(
            &["--hide-columns"],
            "[HIDE_COLUMNS ...]",
            "Case-insensitive space separated list of prefixes to determine which \
             columns to hide in the output if provided"
                .to_string(),
        ),
        option(
            &["-r", "--renderer"],
            "RENDERER",
            "Determines how to render the output (quick, none, csv, pretty, json, \
             jsonl, arrow, parquet)"
                .to_string(),
        ),
        option(
            &["--single-location"],
            "SINGLE_LOCATION",
            "Specifies a base location on which to stack".to_string(),
        ),
        option(&["--stackers"], "[STACKERS ...]", "List of stackers".to_string()),
        option(
            &["--single-swap-locations"],
            "[SINGLE_SWAP_LOCATIONS ...]",
            "Specifies a list of swap layer URIs for use with single-location".to_string(),
        ),
    ]
}

/// The `usage:` line the framework prints, which names every option and then
/// the plugin.
fn framework_usage(width: usize) -> String {
    const PREFIX: &str = "usage: ";
    let actions = framework_actions();
    let mut parts: Vec<String> = Vec::new();
    for action in &actions {
        // The two ways of naming a symbol store are alternatives to each other,
        // and are shown as one choice.
        if action.flags[0] == "--offline" {
            parts.push("[--offline | -u URL]".to_string());
            continue;
        }
        if action.flags[0] == "-u" {
            continue;
        }
        let usage = action.usage();
        if usage.starts_with('[') {
            parts.push(usage);
        } else {
            parts.extend(usage.split(' ').map(str::to_string));
        }
    }
    // The plugin itself is a value rather than an option, and values are laid
    // out after the options rather than packed in with them.
    let positional = vec!["PLUGIN".to_string(), "...".to_string()];

    let program = "vol";
    let single = format!("{program} {} {}", parts.join(" "), positional.join(" "));
    if PREFIX.len() + single.len() <= width {
        return format!("{PREFIX}{single}\n");
    }

    let indent = " ".repeat(PREFIX.len() + program.len() + 1);
    let mut all = vec![program.to_string()];
    all.extend(parts);
    let mut lines = pack(&all, &indent, Some(PREFIX.len()), width);
    lines[0] = lines[0][indent.len()..].to_string();
    lines.extend(pack(&positional, &indent, None, width));
    format!("{PREFIX}{}\n", lines.join("\n"))
}

/// The usage block on its own, which is what an error is reported under.
pub fn framework_usage_block() -> String {
    framework_usage(text_width())
}

/// The whole help page for the framework itself.
pub fn framework_help(plugins: &[(String, String)]) -> String {
    let width = text_width();
    let actions = framework_actions();

    // The help column is decided by the widest thing in either section, the
    // plugin names included.
    let longest = actions
        .iter()
        .map(|action| action.invocation().len() + 2)
        .chain(plugins.iter().map(|(name, _)| name.len() + 4))
        .chain(std::iter::once("PLUGIN".len() + 2))
        .max()
        .unwrap_or(0);
    let help_position = longest.saturating_add(2).min(MAX_HELP_POSITION);

    let mut help = framework_usage(width);
    help.push('\n');
    help.push_str(&fill("An open-source memory forensics framework", width));
    help.push_str("\n\noptions:\n");
    help.push_str(&format_actions_at(&actions, width, help_position, 2));

    help.push_str("\nPlugins:\n");
    help.push_str(&fill_indented(
        "For plugin specific options, run 'vol <plugin> --help'",
        width,
        2,
    ));
    // A section's description is separated from its entries by a blank line.
    help.push_str("\n\n");
    // The choice of plugin is a value in its own right, described by the list
    // of plugins beneath it.
    help.push_str("  PLUGIN\n");
    let choices: Vec<Action> = plugins
        .iter()
        .map(|(name, description)| Action {
            flags: vec![name.clone()],
            args: String::new(),
            help: description.clone(),
            required: true,
        })
        .collect();
    help.push_str(&format_actions_at(&choices, width, help_position, 4));
    help
}

/// Wrap text and indent every line by the given amount.
fn fill_indented(text: &str, width: usize, indent: usize) -> String {
    wrap(text, width - indent)
        .into_iter()
        .map(|line| format!("{}{line}", " ".repeat(indent)))
        .collect::<Vec<String>>()
        .join("\n")
}
