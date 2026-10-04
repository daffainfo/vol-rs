//! Print every plugin's option table, so the port can be checked against the
//! reference implementation's own requirement list.

fn main() {
    let registry = vol_rs::framework::plugins::PluginRegistry::new();
    for plugin in registry.all() {
        let name = plugin.name();
        for requirement in plugin.requirements() {
            let kind = format!("{:?}", requirement.kind);
            let default = match &requirement.default {
                Some(value) => format!("{value:?}"),
                None => "None".to_string(),
            };
            println!(
                "{name}\t{}\t{kind}\t{default}\t{}\t{}",
                requirement.name, requirement.optional, requirement.description
            );
        }
    }
}
