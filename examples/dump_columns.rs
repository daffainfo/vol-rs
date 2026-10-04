//! Print every plugin's column list, so the port can be checked against the
//! reference implementation's own tree grid headings.

fn main() {
    let registry = vol_rs::framework::plugins::PluginRegistry::new();
    for plugin in registry.all() {
        let columns: Vec<String> = plugin
            .columns()
            .iter()
            .map(|column| format!("{}:{:?}", column.name, column.column_type))
            .collect();
        println!("{}\t{}", plugin.name(), columns.join(", "));
    }
}
