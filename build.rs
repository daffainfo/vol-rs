//! Compress the bundled symbol files and make them part of the binary.
//!
//! The files are held in the repository as plain JSON so they can be read and
//! changed, and compressed here so they cost little in the binary that ships.

use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=symbols");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("symbols");

    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files.sort();

    let packed = out.join("bundled");
    std::fs::create_dir_all(&packed).expect("could not make the staging directory");

    let mut listing = String::from(
        "/// Every symbol file built into the binary, as compressed bytes.\n\
         pub static BUNDLED_SYMBOLS: &[(&str, &[u8])] = &[\n",
    );
    for name in &files {
        let raw = std::fs::read(root.join(name)).expect("could not read a bundled symbol file");
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 9);
        encoder.write_all(&raw).expect("could not compress");
        let squeezed = encoder.finish().expect("could not finish compressing");

        let flat = name.replace(['/', '\\'], "_");
        std::fs::write(packed.join(&flat), &squeezed).expect("could not stage");
        listing.push_str(&format!(
            "    ({name:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bundled/{flat}\"))),\n"
        ));
    }
    listing.push_str("];\n");
    std::fs::write(out.join("bundled_symbols.rs"), listing).expect("could not write the listing");
}

/// Every JSON file under `directory`, named relative to `root`.
fn collect(root: &Path, directory: &Path, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, found);
        } else if path.extension().is_some_and(|e| e == "json") {
            let name = path
                .strip_prefix(root)
                .expect("a found file is under the root")
                .to_string_lossy()
                .replace('\\', "/");
            found.push(name);
        }
    }
}
