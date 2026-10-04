//! Convert a program database to a symbol file, for checking the converter.
fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: pdb_to_isf <file.pdb> <guid> <age>");
    let guid = args.next().unwrap_or_default();
    let age: u32 = args.next().unwrap_or_else(|| "1".into()).parse().unwrap_or(1);
    let data = std::fs::read(&path).expect("could not read the database");
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let isf = vol_rs::framework::symbols::windows::pdbconv::to_isf(&data, &name, &guid, age)
        .expect("could not convert");
    println!("{}", serde_json::to_string(&isf).expect("could not write"));
}
