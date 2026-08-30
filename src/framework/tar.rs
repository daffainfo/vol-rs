//! Writing tar archives, as the reference implementation's `tarfile` writes
//! them.
//!
//! One plugin recovers a filesystem out of the page cache and packs it into a
//! compressed tarball. The entries are written in the extended format Python
//! defaults to: a `pax` record carrying the fractional timestamp, followed by
//! the ordinary header everything else can read.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

/// Every field in a tar header is fixed width, and the blocks are padded out to
/// this size.
const BLOCK: usize = 512;

/// The longest name an ordinary header can hold.
const NAME_LIMIT: usize = 100;

/// Builds a tar archive in memory.
pub struct Archive {
    data: Vec<u8>,
}

/// What an entry is.
enum Kind<'a> {
    File(&'a [u8]),
    Directory,
    Symlink(&'a str),
}

impl Default for Archive {
    fn default() -> Self {
        Archive::new()
    }
}

impl Archive {
    pub fn new() -> Self {
        Archive { data: Vec::new() }
    }

    /// Add a directory.
    pub fn directory(&mut self, path: &str, mode: u32, mtime: f64) {
        self.add(path, mode, mtime, Kind::Directory);
    }

    /// Add a file with its contents.
    pub fn file(&mut self, path: &str, mode: u32, mtime: f64, contents: &[u8]) {
        self.add(path, mode, mtime, Kind::File(contents));
    }

    /// Add a symbolic link pointing at `target`.
    pub fn symlink(&mut self, path: &str, target: &str, mode: u32, mtime: f64) {
        self.add(path, mode, mtime, Kind::Symlink(target));
    }

    /// Close the archive: two empty blocks, then padding to a whole record.
    pub fn finish(mut self) -> Vec<u8> {
        self.data.extend(std::iter::repeat_n(0u8, BLOCK * 2));
        // A record is twenty blocks, and an archive is a whole number of them.
        let record = BLOCK * 20;
        let remainder = self.data.len() % record;
        if remainder != 0 {
            self.data
                .extend(std::iter::repeat_n(0u8, record - remainder));
        }
        self.data
    }

    fn add(&mut self, path: &str, mode: u32, mtime: f64, kind: Kind) {
        // A directory's name carries a trailing separator.
        let owned;
        let path = if matches!(kind, Kind::Directory) && !path.ends_with('/') {
            owned = format!("{path}/");
            &owned
        } else {
            path
        };
        // The timestamp has a fractional part and the name may be too long for
        // the ordinary header, so both are carried in an extended record.
        let mut records = String::new();
        records.push_str(&pax_record("mtime", &format_timestamp(mtime)));
        if path.len() > NAME_LIMIT {
            records.push_str(&pax_record("path", path));
        }
        if let Kind::Symlink(target) = kind
            && target.len() > NAME_LIMIT
        {
            records.push_str(&pax_record("linkpath", target));
        }
        if !records.is_empty() {
            self.write_entry(
                "././@PaxHeader",
                0o644,
                mtime.trunc() as u64,
                b'x',
                "",
                records.as_bytes(),
            );
        }

        let (flag, target, contents): (u8, &str, &[u8]) = match kind {
            Kind::File(contents) => (b'0', "", contents),
            Kind::Directory => (b'5', "", &[]),
            Kind::Symlink(target) => (b'2', target, &[]),
        };
        self.write_entry(path, mode, mtime.trunc() as u64, flag, target, contents);
    }

    fn write_entry(
        &mut self,
        path: &str,
        mode: u32,
        mtime: u64,
        flag: u8,
        target: &str,
        contents: &[u8],
    ) {
        let mut header = [0u8; BLOCK];
        // A name too long for the field is truncated here and given in full by
        // the extended record that precedes it.
        let name = path.as_bytes();
        let length = name.len().min(NAME_LIMIT);
        header[..length].copy_from_slice(&name[..length]);

        write_octal(&mut header[100..108], mode as u64, 7);
        write_octal(&mut header[108..116], 0, 7);
        write_octal(&mut header[116..124], 0, 7);
        write_octal(&mut header[124..136], contents.len() as u64, 11);
        write_octal(&mut header[136..148], mtime, 11);
        header[156] = flag;
        let link = target.as_bytes();
        let link_length = link.len().min(NAME_LIMIT);
        header[157..157 + link_length].copy_from_slice(&link[..link_length]);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // The checksum is computed with its own field read as spaces.
        header[148..156].copy_from_slice(b"        ");
        let checksum: u64 = header.iter().map(|byte| *byte as u64).sum();
        // Six digits and a terminator, then the space the format ends with.
        write_octal(&mut header[148..155], checksum, 6);
        header[155] = b' ';

        self.data.extend_from_slice(&header);
        self.data.extend_from_slice(contents);
        let remainder = contents.len() % BLOCK;
        if remainder != 0 {
            self.data.extend(std::iter::repeat_n(0u8, BLOCK - remainder));
        }
    }
}

/// One extended record: its own length, then `keyword=value`.
///
/// The length counts itself, so it is worked out by trying successive widths
/// until the answer stops changing.
fn pax_record(keyword: &str, value: &str) -> String {
    let body = format!(" {keyword}={value}\n");
    let mut length = body.len();
    loop {
        let total = body.len() + length.to_string().len();
        if total == length {
            break;
        }
        length = total;
    }
    format!("{length}{body}")
}

/// A timestamp with its fractional part, as Python writes one.
fn format_timestamp(mtime: f64) -> String {
    let text = format!("{mtime:.6}");
    // Trailing zeros are not written, and neither is a bare decimal point.
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    trimmed.to_string()
}

/// Write a value as octal digits, right aligned and null terminated.
fn write_octal(field: &mut [u8], value: u64, digits: usize) {
    let text = format!("{value:0>digits$o}", digits = digits);
    let bytes = text.as_bytes();
    let start = field.len().saturating_sub(bytes.len() + 1);
    field[start..start + bytes.len()].copy_from_slice(bytes);
    field[field.len() - 1] = 0;
}
