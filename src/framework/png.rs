//! Writing PNG files the way the reference implementation's imaging library
//! writes them.
//!
//! Only one plugin needs this, recovering a framebuffer, but its output has to
//! match byte for byte, which means matching two things exactly: the row filter
//! chosen for each line, and the deflate stream. The filter is picked by the
//! usual heuristic of least total deviation, and the compression is done by
//! zlib itself with the settings the reference implementation asks for.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

/// Bytes per pixel in the images written here.
const CHANNELS: usize = 4;

/// The largest amount of compressed data one `IDAT` chunk carries.
const MAX_CHUNK: usize = 65536;

/// Encode 8-bit RGBA pixels as a PNG file.
pub fn encode_rgba(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let stride = width as usize * CHANNELS;
    let mut filtered = Vec::with_capacity((stride + 1) * height as usize);
    let zeros = vec![0u8; stride];
    let mut previous: &[u8] = &zeros;

    for row in 0..height as usize {
        let start = row * stride;
        let current = &pixels[start..start + stride];
        let (kind, line) = filter_row(current, previous, stride);
        filtered.push(kind);
        filtered.extend_from_slice(&line);
        previous = current;
    }

    let compressed = deflate(&filtered);

    let mut file = Vec::with_capacity(compressed.len() + 64);
    file.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    // Eight bits per channel, truecolour with alpha, no interlacing.
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    write_chunk(&mut file, b"IHDR", &header);

    for piece in compressed.chunks(MAX_CHUNK) {
        write_chunk(&mut file, b"IDAT", piece);
    }
    write_chunk(&mut file, b"IEND", &[]);
    file
}

/// Choose the filter that leaves a row easiest to compress.
///
/// Each candidate is scored by the sum of its bytes read as signed values, and
/// the lowest wins. A tie goes to the earlier filter.
fn filter_row(current: &[u8], previous: &[u8], stride: usize) -> (u8, Vec<u8>) {
    let mut best: Option<(u64, u8, Vec<u8>)> = None;
    for kind in 0..5u8 {
        let mut line = vec![0u8; stride];
        let mut score = 0u64;
        for index in 0..stride {
            let left = if index >= CHANNELS {
                current[index - CHANNELS]
            } else {
                0
            };
            let above = previous[index];
            let corner = if index >= CHANNELS {
                previous[index - CHANNELS]
            } else {
                0
            };
            let value = match kind {
                0 => current[index],
                1 => current[index].wrapping_sub(left),
                2 => current[index].wrapping_sub(above),
                3 => current[index]
                    .wrapping_sub(((left as u16 + above as u16) >> 1) as u8),
                _ => current[index].wrapping_sub(paeth(left, above, corner)),
            };
            line[index] = value;
            score += if value < 128 {
                value as u64
            } else {
                256 - value as u64
            };
        }
        if best.as_ref().is_none_or(|(lowest, ..)| score < *lowest) {
            best = Some((score, kind, line));
        }
    }
    let (_, kind, line) = best.expect("five filters were tried");
    (kind, line)
}

/// The predictor the Paeth filter subtracts.
fn paeth(left: u8, above: u8, corner: u8) -> u8 {
    let estimate = left as i16 + above as i16 - corner as i16;
    let to_left = (estimate - left as i16).abs();
    let to_above = (estimate - above as i16).abs();
    let to_corner = (estimate - corner as i16).abs();
    if to_left <= to_above && to_left <= to_corner {
        left
    } else if to_above <= to_corner {
        above
    } else {
        corner
    }
}

/// Compress with the settings the reference implementation's encoder uses:
/// the default level, the largest window and memory level, and the strategy
/// meant for filtered data.
fn deflate(data: &[u8]) -> Vec<u8> {
    const LEVEL: i32 = -1;
    const WINDOW_BITS: i32 = 15;
    const MEMORY_LEVEL: i32 = 9;
    const FILTERED: i32 = 1;

    // The stream is initialised by zlib itself. Only the allocator hooks and
    // the buffers have to start empty.
    let mut stream = libz_sys::z_stream {
        next_in: std::ptr::null_mut(),
        avail_in: 0,
        total_in: 0,
        next_out: std::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null_mut(),
        state: std::ptr::null_mut(),
        zalloc: zlib_alloc,
        zfree: zlib_free,
        opaque: std::ptr::null_mut(),
        data_type: 0,
        adler: 0,
        reserved: 0,
    };

    unsafe {
        let version = libz_sys::zlibVersion();
        let started = libz_sys::deflateInit2_(
            &mut stream,
            LEVEL,
            libz_sys::Z_DEFLATED,
            WINDOW_BITS,
            MEMORY_LEVEL,
            FILTERED,
            version,
            std::mem::size_of::<libz_sys::z_stream>() as i32,
        );
        if started != libz_sys::Z_OK {
            return Vec::new();
        }

        let mut out = vec![0u8; libz_sys::deflateBound(&mut stream, data.len() as u64) as usize];
        stream.next_in = data.as_ptr() as *mut u8;
        stream.avail_in = data.len() as u32;
        stream.next_out = out.as_mut_ptr();
        stream.avail_out = out.len() as u32;
        let finished = libz_sys::deflate(&mut stream, libz_sys::Z_FINISH);
        let written = out.len() - stream.avail_out as usize;
        libz_sys::deflateEnd(&mut stream);
        if finished != libz_sys::Z_STREAM_END {
            return Vec::new();
        }
        out.truncate(written);
        out
    }
}

// zlib wants somewhere to get its working memory from. Handing it the C
// allocator keeps the two sides of every allocation in the same place.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut std::ffi::c_void;
    fn free(pointer: *mut std::ffi::c_void);
}

unsafe extern "C" fn zlib_alloc(
    _opaque: *mut std::ffi::c_void,
    items: u32,
    size: u32,
) -> *mut std::ffi::c_void {
    unsafe { malloc(items as usize * size as usize) }
}

unsafe extern "C" fn zlib_free(_opaque: *mut std::ffi::c_void, pointer: *mut std::ffi::c_void) {
    unsafe { free(pointer) }
}

/// Append one chunk, with its length, type, payload and checksum.
fn write_chunk(file: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    file.extend_from_slice(&(data.len() as u32).to_be_bytes());
    file.extend_from_slice(kind);
    file.extend_from_slice(data);
    let mut checksum = crc32(0xffff_ffff, kind);
    checksum = crc32(checksum, data);
    file.extend_from_slice(&(checksum ^ 0xffff_ffff).to_be_bytes());
}

/// The checksum every PNG chunk carries.
fn crc32(start: u32, data: &[u8]) -> u32 {
    let mut checksum = start;
    for byte in data {
        checksum ^= *byte as u32;
        for _ in 0..8 {
            checksum = if checksum & 1 != 0 {
                (checksum >> 1) ^ 0xedb8_8320
            } else {
                checksum >> 1
            };
        }
    }
    checksum
}
