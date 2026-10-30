// Decode an undamaged QR symbol from the SVG this crate's renderer emits.
//
// Test-only, and not a scanner. The product never calls it. It exists so
// `decode(encode(add line))` can be the add line, checked on every machine
// `cargo test` runs on, without a second crate and without a system library
// that macOS may not have.
//
// The tables stop at version 15. That is this decoder's limit. The encoder
// is the `qrcode` crate and is not capped here. A symbol past version 15
// fails this decode rather than being read as something else.
//
// Block sizes and format strings are ISO/IEC 18004 Table 9 and the format
// information. Mask formulas are the eight data masks. A wrong table fails
// the exact-string check; it does not pass.

pub struct Symbol {
    pub n: usize,
    pub dark: Vec<bool>,
}

pub fn symbol(svg: &str) -> Result<Symbol, String> {
    if !svg.starts_with("<svg ") || !svg.ends_with("</svg>") {
        return Err("not a bare svg element".into());
    }
    let width = attr_usize(svg, "width")?;
    let height = attr_usize(svg, "height")?;
    if width != height || width == 0 || width > 4096 {
        return Err(format!("svg size {width}x{height}"));
    }
    let mut rects = Vec::new();
    let path = path_data(svg)?;
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'M' {
            return Err(format!("path byte {} is not a move", bytes[i]));
        }
        i += 1;
        let (x, i2) = take_int(bytes, i)?;
        i = i2;
        if bytes.get(i) != Some(&b' ') {
            return Err("move is missing a space".into());
        }
        i += 1;
        let (y, i2) = take_int(bytes, i)?;
        i = i2;
        if bytes.get(i) != Some(&b'h') {
            return Err("expected h".into());
        }
        i += 1;
        let (w, i2) = take_int(bytes, i)?;
        i = i2;
        if bytes.get(i) != Some(&b'v') {
            return Err("expected v".into());
        }
        i += 1;
        let (h, i2) = take_int(bytes, i)?;
        i = i2;
        if bytes.get(i) != Some(&b'H') {
            return Err("expected H".into());
        }
        i += 1;
        let (_, i2) = take_int(bytes, i)?;
        i = i2;
        if bytes.get(i) != Some(&b'V') {
            return Err("expected V".into());
        }
        i += 1;
        let (_, i2) = take_int(bytes, i)?;
        i = i2;
        if w == 0 || h == 0 || x >= width || y >= height {
            return Err(format!("rect {x},{y} {w}x{h} outside {width}"));
        }
        rects.push((x, y, w, h));
    }
    if rects.is_empty() {
        return Err("svg path draws nothing".into());
    }
    // The renderer draws one rectangle per dark module. Its default module
    // is 8px, not 1. Every edge here is a multiple of that module.
    let m = rects.iter().map(|r| r.2.min(r.3)).min().unwrap();
    if m == 0 || width % m != 0 {
        return Err(format!("module size {m} does not divide width {width}"));
    }
    let cells = width / m;
    let mut pixels = vec![false; cells * cells];
    for (x, y, w, h) in rects {
        if x % m != 0 || y % m != 0 || w % m != 0 || h % m != 0 {
            return Err(format!("rect {x},{y} {w}x{h} is not on the {m}px grid"));
        }
        let (cx, cy, cw, ch) = (x / m, y / m, w / m, h / m);
        for dy in 0..ch {
            for dx in 0..cw {
                let px = cx + dx;
                let py = cy + dy;
                if px >= cells || py >= cells {
                    return Err(format!("module {px},{py} outside {cells}"));
                }
                pixels[py * cells + px] = true;
            }
        }
    }
    // Quiet zone is four modules. The corner cell is the white background,
    // and the finder starts inside it.
    const QZ: usize = 4;
    if cells <= QZ * 2 {
        return Err("svg is smaller than a quiet zone".into());
    }
    let n = cells - QZ * 2;
    if n < 21 || (n - 17) % 4 != 0 {
        return Err(format!("{n} modules is not a QR version"));
    }
    if pixels[0] {
        return Err("quiet-zone corner is dark".into());
    }
    if !pixels[QZ * cells + QZ] {
        return Err("finder corner is light".into());
    }
    let mut dark = vec![false; n * n];
    for y in 0..n {
        for x in 0..n {
            dark[y * n + x] = pixels[(y + QZ) * cells + (x + QZ)];
        }
    }
    Ok(Symbol { n, dark })
}

pub fn decode_modules(n: usize, dark: &[bool]) -> Result<String, String> {
    if dark.len() != n * n {
        return Err("module grid has the wrong length".into());
    }
    if n < 21 || (n - 17) % 4 != 0 {
        return Err(format!("{n} is not a QR width"));
    }
    let version = ((n - 17) / 4) as i16;
    if !(1..=15).contains(&version) {
        return Err(format!("version {version} is past this decoder's table"));
    }
    let (ec, mask) = format_info(dark, n)?;
    let (d1, c1, d2, c2, _ec_bytes) = blocks(version, ec)?;
    let data_bytes = d1 * c1 + d2 * c2;
    let raw = read_data(dark, n, version, mask, data_bytes)?;
    let data = deinterleave(&raw, d1, c1, d2, c2)?;
    let bytes = read_payload(&data, version)?;
    String::from_utf8(bytes).map_err(|_| "payload is not utf-8".into())
}

fn attr_usize(svg: &str, name: &str) -> Result<usize, String> {
    let key = format!(" {name}=\"");
    let i = svg.find(&key).ok_or_else(|| format!("no {name}"))?;
    let rest = &svg[i + key.len()..];
    let end = rest
        .find('"')
        .ok_or_else(|| format!("{name} is not quoted"))?;
    rest[..end].parse().map_err(|_| format!("bad {name}"))
}

fn path_data(svg: &str) -> Result<&str, String> {
    let key = " d=\"";
    let i = svg.find(key).ok_or("svg has no path")?;
    let rest = &svg[i + key.len()..];
    let end = rest.find('"').ok_or("path is not closed")?;
    Ok(&rest[..end])
}

fn take_int(bytes: &[u8], mut i: usize) -> Result<(usize, usize), String> {
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return Err("expected a number".into());
    }
    let n: usize = std::str::from_utf8(&bytes[start..i])
        .map_err(|_| "number is not utf-8")?
        .parse()
        .map_err(|_| "number does not fit")?;
    Ok((n, i))
}

fn format_info(dark: &[bool], n: usize) -> Result<(u8, u8), String> {
    let n = n as i32;
    let main = [
        (0, 8),
        (1, 8),
        (2, 8),
        (3, 8),
        (4, 8),
        (5, 8),
        (7, 8),
        (8, 8),
        (8, 7),
        (8, 5),
        (8, 4),
        (8, 3),
        (8, 2),
        (8, 1),
        (8, 0),
    ];
    let mut side = [(0i32, 0i32); 15];
    for i in 0..7 {
        side[i] = (8, n - 1 - i as i32);
    }
    for i in 0..8 {
        side[7 + i] = (n - 8 + i as i32, 8);
    }
    let a = format_value(dark, n as usize, &main);
    let b = format_value(dark, n as usize, &side);
    let idx = FORMAT
        .iter()
        .position(|v| *v == a)
        .or_else(|| FORMAT.iter().position(|v| *v == b))
        .ok_or_else(|| format!("format info {a:#06x} / {b:#06x} is not a format string"))?;
    if a != b && FORMAT.contains(&a) && FORMAT.contains(&b) && a != b {
        return Err("the two format copies disagree".into());
    }
    let ec = ((idx >> 3) ^ 1) as u8;
    let mask = (idx & 7) as u8;
    Ok((ec, mask))
}

fn format_value(dark: &[bool], n: usize, coords: &[(i32, i32)]) -> u16 {
    let mut v = 0u16;
    for (i, &(x, y)) in coords.iter().enumerate() {
        if dark[(y as usize) * n + (x as usize)] {
            v |= 1 << (14 - i);
        }
    }
    v
}

/// Index is `((ec ^ 1) << 3) | mask` with L=0, M=1, Q=2, H=3.
const FORMAT: [u16; 32] = [
    0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0, 0x77c4, 0x72f3, 0x7daa, 0x789d,
    0x662f, 0x6318, 0x6c41, 0x6976, 0x1689, 0x13be, 0x1ce7, 0x19d0, 0x0762, 0x0255, 0x0d0c, 0x083b,
    0x355f, 0x3068, 0x3f31, 0x3a06, 0x24b4, 0x2183, 0x2eda, 0x2bed,
];

fn mask_flips(mask: u8, x: i32, y: i32) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (y / 2 + x / 3) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
        _ => false,
    }
}

fn functional(version: i16, n: i32, x: i32, y: i32) -> bool {
    if x == 6 || y == 6 {
        return true;
    }
    if (x < 9 && y < 9) || (x < 9 && y >= n - 8) || (x >= n - 8 && y < 9) {
        return true;
    }
    if version >= 7
        && ((x <= 5 && (n - 11..=n - 9).contains(&y)) || (y <= 5 && (n - 11..=n - 9).contains(&x)))
    {
        return true;
    }
    let centers = alignment_centers(version);
    if centers.is_empty() {
        return false;
    }
    let last = centers.len() - 1;
    for (i, &cx) in centers.iter().enumerate() {
        for (j, &cy) in centers.iter().enumerate() {
            if (i == 0 && (j == 0 || j == last)) || (i == last && j == 0) {
                continue;
            }
            if (cx - x).abs() <= 2 && (cy - y).abs() <= 2 {
                return true;
            }
        }
    }
    false
}

fn alignment_centers(version: i16) -> &'static [i32] {
    match version {
        2 => &[6, 18],
        3 => &[6, 22],
        4 => &[6, 26],
        5 => &[6, 30],
        6 => &[6, 34],
        7 => &[6, 22, 38],
        8 => &[6, 24, 42],
        9 => &[6, 26, 46],
        10 => &[6, 28, 50],
        11 => &[6, 30, 54],
        12 => &[6, 32, 58],
        13 => &[6, 34, 62],
        14 => &[6, 26, 46, 66],
        15 => &[6, 26, 48, 70],
        _ => &[],
    }
}

fn zigzag(n: usize) -> Vec<(usize, usize)> {
    let n = n as i32;
    let mut out = Vec::new();
    let mut right = n - 1;
    let mut up = true;
    while right > 0 {
        if right == 6 {
            right -= 1;
        }
        if right <= 0 {
            break;
        }
        let mut y = if up { n - 1 } else { 0 };
        let step = if up { -1 } else { 1 };
        for _ in 0..n {
            out.push((right as usize, y as usize));
            out.push(((right - 1) as usize, y as usize));
            y += step;
        }
        up = !up;
        right -= 2;
    }
    out
}

fn read_data(
    dark: &[bool],
    n: usize,
    version: i16,
    mask: u8,
    nbytes: usize,
) -> Result<Vec<u8>, String> {
    let need = nbytes * 8;
    let mut bits = Vec::with_capacity(need);
    for (x, y) in zigzag(n) {
        if functional(version, n as i32, x as i32, y as i32) {
            continue;
        }
        let on = dark[y * n + x] ^ mask_flips(mask, x as i32, y as i32);
        bits.push(on);
        if bits.len() == need {
            break;
        }
    }
    if bits.len() < need {
        return Err(format!("only {} data bits, need {need}", bits.len()));
    }
    let mut out = vec![0u8; nbytes];
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Ok(out)
}

/// `(data_len, count, data_len_2, count_2, ec_per_block)`, EC order L M Q H.
fn blocks(version: i16, ec: u8) -> Result<(usize, usize, usize, usize, usize), String> {
    // ISO/IEC 18004:2006 Table 9, versions 1–15. Column order is L, M, Q, H.
    const DATA: [[(usize, usize, usize, usize); 4]; 15] = [
        [(19, 1, 0, 0), (16, 1, 0, 0), (13, 1, 0, 0), (9, 1, 0, 0)],
        [(34, 1, 0, 0), (28, 1, 0, 0), (22, 1, 0, 0), (16, 1, 0, 0)],
        [(55, 1, 0, 0), (44, 1, 0, 0), (17, 2, 0, 0), (13, 2, 0, 0)],
        [(80, 1, 0, 0), (32, 2, 0, 0), (24, 2, 0, 0), (9, 4, 0, 0)],
        [
            (108, 1, 0, 0),
            (43, 2, 0, 0),
            (15, 2, 16, 2),
            (11, 2, 12, 2),
        ],
        [(68, 2, 0, 0), (27, 4, 0, 0), (19, 4, 0, 0), (15, 4, 0, 0)],
        [(78, 2, 0, 0), (31, 4, 0, 0), (14, 2, 15, 4), (13, 4, 14, 1)],
        [
            (97, 2, 0, 0),
            (38, 2, 39, 2),
            (18, 4, 19, 2),
            (14, 4, 15, 2),
        ],
        [
            (116, 2, 0, 0),
            (36, 3, 37, 2),
            (16, 4, 17, 4),
            (12, 4, 13, 4),
        ],
        [
            (68, 2, 69, 2),
            (43, 4, 44, 1),
            (19, 6, 20, 2),
            (15, 6, 16, 2),
        ],
        [
            (81, 4, 0, 0),
            (50, 1, 51, 4),
            (22, 4, 23, 4),
            (12, 3, 13, 8),
        ],
        [
            (92, 2, 93, 2),
            (36, 6, 37, 2),
            (20, 4, 21, 6),
            (14, 7, 15, 4),
        ],
        [
            (107, 4, 0, 0),
            (37, 8, 38, 1),
            (20, 8, 21, 4),
            (11, 12, 12, 4),
        ],
        [
            (115, 3, 116, 1),
            (40, 4, 41, 5),
            (16, 11, 17, 5),
            (12, 11, 13, 5),
        ],
        [
            (87, 5, 88, 1),
            (41, 5, 42, 5),
            (24, 5, 25, 7),
            (12, 11, 13, 7),
        ],
    ];
    const EC: [[usize; 4]; 15] = [
        [7, 10, 13, 17],
        [10, 16, 22, 28],
        [15, 26, 18, 22],
        [20, 18, 26, 16],
        [26, 24, 18, 22],
        [18, 16, 24, 28],
        [20, 18, 18, 26],
        [24, 22, 22, 26],
        [30, 22, 20, 24],
        [18, 26, 24, 28],
        [20, 30, 28, 24],
        [24, 22, 26, 28],
        [26, 22, 24, 22],
        [30, 24, 20, 24],
        [22, 24, 30, 24],
    ];
    let v = usize::try_from(version).map_err(|_| "bad version")?;
    let e = usize::from(ec);
    if !(1..=15).contains(&version) || e > 3 {
        return Err(format!("no block table for version {version} ec {ec}"));
    }
    let (d1, c1, d2, c2) = DATA[v - 1][e];
    Ok((d1, c1, d2, c2, EC[v - 1][e]))
}

fn deinterleave(raw: &[u8], d1: usize, c1: usize, d2: usize, c2: usize) -> Result<Vec<u8>, String> {
    let n = c1 + c2;
    if n == 0 {
        return Err("no blocks".into());
    }
    let mut lens = Vec::with_capacity(n);
    lens.extend(std::iter::repeat_n(d1, c1));
    lens.extend(std::iter::repeat_n(d2, c2));
    let total: usize = lens.iter().sum();
    if raw.len() < total {
        return Err(format!(
            "have {} data bytes, blocks need {total}",
            raw.len()
        ));
    }
    let mut blocks: Vec<Vec<u8>> = lens.iter().map(|&len| Vec::with_capacity(len)).collect();
    let max = lens.iter().copied().max().unwrap_or(0);
    let mut idx = 0;
    for i in 0..max {
        for (b, &len) in lens.iter().enumerate() {
            if i < len {
                blocks[b].push(raw[idx]);
                idx += 1;
            }
        }
    }
    if idx != total {
        return Err("deinterleave did not consume the data bytes".into());
    }
    Ok(blocks.into_iter().flatten().collect())
}

fn read_payload(data: &[u8], version: i16) -> Result<Vec<u8>, String> {
    let mut i = 0;
    let bit = |data: &[u8], i: &mut usize, n: usize| -> Option<u32> {
        if *i + n > data.len() * 8 {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let byte = data[*i / 8];
            let one = (byte >> (7 - (*i % 8))) & 1;
            v = (v << 1) | u32::from(one);
            *i += 1;
        }
        Some(v)
    };
    let mut out = Vec::new();
    loop {
        let left = data.len() * 8 - i;
        if left < 4 {
            break;
        }
        let mode = bit(data, &mut i, 4).ok_or("truncated mode")?;
        if mode == 0 {
            break;
        }
        match mode {
            0b0001 => {
                let count_bits = if version <= 9 { 10 } else { 12 };
                let len = bit(data, &mut i, count_bits).ok_or("truncated numeric count")? as usize;
                let mut left_digits = len;
                while left_digits > 0 {
                    let (nbits, width) = if left_digits >= 3 {
                        (10, 3)
                    } else if left_digits == 2 {
                        (7, 2)
                    } else {
                        (4, 1)
                    };
                    let v = bit(data, &mut i, nbits).ok_or("truncated numeric")?;
                    let s = format!("{:0width$}", v, width = width);
                    out.extend(s.into_bytes());
                    left_digits -= width;
                }
            }
            0b0010 => {
                let count_bits = if version <= 9 { 9 } else { 11 };
                let len = bit(data, &mut i, count_bits).ok_or("truncated alnum count")? as usize;
                let mut left_chars = len;
                while left_chars >= 2 {
                    let v = bit(data, &mut i, 11).ok_or("truncated alnum")? as usize;
                    out.push(ALNUM[v / 45]);
                    out.push(ALNUM[v % 45]);
                    left_chars -= 2;
                }
                if left_chars == 1 {
                    let v = bit(data, &mut i, 6).ok_or("truncated alnum")? as usize;
                    out.push(ALNUM[v]);
                }
            }
            0b0100 => {
                let count_bits = if version <= 9 { 8 } else { 16 };
                let len = bit(data, &mut i, count_bits).ok_or("truncated byte count")? as usize;
                for _ in 0..len {
                    out.push(bit(data, &mut i, 8).ok_or("truncated byte")? as u8);
                }
            }
            other => {
                return Err(format!(
                    "mode {other:#x} is not numeric, alphanumeric, or byte"
                ));
            }
        }
    }
    Ok(out)
}

const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
