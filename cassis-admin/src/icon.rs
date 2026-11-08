//! The admin page's icon: a square of the daemon's color, as a PNG
//! `data:` URL, which every renderer shows.

use base64::Engine;

/// Pixels per side.
const SIZE: u32 = 16;

/// A square of the color of `hue` (degrees), as a `data:` URL.
pub fn square(hue: u16) -> String {
    let rgb = hsl(hue, 0.6, 0.5);
    let row: Vec<u8> = std::iter::once(0) // no filter
        .chain((0..SIZE).flat_map(|_| rgb))
        .collect();
    let pixels = row.repeat(SIZE as usize);
    let mut header = Vec::new();
    header.extend(SIZE.to_be_bytes());
    header.extend(SIZE.to_be_bytes());
    header.extend([8, 2, 0, 0, 0]); // 8-bit RGB, no interlace
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut png, b"IHDR", &header);
    chunk(&mut png, b"IDAT", &zlib_stored(&pixels));
    chunk(&mut png, b"IEND", &[]);
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}

fn hsl(hue: u16, saturation: f64, lightness: f64) -> [u8; 3] {
    let chroma = (1.0 - (2.0 * lightness - 1.0).abs()) * saturation;
    let h = f64::from(hue % 360) / 60.0;
    let x = chroma * (1.0 - (h % 2.0 - 1.0).abs());
    let (r, g, b) = match h as u8 {
        0 => (chroma, x, 0.0),
        1 => (x, chroma, 0.0),
        2 => (0.0, chroma, x),
        3 => (0.0, x, chroma),
        4 => (x, 0.0, chroma),
        _ => (chroma, 0.0, x),
    };
    let m = lightness - chroma / 2.0;
    [r, g, b].map(|c| ((c + m) * 255.0).round() as u8)
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend((data.len() as u32).to_be_bytes());
    let start = png.len();
    png.extend(kind);
    png.extend(data);
    let crc = crc32(&png[start..]);
    png.extend(crc.to_be_bytes());
}

/// `data` in a zlib stream of uncompressed deflate blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = data.chunks(u16::MAX as usize).collect();
    for (at, block) in blocks.iter().enumerate() {
        out.push(u8::from(at + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(*block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    out.extend(((b << 16) | a).to_be_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_and_colors() {
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
        assert_eq!(hsl(0, 1.0, 0.5), [255, 0, 0]);
        assert_eq!(hsl(240, 1.0, 0.5), [0, 0, 255]);
        assert!(square(200).starts_with("data:image/png;base64,iVBORw0KGgo"));
    }
}
