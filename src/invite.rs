//! The public `gage add` line, as SVG the page inserts as markup.
//!
//! Display only. Nothing here scans a code, opens a camera, or reads the
//! clipboard. The payload is [`crate::identity::Identity::add_line`] and
//! nothing else: the handle and both public keys, which `gage connect`
//! already prints.
//!
//! The bytes are a fragment. The renderer starts with an XML declaration,
//! and putting that into the HTML document is how a parser drops the
//! element. The `xmlns` is a namespace, not a request. Fills are written
//! out as black on white so a dark page cannot invert the modules.

use qrcode::QrCode;
use qrcode::render::svg;

/// SVG markup for `payload`.
///
/// A bare `<svg>` element. Error correction is the crate's default, medium,
/// and the version is whatever fits, so a long handle is a larger code
/// rather than a refusal at a hard-coded size.
pub fn svg(payload: &str) -> Result<String, String> {
    let code = QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
    let doc = code
        .render::<svg::Color>()
        .dark_color(svg::Color("#000"))
        .light_color(svg::Color("#fff"))
        .quiet_zone(true)
        // 8px is this renderer's own default. Named here so a later default
        // change does not silently shrink the code to one pixel a screen
        // cannot hold. The page scales the result down to the column.
        .module_dimensions(8, 8)
        .build();
    let start = doc
        .find("<svg")
        .ok_or_else(|| "renderer produced no svg element".to_string())?;
    let mut frag = doc[start..].to_string();
    if !frag.starts_with("<svg ") {
        return Err("renderer produced an unexpected svg tag".into());
    }
    // The label names the thing. It does not repeat the line: the line
    // contains the public key, and the markup must not.
    frag.insert_str(5, "role=\"img\" aria-label=\"Public gage add line\" ");
    let end = frag.find('>').ok_or("svg tag is not closed")?;
    frag.insert_str(end + 1, "<title>Public gage add line</title>");
    let lower = frag.to_ascii_lowercase();
    if frag.contains("<?xml")
        || frag.contains("<!DOCTYPE")
        || lower.contains("<script")
        || lower.contains("<img")
        || lower.contains("<foreignobject")
    {
        return Err("svg fragment is not bare markup".into());
    }
    Ok(frag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use ed25519_dalek::SigningKey;

    // `include!` is relative to this file. `#[path]` is relative to a
    // directory the inline module does not have, and `..` through that
    // missing directory does not resolve.
    mod qr_decode {
        include!("../tests/common/qr_decode.rs");
    }

    fn round_trip(line: &str) -> String {
        let picture = svg(line).unwrap_or_else(|e| panic!("encode {line:?}: {e}"));
        let sym = qr_decode::symbol(&picture).unwrap_or_else(|e| panic!("parse: {e}"));
        let code = QrCode::new(line.as_bytes()).unwrap();
        let painted: Vec<bool> = code
            .to_colors()
            .iter()
            .map(|c| c.select(true, false))
            .collect();
        assert_eq!(
            sym.dark, painted,
            "the path is not the symbol the encoder stored"
        );
        qr_decode::decode_modules(sym.n, &sym.dark).unwrap_or_else(|e| panic!("decode: {e}"))
    }

    #[test]
    fn the_svg_is_well_formed() {
        let line = crate::identity::add_line("icy dune", &token([1u8; 32], [2u8; 32]));
        let picture = svg(&line).unwrap();
        assert!(picture.starts_with("<svg "), "{picture}");
        assert!(picture.ends_with("</svg>"));
        assert_eq!(picture.matches("<svg").count(), 1);
        assert_eq!(picture.matches("</svg>").count(), 1);
        assert!(picture.contains("xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(picture.contains("fill=\"#000\""));
        assert!(picture.contains("fill=\"#fff\""));
        assert!(picture.contains("<title>Public gage add line</title>"));
        assert!(!picture.contains("<?xml"));
        assert!(!picture.contains("<!DOCTYPE"));
        assert!(!picture.to_ascii_lowercase().contains("<script"));
        let bare = picture.replace("http://www.w3.org/2000/svg", "");
        assert!(
            !bare.contains("http:") && !bare.contains("https:"),
            "{bare}"
        );
        // The pin. Defaults pull `image`, which this tree does not want.
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains(
                "qrcode = { version = \"0.14.1\", default-features = false, features = [\"svg\"] }"
            ),
            "qrcode pin drifted"
        );
    }

    #[test]
    fn the_encoded_payload_round_trips_to_the_add_line() {
        // Short numeric payload: the annex sample the encoder's own suite
        // draws. Anchors the decoder on a symbol that is not an add line.
        assert_eq!(round_trip("01234567"), "01234567");
        for handle in ["icy dune", "cheerful kingfisher", "o'brien"] {
            let line = crate::identity::add_line(handle, &token([3u8; 32], [4u8; 32]));
            assert_eq!(round_trip(&line), line, "{handle}");
            assert!(line.starts_with("gage add "), "{line}");
        }
    }

    #[test]
    fn a_long_handle_still_encodes() {
        // 40 is the most the page will accept. 64 is past version 8 at
        // error correction M (152 bytes); the line is 163 characters, so
        // this is a version-9 code if the version is chosen rather than
        // clamped.
        let forty = format!("long name {}", "a".repeat(30));
        assert_eq!(forty.len(), 40, "{}", forty.len());
        let line = crate::identity::add_line(&forty, &token([5u8; 32], [6u8; 32]));
        assert_eq!(round_trip(&line), line);

        let sixty_four = "b".repeat(64);
        let line = crate::identity::add_line(&sixty_four, &token([5u8; 32], [6u8; 32]));
        assert!(line.len() > 152, "the long line was {}", line.len());
        let picture = svg(&line).unwrap();
        let sym = qr_decode::symbol(&picture).unwrap();
        let version = (sym.n - 17) / 4;
        assert!(
            version >= 9,
            "version {version}, {} modules, line is {} bytes",
            sym.n,
            line.len()
        );
        assert_eq!(qr_decode::decode_modules(sym.n, &sym.dark).unwrap(), line);
    }

    #[test]
    fn nothing_in_the_output_contains_a_key_or_a_passphrase() {
        let sign_seed = [0x11u8; 32];
        let box_seed = [0x22u8; 32];
        let secret_sign = B64.encode(sign_seed);
        let secret_box = B64.encode(box_seed);
        let passphrase = "correct horse battery staple";
        let public = token(sign_seed, box_seed);
        let line = crate::identity::add_line("cheerful kingfisher", &public);
        // The line is safe to read aloud: the handle and the public token.
        // The seeds that `identity.key` stores are not it.
        assert!(
            !line.contains(&secret_sign),
            "add line contains the signing seed"
        );
        assert!(
            !line.contains(&secret_box),
            "add line contains the encryption seed"
        );
        assert!(!line.contains(passphrase));
        assert!(!line.contains("passphrase"));
        let picture = svg(&line).unwrap();
        assert_eq!(round_trip(&line), line);
        for secret in [
            &secret_sign,
            &secret_box,
            passphrase,
            "passphrase",
            "sign_seed",
            "box_secret",
            "identity.key",
            &public,
        ] {
            assert!(!picture.contains(secret), "svg markup contains {secret}");
        }
    }

    /// The public token `full_key` is: signing key, dot, encryption key.
    fn token(sign_seed: [u8; 32], box_seed: [u8; 32]) -> String {
        let signing = SigningKey::from_bytes(&sign_seed);
        let sealing = crypto_box::SecretKey::from_bytes(box_seed);
        format!(
            "{}.{}",
            B64.encode(signing.verifying_key().to_bytes()),
            B64.encode(sealing.public_key().as_bytes())
        )
    }
}
