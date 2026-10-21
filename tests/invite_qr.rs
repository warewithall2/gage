//! The served invite, against a real identity in a throwaway home.
//!
//! The decoder and the exact-string check live next to `svg()`. This file
//! checks the thing those tests cannot see without touching process-global
//! environment: what `gage ui` actually writes on the wire, and that the
//! key file's secrets are not in it. The home is set on the child only.
//! `GAGE_HOME`, `COUNTERSIGN_HOME` and `CTX_HOME` all point at the same
//! temporary directory, so a home-selection bug still cannot write the
//! user's real identity.

#[path = "common/qr_decode.rs"]
mod qr_decode;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    home: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // The live services own these. An ephemeral port should not be either.
    assert!(port != 7777 && port != 7791, "ephemeral port landed on a live service");
    port
}

fn gage(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gage"))
        .args(args)
        .env("GAGE_HOME", home)
        .env("COUNTERSIGN_HOME", home)
        .env("CTX_HOME", home)
        .output()
        .unwrap_or_else(|e| panic!("spawn gage: {e}"))
}

fn serve(home: &std::path::Path, port: u16) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gage"))
        .args(["ui", "--port", &port.to_string()])
        .env("GAGE_HOME", home)
        .env("COUNTERSIGN_HOME", home)
        .env("CTX_HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn ui: {e}"));
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    if got.contains(&b'\n') {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(got);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(8))
        .unwrap_or_else(|_| panic!("ui did not announce itself"));
    let line = String::from_utf8_lossy(&line);
    assert!(
        line.contains(&format!("127.0.0.1:{port}")),
        "ui said {line:?}"
    );
    child
}

fn http(port: u16, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

fn field<'a>(raw: &'a str, key: &str) -> &'a str {
    // Pretty-printed JSON: `"sign_seed": "..."`, with a space after the colon.
    let pat = format!("\"{key}\"");
    let i = raw
        .find(&pat)
        .unwrap_or_else(|| panic!("no {key} in identity.key: {raw}"));
    let rest = raw[i + pat.len()..].trim_start();
    let rest = rest
        .strip_prefix(':')
        .unwrap_or_else(|| panic!("{key} has no colon"))
        .trim_start();
    let rest = rest
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("{key} is not a string"));
    let end = rest.find('"').unwrap_or_else(|| panic!("{key} is not closed"));
    &rest[..end]
}

#[test]
fn the_served_svg_is_the_add_line_and_not_the_key_file() {
    let home = std::env::temp_dir().join(format!("gage-invite-{}-{}", std::process::id(), free_port()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let init = gage(&home, &["init", "icy dune"]);
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));
    let key_file = std::fs::read_to_string(home.join("identity.key")).unwrap();
    let sign_seed = field(&key_file, "sign_seed");
    let box_secret = field(&key_file, "box_secret");
    assert!(sign_seed.len() >= 40 && box_secret.len() >= 40);
    let who = gage(&home, &["whoami"]);
    assert!(who.status.success(), "whoami: {}", String::from_utf8_lossy(&who.stderr));
    let line = String::from_utf8_lossy(&who.stdout);
    let (handle, full_key) = line
        .lines()
        .next()
        .unwrap_or("")
        .split_once('\t')
        .unwrap_or_else(|| panic!("whoami stdout: {line:?}"));
    assert_eq!(handle, "icy dune");
    let expected = format!("gage add 'icy dune' {full_key}");

    let port = free_port();
    let server = Server {
        child: serve(&home, port),
        home: home.clone(),
    };
    let (status, head, body) = http(port, "/api/invite");
    assert_eq!(status, 200, "{head}\n{body}");
    assert!(head.to_ascii_lowercase().contains("content-type: image/svg+xml"));
    assert!(body.starts_with("<svg ") && body.ends_with("</svg>"));
    assert!(!body.contains("<?xml") && !body.contains("<!DOCTYPE"));
    assert!(!body.to_ascii_lowercase().contains("<script"));
    let bare = body.replace("http://www.w3.org/2000/svg", "");
    assert!(!bare.contains("http:") && !bare.contains("https:"));
    for secret in [sign_seed, box_secret, "passphrase", "sign_seed", "box_secret", full_key] {
        assert!(!body.contains(secret), "served svg contains {secret}");
    }
    assert!(!body.contains(&key_file));
    let sym = qr_decode::symbol(&body).unwrap_or_else(|e| panic!("parse served svg: {e}"));
    let got = qr_decode::decode_modules(sym.n, &sym.dark).unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(got, expected);

    let (page_status, _, page) = http(port, "/");
    assert_eq!(page_status, 200);
    assert!(page.contains("fetch('/api/invite')"));
    assert!(!page.contains("http://") && !page.contains("https://"));
    assert!(!page.contains("<img"));

    // A home with no identity does not invent a code, and does not name the path.
    let empty = std::env::temp_dir().join(format!("gage-invite-empty-{}-{}", std::process::id(), port));
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir_all(&empty).unwrap();
    let empty_port = free_port();
    let empty_server = Server {
        child: serve(&empty, empty_port),
        home: empty,
    };
    let (status, _, body) = http(empty_port, "/api/invite");
    assert_eq!(status, 404, "{body}");
    assert!(!body.contains("identity.key"));
    drop(empty_server);
    drop(server);
}
