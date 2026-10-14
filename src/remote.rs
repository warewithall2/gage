//! Talking to a relay. A hand-rolled HTTP/1.1 client, for the same reason the
//! server is hand-rolled: the whole network surface stays small enough to read.
//!
//! No TLS here, deliberately. Over a tailnet, WireGuard already provides the
//! encrypted channel and there is no public exposure, so a TLS stack would be
//! a second dependency protecting a link that is already protected. And the
//! payload is a sealed box in either case: the relay cannot read it, so the
//! transport is not what the content's confidentiality rests on. Exposing a
//! relay publicly means putting a reverse proxy in front for TLS -- the
//! envelope stays unchanged.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn relay_addr() -> Option<String> {
    let p = crate::identity::home().join("relay");
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn set_relay(addr: &str) -> std::io::Result<()> {
    let dir = crate::identity::home();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("relay"), addr.trim())
}

pub fn post(addr: &str, path: &str, body: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.set_write_timeout(Some(Duration::from_secs(60)))?;
    let host = addr.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no http body"))?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("relay said: {} {}", status.trim(), rest.trim()),
        ));
    }
    Ok(rest.to_string())
}
