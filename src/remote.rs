//! Talking to a relay. A hand-rolled HTTP/1.1 client, for the same reason the
//! server is hand-rolled: the whole network surface stays small enough to
//! read.
//!
//! ## Why there is TLS here now
//!
//! There was not, and the reasoning was sound for what the relay then was: on
//! a tailnet WireGuard already encrypts the link, and the payload is a sealed
//! box in either case, so the relay cannot read it whatever the transport.
//! Neither of those changes once the relay is on the public internet, and
//! neither is the point. What changes is everything *around* the payload:
//!
//! * **The recipient's key is in the request.** `/send` carries `to_box` in
//!   the clear, so anyone on the path learns who you are writing to, how
//!   often, and how big it was. The content stays sealed and the
//!   correspondence does not.
//! * **A relay can be impersonated.** Without a server identity, anything
//!   that can answer for that address can take your push, return
//!   `{"ok":true}`, and drop it. Nothing is readable and nothing is
//!   delivered, and the sender has been told it worked.
//!
//! Signatures cover content; they never covered delivery. So the scheme in
//! the relay address decides: `https://relay.example.com` verifies a
//! certificate against Mozilla's root list, compiled in, `host:port` does not and is for a
//! tailnet or a loopback test. The address is written by the person, so the
//! choice is theirs and it is visible in `gage whoami`-shaped output rather
//! than buried in a default.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether the last TLS read ended without a `close_notify`, so the error
/// message for a short body can say which kind of cut it was.
static TRUNCATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn relay_addr() -> Option<String> {
    let p = crate::identity::home().join("relay");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn set_relay(addr: &str) -> std::io::Result<()> {
    let dir = crate::identity::home();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("relay"), addr.trim())
}

/// How a relay address is to be reached: the host:port to dial, the `Host`
/// header to send, and the TLS name to verify, or `None` for plain HTTP.
///
/// Kept as one function so there is a single place that decides what an
/// address means, and so it can be tested without a network.
pub fn target(addr: &str) -> (String, String, Option<String>) {
    // An IPv6 literal has to keep its brackets in anything that will be
    // parsed as an address: `::1:7788` is not a socket address at all, and
    // the first version of this built exactly that -- with a unit test
    // asserting it, which is a test pinning a bug rather than a property.
    let dial = |host: &str, port: u16| {
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    };
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix("https://") {
        let rest = rest.trim_end_matches('/');
        let (host, port) = split_host_port(rest, 443);
        (dial(host, port), host.to_string(), Some(host.to_string()))
    } else {
        let rest = a.strip_prefix("http://").unwrap_or(a).trim_end_matches('/');
        let (host, port) = split_host_port(rest, 7788);
        let d = dial(host, port);
        (d.clone(), d, None)
    }
}

/// Split `host`, `host:port` or `[v6]:port`. An IPv6 literal has colons of
/// its own, so the last colon is only a port separator when it comes after
/// the closing bracket.
fn split_host_port(s: &str, default_port: u16) -> (&str, u16) {
    if let Some(end) = s.strip_prefix('[').and_then(|_| s.find(']')) {
        let host = &s[1..end];
        let port = s[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host, port);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse().unwrap_or(default_port))
        }
        _ => (s, default_port),
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// One request. The body is JSON; the reply is the JSON body or an error
/// carrying what the relay said.
pub fn post(addr: &str, path: &str, body: &str) -> std::io::Result<String> {
    let (dial, host_header, tls_name) = target(addr);
    let mut sock = TcpStream::connect(&dial)?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let raw = match tls_name {
        None => {
            sock.write_all(req.as_bytes())?;
            sock.write_all(body.as_bytes())?;
            sock.flush()?;
            let mut raw = Vec::new();
            sock.read_to_end(&mut raw)?;
            raw
        }
        Some(name) => {
            let server = rustls_pki_types::ServerName::try_from(name.clone())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("{name} is not a name a certificate can be checked against"),
                    )
                })?
                .to_owned();
            let conn = rustls::ClientConnection::new(tls_config(), server).map_err(|e| {
                std::io::Error::other(format!("could not start TLS with {name}: {e}"))
            })?;
            let mut tls = rustls::StreamOwned::new(conn, sock);
            tls.write_all(req.as_bytes())?;
            tls.write_all(body.as_bytes())?;
            tls.flush()?;
            let mut raw = Vec::new();
            // A server that closes without `close_notify` is common, so it
            // is tolerated -- but it is RECORDED, because the justification
            // the first version gave for swallowing it was false. It said
            // "the response has its own Content-Length and the body below is
            // checked"; nothing below checked any length. A network attacker
            // who cannot forge a certificate could still cut the connection
            // and have a partial body under a 200 status accepted as the
            // relay's whole answer. Verifying the channel says nothing about
            // the completeness of what arrived on it.
            let mut truncated = false;
            match tls.read_to_end(&mut raw) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => truncated = true,
                Err(e) => return Err(e),
            }
            if truncated {
                // Checked against the declared length below rather than
                // trusted. `raw` is returned and the caller's parse will
                // reject a short body; this flag makes the reason sayable.
                TRUNCATED.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            raw
        }
    };

    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no http body"))?;
    // The body is checked against the length the server declared. Without
    // this, a cut connection delivered a partial body under a `200` and it
    // was accepted as the whole answer -- which is what the comment above
    // used to claim was already happening.
    if let Some(want) = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>())
        })
        .and_then(|r| r.ok())
    {
        if rest.len() < want {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "the relay's answer was cut short: {} of {want} bytes{}",
                    rest.len(),
                    if TRUNCATED.swap(false, std::sync::atomic::Ordering::Relaxed) {
                        " (the connection closed without a TLS close_notify)"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    TRUNCATED.store(false, std::sync::atomic::Ordering::Relaxed);
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(std::io::Error::other(format!(
            "relay said: {} {}",
            status.trim(),
            rest.trim()
        )));
    }
    Ok(rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_says_whether_it_is_verified() {
        // The scheme is the whole decision, and it is written by a person.
        // A default that silently chose plain HTTP for `relay.example.com`
        // would be a downgrade nobody saw.
        let (dial, host, tls) = target("https://relay.example.com");
        assert_eq!(dial, "relay.example.com:443");
        assert_eq!(host, "relay.example.com");
        assert_eq!(tls.as_deref(), Some("relay.example.com"));

        let (dial, host, tls) = target("https://relay.example.com:9443/");
        assert_eq!(dial, "relay.example.com:9443");
        // The Host header carries no port for https, because the certificate
        // is checked against the NAME.
        assert_eq!(host, "relay.example.com");
        assert_eq!(tls.as_deref(), Some("relay.example.com"));

        // Bare host:port is the tailnet and loopback case: no TLS, and the
        // Host header keeps the port, which is what the relay has always
        // been sent.
        let (dial, host, tls) = target("100.64.0.1:7788");
        assert_eq!(dial, "100.64.0.1:7788");
        assert_eq!(host, "100.64.0.1:7788");
        assert!(tls.is_none());

        // A bare host gets the project's port rather than 80.
        let (dial, _, tls) = target("127.0.0.1");
        assert_eq!(dial, "127.0.0.1:7788");
        assert!(tls.is_none());
    }

    #[test]
    fn an_ipv6_literal_stays_dialable() {
        // Two separate hazards. `rsplit_once(':')` on `[::1]:7788` would take
        // `1]` as the host -- and then rebuilding it unbracketed gives
        // `::1:7788`, which is not a socket address. The assertion is that
        // the result PARSES, not that it looks a particular way.
        for a in ["[::1]:7788", "http://[2001:db8::5]:9000", "[::1]"] {
            let (dial, _, tls) = target(a);
            assert!(
                dial.parse::<std::net::SocketAddr>().is_ok(),
                "{a} produced {dial}, which is not a socket address"
            );
            assert!(tls.is_none());
        }
        assert_eq!(target("[::1]:7788").0, "[::1]:7788");
        assert_eq!(target("[::1]").0, "[::1]:7788");
    }
}
