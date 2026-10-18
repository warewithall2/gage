//! LAN discovery: where a key is reachable, never whose key it is.
//!
//! LocalSend's experience without LocalSend's identity model, which is the
//! whole point of [docs/lan-discovery-design.md]. There, a peer is a device
//! name the device chose, and anyone on the network can claim "Owen's
//! Laptop". That is fine for one expected file and not fine for instructions
//! an agent may act on later under a grant, so the two jobs stay separate:
//!
//! - **Discovery answers where.** A UDP packet says "this key is reachable at
//!   this port". It is a hint about an address and never a claim about a
//!   person. Every packet is signed by the key it names, so a bystander
//!   cannot announce somebody else's key at their own address and swallow
//!   their mail -- but a signature only proves the announcer holds that key,
//!   which is exactly as much as an address hint should prove.
//! - **Trust answers who**, and it answers it where it always has: the
//!   receiver's own contact list, keyed on the key, after a human compared a
//!   fingerprint once. `pair` is that one moment and cannot be optimised
//!   away.
//!
//! There is deliberately **no standing announcement**. The README says "no
//! server, no presence, no accounts", and a laptop broadcasting its handle
//! and public key onto every café network it joins would have quietly made
//! that false. So announcing is a time-boxed mode you ask for -- `gage nearby
//! --announce 60` shouts for a minute and stops -- and afterwards finding a
//! paired machine is a *query* rather than a broadcast of your existence.
//!
//! The query has the property that makes the presence objection go away: a
//! listener answers only a query signed by a key already on its list. A
//! stranger who sends one gets silence, and cannot tell silence from an empty
//! network. What the query does reveal, honestly, is that *somebody holding
//! this public key is looking for someone*, to anyone sniffing the segment at
//! that moment. The key being sought is sent as a salted hash rather than in
//! the clear, so the pair of you is not on the wire; the asker's own key is,
//! because the signature is what makes answering safe. That is a cost at the
//! moment you deliberately send, not a standing broadcast.
//!
//! Three ports, split so the two modes never fight over one socket:
//!
//! | port     | who binds it            | what it is for               |
//! |----------|-------------------------|------------------------------|
//! | 7789/udp | `gage nearby`            | pairing announcements        |
//! | 7790/udp | `gage listen`            | address queries, known keys only |
//! | 7791/tcp | `gage listen`            | a sealed envelope arriving   |

use crate::identity::Identity;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Pairing announcements. Bound only while `gage nearby` runs.
pub const ANNOUNCE_PORT: u16 = 7789;
/// Address queries. Answered only for keys already on the list.
pub const QUERY_PORT: u16 = 7790;
/// Where a sealed envelope lands.
pub const LISTEN_PORT: u16 = 7791;

/// A deliberate test seam, and the only one in the module.
///
/// Discovery is two machines on a physical network, which is precisely the
/// kind of surface that goes untested and then breaks in the one place a
/// human touches -- as the viewer did, the same day this was written. Two
/// ctx homes on one host cannot both bind a fixed port, so the ports and the
/// broadcast address come from the environment when it sets them. That makes
/// the real announce, query and answer paths runnable on loopback.
///
/// It is not a back door: every one of these only decides WHERE packets go.
/// Nothing about who may be answered, or what a signature must cover, can be
/// reached from here.
fn env_u16(k: &str, default: u16) -> u16 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Where announcements are heard, and where they are sent. The same port on
/// a real network; different ones on loopback, so two homes on one host are
/// not fighting over one socket.
fn announce_bind() -> u16 {
    env_u16("CTX_LAN_ANNOUNCE_BIND", ANNOUNCE_PORT)
}

fn announce_dest() -> u16 {
    env_u16("CTX_LAN_ANNOUNCE_DEST", announce_bind())
}

fn query_bind() -> u16 {
    env_u16("CTX_LAN_QUERY_BIND", QUERY_PORT)
}

fn query_dest() -> u16 {
    env_u16("CTX_LAN_QUERY_DEST", query_bind())
}

/// This machine's address on the network it would use to reach the world.
///
/// A connected UDP socket, which sends nothing: `connect` on a datagram
/// socket only fixes the route, and the kernel then reports which local
/// address that route would use. No packet leaves, and the address it is
/// pointed at is never contacted.
fn local_ip() -> Option<std::net::IpAddr> {
    let s = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect(("1.1.1.1", 9)).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Every address worth sending one announcement to.
///
/// Two, because one of them does not work everywhere. `255.255.255.255` is
/// the all-hosts broadcast and is what Linux wants; macOS and the BSDs
/// generally refuse it outright with "can't assign requested address" unless
/// the socket is bound to a specific interface, and want the
/// subnet-directed form (`192.168.1.255`) instead. Sending to both costs one
/// extra datagram and removes a platform question from the one command a
/// person runs first.
///
/// The subnet address assumes a /24, because reading the real netmask means
/// `getifaddrs` and a libc dependency for one number. A wrong guess sends a
/// packet nowhere; it does not break the other destination. `CTX_LAN_BCAST`
/// replaces the whole list, which is how the test suite puts both homes on
/// loopback and how an unusual network can be pointed at by hand.
pub fn bcast_targets() -> Vec<String> {
    if let Ok(v) = std::env::var("CTX_LAN_BCAST") {
        return vec![v];
    }
    let mut out = vec!["255.255.255.255".to_string()];
    if let Some(std::net::IpAddr::V4(ip)) = local_ip() {
        let o = ip.octets();
        if o[0] != 127 {
            out.push(format!("{}.{}.{}.255", o[0], o[1], o[2]));
        }
    }
    out
}

/// A datagram is one packet, so this caps what a stranger can make us parse.
const MAX_PACKET: usize = 2048;
/// How far out of step a packet's clock may be. A recorded announcement
/// replayed next week is then not an address hint any more.
const MAX_SKEW: u64 = 120;

#[derive(Serialize, Deserialize, Clone)]
pub struct Packet {
    /// `announce` | `query` | `here`. Inside the signature, so a query
    /// cannot be replayed as an announcement.
    pub t: String,
    /// Decoration, exactly as everywhere else in ctx: a string the sender
    /// chose. Shown in quotes and never matched on.
    #[serde(default)]
    pub handle: String,
    /// ed25519 public key of whoever signed this packet.
    pub sign: String,
    #[serde(default)]
    pub boxpub: String,
    #[serde(default)]
    pub port: u16,
    pub at: u64,
    /// On a `query`: sha256(wanted signing key + nonce). A hash rather than
    /// the key itself, so the LAN does not learn who you are sending to --
    /// only the intended recipient can recompute it.
    #[serde(default)]
    pub want: String,
    #[serde(default)]
    pub nonce: String,
    pub sig: String,
}

/// The exact bytes signed, with every field length-prefixed.
///
/// Not pipe-joined: `handle` is attacker-chosen text, and a handle containing
/// the separator could otherwise shift the field boundaries so that two
/// different packets produced the same signing input. Length prefixes make
/// the encoding unambiguous for free.
fn signed_bytes(p: &Packet) -> Vec<u8> {
    let mut out = b"ctx-lan-1".to_vec();
    for f in [
        p.t.as_str(),
        p.handle.as_str(),
        p.sign.as_str(),
        p.boxpub.as_str(),
        &p.port.to_string(),
        &p.at.to_string(),
        p.want.as_str(),
        p.nonce.as_str(),
    ] {
        out.extend_from_slice(f.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(f.as_bytes());
    }
    out
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What a wanted key looks like on the wire, hashed with the query's nonce.
pub fn want_tag(sign_key: &str, nonce: &str) -> String {
    crate::bundle::sha256_hex(format!("ctx-lan-want|{}|{}", sign_key.trim(), nonce).as_bytes())
}

/// A fresh nonce, or None when the system cannot provide randomness.
///
/// No zero-byte fallback: a constant nonce would make `want_tag` a fixed
/// value per recipient, which is the leak the hash exists to prevent, and
/// would let a recorded `here` be replayed as an answer to a later query.
pub fn new_nonce() -> Option<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut buf = [0u8; 18];
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    f.read_exact(&mut buf).ok()?;
    Some(B64.encode(buf))
}

fn sign_packet(id: &Identity, mut p: Packet) -> Packet {
    p.sig = id.sign_b64(&signed_bytes(&p));
    p
}

/// Parse and check a datagram, or say why it is being ignored.
///
/// Every reason is a silent drop at the call sites: a discovery socket is
/// reachable by anyone on the segment, and a parse error it narrates is a
/// parse error somebody can use to find out it is there.
pub fn parse(raw: &[u8]) -> Option<Packet> {
    if raw.len() > MAX_PACKET {
        return None;
    }
    let p: Packet = serde_json::from_slice(raw).ok()?;
    if !matches!(p.t.as_str(), "announce" | "query" | "here") {
        return None;
    }
    if !crate::bundle::b64_decode_ok(&p.sign) {
        return None;
    }
    // The clock check comes before the signature only in cost: a valid
    // signature over a week-old packet is still a replay.
    let n = now();
    if p.at.abs_diff(n) > MAX_SKEW {
        return None;
    }
    if !crate::identity::verify(&p.sign, &signed_bytes(&p), &p.sig) {
        return None;
    }
    Some(p)
}

/// What a peer looked like on the wire. `addr` comes from the UDP source
/// rather than from the packet, so a peer cannot name an address that is not
/// its own and point you at a third party.
pub struct Seen {
    pub handle: String,
    pub sign: String,
    pub boxpub: String,
    pub addr: SocketAddr,
    pub port: u16,
}

impl Seen {
    pub fn token(&self) -> String {
        if self.boxpub.is_empty() {
            self.sign.clone()
        } else {
            format!("{}.{}", self.sign, self.boxpub)
        }
    }
}

/// Broadcast on 7789 for `secs`, listening for the other machine at the same
/// time so one command on each laptop is enough to pair.
///
/// Returns everyone seen, newest fact per key.
pub fn nearby(
    id: Option<&Identity>,
    listen_port: u16,
    secs: u64,
    announce: bool,
) -> std::io::Result<Vec<Seen>> {
    let ap = announce_bind();
    let sock = UdpSocket::bind(("0.0.0.0", ap)).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "could not bind udp {ap} ({e}). Another gage nearby is probably \
                 already running -- discovery wants one process per machine."
            ),
        )
    })?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut out: Vec<Seen> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut last_shout = std::time::Instant::now() - Duration::from_secs(10);

    while std::time::Instant::now() < deadline {
        if announce {
            if let Some(id) = id {
                if last_shout.elapsed() >= Duration::from_secs(2) {
                    let p = sign_packet(
                        id,
                        Packet {
                            t: "announce".into(),
                            handle: id.handle.clone(),
                            sign: id.public_b64(),
                            boxpub: id.box_public_b64(),
                            port: listen_port,
                            at: now(),
                            want: String::new(),
                            nonce: String::new(),
                            sig: String::new(),
                        },
                    );
                    let body = serde_json::to_vec(&p).unwrap_or_default();
                    // A failed broadcast is not fatal: a machine with no
                    // route for 255.255.255.255 can still be the one that
                    // LISTENS while the other announces.
                    // A failure on one destination is not a failure: the
                    // whole point of having two is that a platform refuses
                    // one of them.
                    for d in bcast_targets() {
                        let _ = sock.send_to(&body, (d.as_str(), announce_dest()));
                    }
                    last_shout = std::time::Instant::now();
                }
            }
        }
        let mut buf = [0u8; MAX_PACKET];
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let Some(p) = parse(&buf[..n]) else { continue };
        if p.t != "announce" {
            continue;
        }
        if let Some(id) = id {
            if p.sign == id.public_b64() {
                continue; // our own broadcast, come back around
            }
        }
        let seen = Seen {
            handle: p.handle,
            sign: p.sign,
            boxpub: p.boxpub,
            addr: from,
            port: p.port,
        };
        match out.iter().position(|s| s.sign == seen.sign) {
            Some(i) => out[i] = seen,
            None => out.push(seen),
        }
    }
    Ok(out)
}

/// Ask the network where one specific key is, and wait for that key to answer.
///
/// Nothing here trusts the answer for anything except an address. The
/// envelope is sealed to the recipient's box key before it goes anywhere, so
/// the worst a wrong answer can do is deliver ciphertext to somebody who
/// cannot open it.
pub fn resolve(id: &Identity, want_sign: &str, secs: u64) -> std::io::Result<Option<Seen>> {
    let nonce = new_nonce().ok_or_else(|| {
        std::io::Error::other("no randomness available, so a query cannot be made safely")
    })?;
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    let p = sign_packet(
        id,
        Packet {
            t: "query".into(),
            handle: id.handle.clone(),
            sign: id.public_b64(),
            boxpub: String::new(),
            port: 0,
            at: now(),
            want: want_tag(want_sign, &nonce),
            nonce: nonce.clone(),
            sig: String::new(),
        },
    );
    let body = serde_json::to_vec(&p).unwrap_or_default();
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut last = std::time::Instant::now() - Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if last.elapsed() >= Duration::from_secs(1) {
            let mut sent = false;
            let mut last_err = None;
            for d in bcast_targets() {
                match sock.send_to(&body, (d.as_str(), query_dest())) {
                    Ok(_) => sent = true,
                    Err(e) => last_err = Some(e),
                }
            }
            // Only an error when NOTHING went out. On macOS the all-hosts
            // address fails and the subnet one works, so treating the first
            // refusal as fatal would have made this command platform-
            // specific for no reason.
            if !sent {
                return Err(last_err.unwrap_or_else(|| {
                    std::io::Error::other("no broadcast address could be used")
                }));
            }
            last = std::time::Instant::now();
        }
        let mut buf = [0u8; MAX_PACKET];
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let Some(a) = parse(&buf[..n]) else { continue };
        // Three checks, and all three matter: the right shape of packet, from
        // the key we asked about, answering THIS query. Without the nonce an
        // answer recorded earlier could be replayed to point a later send at
        // an address the key no longer holds.
        if a.t != "here" || a.sign != want_sign.trim() || a.nonce != nonce {
            continue;
        }
        return Ok(Some(Seen {
            handle: a.handle,
            sign: a.sign,
            boxpub: a.boxpub,
            addr: from,
            port: a.port,
        }));
    }
    Ok(None)
}

/// The query responder. Answers a signed query from a key on the list, with
/// the address the asker already needs, and ignores everything else.
fn answer_queries(listen_port: u16) -> std::io::Result<()> {
    // Loaded again rather than shared with the TCP half: the secret stays in
    // one place per thread, and a listener that cannot read its own identity
    // should fail here rather than halfway through answering.
    let id = Identity::load()?;
    let sock = UdpSocket::bind(("0.0.0.0", query_bind()))?;
    let me = id.public_b64();
    loop {
        let mut buf = [0u8; MAX_PACKET];
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let Some(q) = parse(&buf[..n]) else { continue };
        if q.t != "query" || q.nonce.is_empty() {
            continue;
        }
        // Are they asking about us? Only we can tell: the wanted key is
        // hashed with their nonce.
        if q.want != want_tag(&me, &q.nonce) {
            continue;
        }
        // The line that dissolves the presence problem. A stranger gets
        // silence and cannot distinguish it from an empty network.
        //
        // Reloaded per query rather than cached, so removing a contact takes
        // effect without restarting the listener.
        if !crate::trust::Contacts::load().knows(&q.sign) {
            eprintln!(
                "  ignored a query from a key not on your list ({}...)",
                q.sign.chars().take(12).collect::<String>()
            );
            continue;
        }
        let a = sign_packet(
            &id,
            Packet {
                t: "here".into(),
                handle: id.handle.clone(),
                sign: me.clone(),
                boxpub: id.box_public_b64(),
                port: listen_port,
                at: now(),
                want: String::new(),
                nonce: q.nonce.clone(),
                sig: String::new(),
            },
        );
        let body = serde_json::to_vec(&a).unwrap_or_default();
        let _ = sock.send_to(&body, from);
    }
}

/// Run both halves of being reachable: answer queries, and accept envelopes.
pub fn listen(bind: &str, port: u16) -> std::io::Result<()> {
    let id = Identity::load()?;
    let l = TcpListener::bind((bind, port))?;
    println!("gage listen on {bind}:{port} (tcp) and 0.0.0.0:{} (udp queries)", query_bind());
    println!("  it answers a query only when the query is signed by a key on your list");
    println!("  an envelope that arrives lands in inbox/pending -- arrival is not consent");
    std::thread::spawn(move || {
        if let Err(e) = answer_queries(port) {
            eprintln!("gage listen: query responder stopped: {e}");
        }
    });
    for s in l.incoming() {
        match s {
            Ok(s) => {
                if let Err(e) = handle_inbound(s, &id) {
                    eprintln!("gage listen: {e}");
                }
            }
            Err(e) => eprintln!("gage listen: accept: {e}"),
        }
    }
    Ok(())
}

fn http_reply(mut s: TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let h = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(h.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}

fn handle_inbound(stream: TcpStream, id: &Identity) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut r = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("/").to_string();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    if len > crate::relay::MAX_BODY {
        return http_reply(stream, "413 Payload Too Large", r#"{"error":"too large"}"#);
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut body)?;
    }
    match (method.as_str(), target.as_str()) {
        ("GET", "/health") => http_reply(stream, "200 OK", r#"{"ok":true}"#),
        ("POST", "/lan/send") => match accept_envelope(&body, id) {
            Ok(msg) => {
                println!("  {msg}");
                http_reply(stream, "200 OK", r#"{"ok":true}"#)
            }
            Err(e) => {
                eprintln!("  refused an envelope: {e}");
                http_reply(stream, "400 Bad Request", r#"{"error":"refused"}"#)
            }
        },
        _ => http_reply(stream, "404 Not Found", r#"{"error":"no such route"}"#),
    }
}

/// Land one envelope in `inbox/pending`, or say why not.
///
/// Same refusals as a relay pull, for the same reasons: the sender does not
/// get to choose the directory name, and a bundle whose signature does not
/// verify never enters the inbox over a transport we control. Unlike a local
/// route -- which the sender writes directly -- this one is ours to refuse.
fn accept_envelope(body: &[u8], id: &Identity) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let raw = v.get("envelope").and_then(|e| e.as_str()).ok_or("no envelope")?;
    let env: crate::seal::Envelope =
        serde_json::from_str(raw).map_err(|e| format!("unreadable envelope: {e}"))?;
    if env.to_box.trim() != id.box_public_b64() {
        return Err("sealed to a different key than this machine holds".into());
    }
    let tmp = crate::identity::home().join(format!("tmp-lan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let land = |tmp: &std::path::Path| -> Result<String, String> {
        crate::seal::unseal_to_dir(&env, id, tmp).map_err(|e| e.to_string())?;
        let loaded = crate::bundle::load(tmp).map_err(|e| e.to_string())?;
        if !crate::manifest::id_is_safe(&loaded.manifest.id) {
            return Err("a bundle whose id is not an id -- it would have become a path".into());
        }
        if !loaded.tampered.is_empty() {
            return Err(loaded.tampered.join(", "));
        }
        let dest = crate::routes::pending_dir(&crate::identity::home()).join(&loaded.manifest.id);
        if dest.exists() {
            return Ok(format!("already have {} -- left in place", loaded.manifest.id));
        }
        std::fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
        crate::routes::deliver(tmp, &dest).map_err(|e| e.to_string())?;
        let verdict = crate::bundle::load(&dest)
            .map(|l| l.trust.label().to_string())
            .unwrap_or_else(|e| format!("could not be read back: {e}"));
        Ok(format!(
            "{}  {}  ({verdict}) -- gage inbox, then accept or reject",
            loaded.manifest.id, loaded.manifest.subject
        ))
    };
    let r = land(&tmp);
    let _ = std::fs::remove_dir_all(&tmp);
    r
}

/// Hand a sealed envelope straight to a machine on this network.
pub fn deliver_to(addr: SocketAddr, body: &str) -> std::io::Result<()> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.set_write_timeout(Some(Duration::from_secs(60)))?;
    let req = format!(
        "POST /lan/send HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text.lines().next().unwrap_or("").to_string();
    if !status.contains(" 200") {
        return Err(std::io::Error::other(format!(
            "the other machine refused it: {}",
            status.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str) -> Packet {
        Packet {
            t: t.into(),
            handle: "laptop".into(),
            sign: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            boxpub: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into(),
            port: 7791,
            at: 1_700_000_000,
            want: String::new(),
            nonce: "nnn".into(),
            sig: String::new(),
        }
    }

    #[test]
    fn the_signing_input_is_unambiguous_across_handles() {
        // A handle is attacker-chosen text. With a separator-joined encoding,
        // a handle containing the separator could move a field boundary and
        // make two different packets sign the same bytes. Length prefixes are
        // what stop that, so it is worth a test rather than a comment.
        let mut a = p("announce");
        a.handle = "a|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        let mut b = p("announce");
        b.handle = "a".into();
        assert_ne!(signed_bytes(&a), signed_bytes(&b));
    }

    #[test]
    fn the_kind_of_packet_is_inside_the_signature() {
        // Otherwise a recorded `query` is a valid `here`, and answering a
        // query becomes something anyone can forge by replaying one.
        assert_ne!(signed_bytes(&p("query")), signed_bytes(&p("here")));
    }

    #[test]
    fn a_wanted_key_is_not_on_the_wire() {
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        let tag = want_tag(k, "nonce-one");
        assert!(!tag.contains("yomSmC"));
        // Only the holder of that key can recognise the tag, and a different
        // query does not look the same -- so the LAN cannot correlate two
        // sends to the same recipient.
        assert_eq!(tag, want_tag(k, "nonce-one"));
        assert_ne!(tag, want_tag(k, "nonce-two"));
        assert_ne!(tag, want_tag("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "nonce-one"));
    }

    #[test]
    fn a_pasted_key_with_whitespace_tags_the_same() {
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        assert_eq!(want_tag(k, "n"), want_tag(&format!(" {k}\n"), "n"));
    }

    #[test]
    fn nothing_unsigned_or_stale_parses() {
        let mut q = p("announce");
        q.at = now();
        // Unsigned.
        assert!(parse(&serde_json::to_vec(&q).unwrap()).is_none());
        // A made-up kind, even before the signature is looked at.
        let mut odd = p("delete-everything");
        odd.at = now();
        assert!(parse(&serde_json::to_vec(&odd).unwrap()).is_none());
        // Oversized.
        let mut big = p("announce");
        big.at = now();
        big.handle = "x".repeat(MAX_PACKET);
        assert!(parse(&serde_json::to_vec(&big).unwrap()).is_none());
        // Not JSON at all.
        assert!(parse(b"hello").is_none());
    }

    #[test]
    fn a_stale_packet_does_not_parse_even_correctly_signed() {
        // The replay case: a recorded announcement is not an address hint a
        // week later, so the clock check has to be inside parse rather than
        // left to each caller to remember.
        let q = p("announce"); // at = 2023
        assert!(parse(&serde_json::to_vec(&q).unwrap()).is_none());
    }

    #[test]
    fn a_seen_peer_renders_the_token_ctx_add_takes() {
        let s = Seen {
            handle: "laptop".into(),
            sign: "SIGN".into(),
            boxpub: "BOX".into(),
            addr: "10.0.0.2:7789".parse().unwrap(),
            port: 7791,
        };
        assert_eq!(s.token(), "SIGN.BOX");
        let bare = Seen { boxpub: String::new(), ..s };
        assert_eq!(bare.token(), "SIGN");
    }
}

// ---------------------------------------------------------------------------
// One command, which is what was actually asked for
// ---------------------------------------------------------------------------

/// What `gage lan` writes while it runs, so another terminal can send to a
/// name it saw on the list. Deleted on the way out, because a stale address
/// is worse than no address: it would send a bundle to whoever holds that IP
/// now.
pub fn nearby_path() -> std::path::PathBuf {
    crate::identity::home().join("nearby.json")
}

#[derive(Serialize, Deserialize)]
pub struct NearbyEntry {
    pub label: String,
    pub handle: String,
    pub sign: String,
    pub boxpub: String,
    pub addr: String,
    pub at: u64,
}

pub fn read_nearby() -> Vec<NearbyEntry> {
    std::fs::read_to_string(nearby_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Find a device by the word-pair label on the list, or by a contact name.
///
/// Returns the sealing key and the address, which is everything a send needs.
pub fn lookup_nearby(name: &str) -> Option<NearbyEntry> {
    let want = name.trim().to_ascii_lowercase().replace('-', " ");
    let seen = read_nearby();
    // An exact label first, then a prefix, so "yellow" is enough when only
    // one device on the list starts with it.
    seen.iter()
        .position(|e| e.label == want || e.handle.to_ascii_lowercase() == want)
        .or_else(|| {
            let hits: Vec<usize> = seen
                .iter()
                .enumerate()
                .filter(|(_, e)| e.label.starts_with(&want))
                .map(|(i, _)| i)
                .collect();
            if hits.len() == 1 { Some(hits[0]) } else { None }
        })
        .map(|i| seen.into_iter().nth(i).unwrap())
}

/// `gage lan`: visible, discoverable and reachable for exactly as long as this
/// command is in the foreground.
///
/// This is the shape the design doc argued itself out of and should not have.
/// The objection to announcing was presence -- a laptop broadcasting its key
/// onto every network it joins -- and the answer was a `--announce 60` flag,
/// which made the common case three commands and two machines' worth of
/// timing. But LocalSend has the same objection and solves it better: it is
/// visible while its window is open and silent when it is closed, and nobody
/// thinks of that as presence because the person can see it running.
///
/// So the time box is the process lifetime. Ctrl-C and this machine is as
/// invisible as it was before. That is strictly clearer than a number of
/// seconds, because the state is on screen rather than in a flag you have to
/// remember you passed.
///
/// Pairing is deliberately NOT a gate here. An unpaired device can send to
/// you, and what arrives lands in `inbox/pending` under `SENDER NOT ON YOUR
/// LIST`, unread, behind the same accept gate as everything else -- which is
/// the protection, and always was. Confirming a fingerprint upgrades a device
/// from "some machine on this wifi" to "the key I checked", which is what a
/// grant should require. Making it a precondition for sending one file was my
/// mistake, not a property of the design.
pub fn run(port: u16) -> std::io::Result<()> {
    let id = match Identity::load() {
        Ok(i) => i,
        // No identity is not an error on this path. It is the first run, and
        // asking someone to choose a name before they have seen the thing
        // work is the step LocalSend does not have.
        Err(_) => {
            let i = Identity::create_named(None)?;
            println!("new identity, named after its own key: {}", i.handle);
            println!("  {}", crate::words::fingerprint_of(&i.public_b64(), Some(&i.box_public_b64())));
            println!();
            i
        }
    };
    let me = id.public_b64();
    let my_label = crate::words::label(&me);

    let tcp = TcpListener::bind(("0.0.0.0", port))?;
    println!("gage lan -- you are \"{my_label}\" on this network");
    println!("  visible and reachable while this runs, silent the moment you stop it");
    println!("  anything sent to you lands unread in inbox/pending");
    println!("  broadcasting to: {}", bcast_targets().join(", "));
    println!();

    let rid = Identity::load()?;
    std::thread::spawn(move || {
        for s in tcp.incoming() {
            match s {
                Ok(s) => {
                    if let Err(e) = handle_inbound(s, &rid) {
                        eprintln!("gage lan: {e}");
                    }
                }
                Err(e) => eprintln!("gage lan: accept: {e}"),
            }
        }
    });
    std::thread::spawn(move || {
        if let Err(e) = answer_queries(port) {
            eprintln!("gage lan: query responder stopped: {e}");
        }
    });

    // Best effort: a stale list is worse than none, so it goes on the way out
    // too. A kill -9 can still leave one behind, which is why every entry
    // carries the time it was seen and a send refuses an old one.
    let _ = std::fs::remove_file(nearby_path());
    let out = nearby_path();
    let cleanup = out.clone();
    let _ = ctrlc_remove(cleanup);

    let sock = UdpSocket::bind(("0.0.0.0", announce_bind())).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "could not bind udp {} ({e}). Another gage lan is already running on \
                 this machine.",
                announce_bind()
            ),
        )
    })?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut seen: Vec<NearbyEntry> = Vec::new();
    let mut last_shout = std::time::Instant::now() - Duration::from_secs(10);
    let mut shown = String::new();
    loop {
        if last_shout.elapsed() >= Duration::from_secs(2) {
            let p = sign_packet(
                &id,
                Packet {
                    t: "announce".into(),
                    handle: id.handle.clone(),
                    sign: me.clone(),
                    boxpub: id.box_public_b64(),
                    port,
                    at: now(),
                    want: String::new(),
                    nonce: String::new(),
                    sig: String::new(),
                },
            );
            let body = serde_json::to_vec(&p).unwrap_or_default();
            for d in bcast_targets() {
                let _ = sock.send_to(&body, (d.as_str(), announce_dest()));
            }
            last_shout = std::time::Instant::now();
            // Forget anyone who stopped announcing, so the list on screen is
            // who is there rather than who has ever been there.
            seen.retain(|e| now().saturating_sub(e.at) <= 15);
        }

        let mut buf = [0u8; MAX_PACKET];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(p) = parse(&buf[..n]) {
                if p.t == "announce" && p.sign != me {
                    let e = NearbyEntry {
                        label: crate::words::label(&p.sign),
                        handle: p.handle.clone(),
                        sign: p.sign.clone(),
                        boxpub: p.boxpub.clone(),
                        addr: format!("{}:{}", from.ip(), p.port),
                        at: now(),
                    };
                    match seen.iter().position(|x| x.sign == e.sign) {
                        Some(i) => seen[i] = e,
                        None => seen.push(e),
                    }
                }
            }
        }

        // Written every pass, so a send from another terminal sees the list
        // as it is now.
        if let Ok(j) = serde_json::to_vec_pretty(&seen) {
            let _ = std::fs::write(&out, j);
        }
        let c = crate::trust::Contacts::load();
        let mut lines = String::new();
        for e in &seen {
            let known = match c.name_for(&e.sign) {
                Some(n) => format!("paired, on your list as {n}"),
                None => "not paired -- gage pair <name> to confirm its key".to_string(),
            };
            lines.push_str(&format!("  {}  at {}  ({known})\n", e.label, e.addr));
            lines.push_str(&format!(
                "      says : {}\n",
                crate::words::fingerprint_of(&e.sign, Some(&e.boxpub))
            ));
        }
        if lines != shown {
            if lines.is_empty() {
                println!("nobody else here yet. Run `gage lan` on the other machine.");
            } else {
                print!("{lines}");
            }
            let _ = std::io::stdout().flush();
            shown = lines;
        }
    }
}

/// Remove the nearby list on Ctrl-C.
///
/// Hand-rolled rather than a signal-handling crate: the whole handler is one
/// `unlink`, and the default disposition is restored immediately after so a
/// second Ctrl-C always kills the process even if the first one is somehow
/// stuck.
#[cfg(unix)]
fn ctrlc_remove(path: std::path::PathBuf) -> std::io::Result<()> {
    use std::sync::OnceLock;
    static PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
    let _ = PATH.set(path);
    unsafe extern "C" {
        fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    }
    extern "C" fn on_int(_: i32) {
        if let Some(p) = PATH.get() {
            let _ = std::fs::remove_file(p);
        }
        std::process::exit(130);
    }
    unsafe { signal(2, on_int) };
    Ok(())
}

#[cfg(not(unix))]
fn ctrlc_remove(_path: std::path::PathBuf) -> std::io::Result<()> {
    Ok(())
}

/// Seal a built bundle and hand it to a machine on this network.
///
/// Two ways to find them, and the first needs no pairing at all: if `gage lan`
/// is running it has already written down who is here and where, so an
/// unpaired device on the list can be sent to by its word-pair label.
/// Failing that, a contact is found by the signed query, which works without
/// `gage lan` open but only for a key already on the other machine's list.
///
/// Returns the lines to show, because one of its callers is a web page.
pub fn hand_over(dir: &std::path::Path, who: &str) -> Result<Vec<String>, String> {
    let id = Identity::load().map_err(|e| e.to_string())?;
    let c = crate::trust::Contacts::load();

    // A name on the list, OR a contact whose key is on the list. The second
    // matters because pairing is one-sided: once you have paired with a
    // machine you will call it `laptop`, and it is still announcing under its
    // word-pair. Without this, `--to laptop` fell through to the signed
    // query -- which the other machine correctly ignores until it has paired
    // with YOU, so the better-named path was the one that failed.
    let on_list = lookup_nearby(who).or_else(|| {
        let k = c.key_for_name(who)?;
        read_nearby().into_iter().find(|e| e.sign == k)
    });

    let (boxpub, addr, desc) = match on_list {
        Some(e) => {
            // An entry older than a minute is not an address any more: DHCP
            // moves on, and sending to whoever holds that IP now is a worse
            // failure than refusing. `gage lan` rewrites it every two seconds.
            let age = now().saturating_sub(e.at);
            if age > 60 {
                return Err(format!(
                    "the entry for {who} is {age}s old, so it is not an address any more. \
                     Is `gage lan` still running on both machines?"
                ));
            }
            if e.boxpub.is_empty() {
                return Err(format!(
                    "{who} announced no encryption key, so nothing can be sealed to it"
                ));
            }
            let known = match c.name_for(&e.sign) {
                Some(n) => format!("paired, on your list as {n}"),
                None => "NOT PAIRED -- it will arrive as SENDER NOT ON YOUR LIST".to_string(),
            };
            (e.boxpub.clone(), e.addr.clone(), format!("{} ({known})", e.label))
        }
        None => {
            let sign = c.key_for_name(who).ok_or_else(|| {
                format!(
                    "no machine called {who} on this network, and no contact by that name.\n  \
                     Run `gage lan` on both machines and use the word-pair it shows."
                )
            })?;
            let boxpub = c
                .box_keys
                .get(&sign)
                .ok_or(format!("{who} has no encryption key on file; re-add them"))?
                .clone();
            let seen = resolve(&id, &sign, 8)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| {
                    format!(
                        "no answer from {who} on this network. They need `gage lan` or `ctx \
                         listen` running, and you need to be on their list -- a query from \
                         a key they do not know is ignored, deliberately and silently."
                    )
                })?;
            (boxpub, format!("{}:{}", seen.addr.ip(), seen.port), who.to_string())
        }
    };

    let env = crate::seal::seal_dir(dir, &boxpub).map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "to_box": boxpub,
        "envelope": serde_json::to_string(&env).map_err(|e| e.to_string())? })
        .to_string();
    let sa: SocketAddr = addr
        .parse()
        .map_err(|e| format!("{who} announced an address that is not one ({addr}): {e}"))?;
    deliver_to(sa, &body).map_err(|e| e.to_string())?;
    Ok(vec![
        format!("  handed to {desc} at {addr}, over this network"),
        "  it is in their inbox/pending -- not accepted".to_string(),
    ])
}
