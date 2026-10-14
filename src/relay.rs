//! A deliberately stupid store-and-forward relay.
//!
//! It holds sealed envelopes addressed to an X25519 public key and hands them
//! over to whoever can prove they hold the matching secret. It cannot read
//! what it stores, so compromising it leaks metadata -- who has mail waiting,
//! how big, and when -- and no content.
//!
//! The authentication detail that matters: a fetcher must PROVE key
//! possession, not merely name a key. Naming is not proof, and anyone who can
//! read a `ctx whoami` line knows your public key, so a name-only scheme
//! would let a stranger drain your inbox. The relay issues a random challenge
//! and requires an ed25519 signature over it.
//!
//! Signing and encryption keys are bound by the ADDRESSING: an envelope is
//! sealed to a box key, and the fetch is authorised by the signing key that
//! was registered alongside it. Registration is therefore the only moment
//! where the relay takes anyone's word for anything, and it takes it once.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;

pub const MAX_BODY: usize = 40 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone)]
pub struct Registration {
    /// ed25519 public key, base64. Authorises fetching.
    pub sign_key: String,
    /// X25519 public key, base64. The mailbox address.
    pub box_key: String,
}

struct State {
    root: PathBuf,
    /// box_key -> sign_key that may collect it
    owners: HashMap<String, String>,
    /// nonce -> box_key it was issued for
    challenges: HashMap<String, String>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn b64_ok(s: &str) -> bool {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    matches!(B64.decode(s), Ok(v) if v.len() == 32)
}

/// A base64 key reaches the filesystem as a directory name, so it is checked
/// rather than trusted: base64 contains '/' and '+', and '/' in a path
/// component is how a mailbox escapes its directory.
fn key_to_dirname(k: &str) -> Option<String> {
    if !b64_ok(k) {
        return None;
    }
    Some(k.replace('/', "_").replace('+', "-").replace('=', ""))
}

pub fn serve(bind: &str, root: PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("mail"))?;
    let owners = std::fs::read_to_string(root.join("owners.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    *STATE.lock().unwrap() = Some(State {
        root: root.clone(),
        owners,
        challenges: HashMap::new(),
    });
    let l = TcpListener::bind(bind)?;
    println!("ctx relay on {bind}, store at {}", root.display());
    println!("  it cannot read what it stores; envelopes are sealed to recipients");
    for s in l.incoming() {
        match s {
            Ok(s) => {
                if let Err(e) = handle(s) {
                    eprintln!("relay: {e}");
                }
            }
            Err(e) => eprintln!("relay: accept: {e}"),
        }
    }
    Ok(())
}

fn reply(mut s: TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let h = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(h.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}

fn handle(stream: TcpStream) -> std::io::Result<()> {
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
    if len > MAX_BODY {
        return reply(stream, "413 Payload Too Large", r#"{"error":"too large"}"#);
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut body)?;
    }

    match (method.as_str(), target.as_str()) {
        ("POST", "/register") => do_register(stream, &body),
        ("POST", "/send") => do_send(stream, &body),
        ("POST", "/challenge") => do_challenge(stream, &body),
        ("POST", "/fetch") => do_fetch(stream, &body),
        ("GET", "/health") => reply(stream, "200 OK", r#"{"ok":true}"#),
        _ => reply(stream, "404 Not Found", r#"{"error":"no such route"}"#),
    }
}

fn do_register(stream: TcpStream, body: &[u8]) -> std::io::Result<()> {
    let Ok(reg) = serde_json::from_slice::<Registration>(body) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad body"}"#);
    };
    if !b64_ok(&reg.sign_key) || !b64_ok(&reg.box_key) {
        return reply(stream, "400 Bad Request", r#"{"error":"keys must be 32-byte base64"}"#);
    }
    let mut g = STATE.lock().unwrap();
    let st = g.as_mut().unwrap();
    // First registration of a mailbox wins. Letting a later caller rebind a
    // box key to a different signing key would let anyone take over a mailbox
    // by re-registering it.
    if let Some(existing) = st.owners.get(&reg.box_key) {
        if existing != &reg.sign_key {
            return reply(
                stream,
                "409 Conflict",
                r#"{"error":"mailbox already registered to another signing key"}"#,
            );
        }
        return reply(stream, "200 OK", r#"{"ok":true,"note":"already registered"}"#);
    }
    st.owners.insert(reg.box_key.clone(), reg.sign_key.clone());
    let path = st.root.join("owners.json");
    let data = serde_json::to_vec_pretty(&st.owners).unwrap_or_default();
    let _ = std::fs::write(path, data);
    reply(stream, "200 OK", r#"{"ok":true}"#)
}

#[derive(Deserialize)]
struct SendReq {
    to_box: String,
    envelope: String,
}

fn do_send(stream: TcpStream, body: &[u8]) -> std::io::Result<()> {
    let Ok(req) = serde_json::from_slice::<SendReq>(body) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad body"}"#);
    };
    let Some(dir) = key_to_dirname(&req.to_box) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad recipient key"}"#);
    };
    let g = STATE.lock().unwrap();
    let st = g.as_ref().unwrap();
    // Only registered mailboxes accept mail, so the relay cannot be used as
    // free storage for arbitrary keys nobody will ever collect.
    if !st.owners.contains_key(&req.to_box) {
        return reply(stream, "404 Not Found", r#"{"error":"no such mailbox"}"#);
    }
    let box_dir = st.root.join("mail").join(&dir);
    if std::fs::create_dir_all(&box_dir).is_err() {
        return reply(stream, "500 Internal Server Error", r#"{"error":"store failed"}"#);
    }
    let name = format!(
        "{}-{}.ctxb",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        &crate::bundle::sha256_hex(req.envelope.as_bytes())[..12]
    );
    match std::fs::write(box_dir.join(&name), req.envelope.as_bytes()) {
        Ok(()) => reply(stream, "200 OK", &format!(r#"{{"ok":true,"id":"{name}"}}"#)),
        Err(_) => reply(stream, "500 Internal Server Error", r#"{"error":"store failed"}"#),
    }
}

#[derive(Deserialize)]
struct ChallengeReq {
    box_key: String,
}

fn do_challenge(stream: TcpStream, body: &[u8]) -> std::io::Result<()> {
    let Ok(req) = serde_json::from_slice::<ChallengeReq>(body) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad body"}"#);
    };
    let mut buf = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let nonce = B64.encode(buf);
    let mut g = STATE.lock().unwrap();
    let st = g.as_mut().unwrap();
    // Issued even for an unknown mailbox, and with the same shape, so the
    // endpoint does not become an oracle for which keys are registered.
    st.challenges.insert(nonce.clone(), req.box_key);
    if st.challenges.len() > 10_000 {
        st.challenges.clear();
    }
    reply(stream, "200 OK", &format!(r#"{{"nonce":"{nonce}"}}"#))
}

#[derive(Deserialize)]
struct FetchReq {
    box_key: String,
    nonce: String,
    /// ed25519 signature over the nonce bytes, by the registered signing key.
    sig: String,
    #[serde(default)]
    delete: bool,
}

fn do_fetch(stream: TcpStream, body: &[u8]) -> std::io::Result<()> {
    let Ok(req) = serde_json::from_slice::<FetchReq>(body) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad body"}"#);
    };
    let mut g = STATE.lock().unwrap();
    let st = g.as_mut().unwrap();
    // One use per challenge. A replayable signature is a stolen credential
    // with a longer life.
    let Some(issued_for) = st.challenges.remove(&req.nonce) else {
        return reply(stream, "401 Unauthorized", r#"{"error":"unknown or used challenge"}"#);
    };
    if issued_for != req.box_key {
        return reply(stream, "401 Unauthorized", r#"{"error":"challenge was for another mailbox"}"#);
    }
    let Some(sign_key) = st.owners.get(&req.box_key).cloned() else {
        return reply(stream, "401 Unauthorized", r#"{"error":"not registered"}"#);
    };
    if !crate::identity::verify(&sign_key, req.nonce.as_bytes(), &req.sig) {
        return reply(stream, "401 Unauthorized", r#"{"error":"signature does not verify"}"#);
    }
    let Some(dir) = key_to_dirname(&req.box_key) else {
        return reply(stream, "400 Bad Request", r#"{"error":"bad key"}"#);
    };
    let box_dir = st.root.join("mail").join(&dir);
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&box_dir) {
        let mut names: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        names.sort();
        for p in names {
            if let Ok(s) = std::fs::read_to_string(&p) {
                out.push(serde_json::json!({
                    "id": p.file_name().map(|n| n.to_string_lossy().to_string()),
                    "envelope": s,
                }));
                if req.delete {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    reply(
        stream,
        "200 OK",
        &serde_json::json!({ "count": out.len(), "items": out }).to_string(),
    )
}
