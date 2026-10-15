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
//! was registered alongside it.
//!
//! Registration used to be the one moment the relay took somebody's word --
//! and the word it took was a PUBLIC value. A box key is what you hand out in
//! a `ctx whoami` line, so anyone could register someone else's mailbox
//! against their own signing key, before the owner got there. First
//! registration wins, so the owner was then locked out permanently: they
//! could never fetch, and mail pushed to them landed in a mailbox the squatter
//! could collect and delete. Sealed, so not readable -- but gone, with the
//! sender believing it was delivered. The muse reviewer found it.
//!
//! So registration proves possession of the box SECRET. The relay seals a
//! nonce to the claimed box key and will only commit the binding when the
//! caller sends that nonce back. A squatter gets a sealed nonce they cannot
//! open, and a pending registration nobody else is blocked by.

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
    /// The nonce the relay sealed to `box_key`, returned to prove the caller
    /// holds the matching secret. Absent on the first leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

struct State {
    root: PathBuf,
    /// box_key -> sign_key that may collect it
    owners: HashMap<String, String>,
    /// nonce -> box_key it was issued for
    challenges: HashMap<String, String>,
    /// A registration waiting for proof: (box_key, sign_key) -> the nonce the
    /// relay sealed to that box key. Keyed by the PAIR, so two parties can
    /// have a pending claim on the same mailbox at once and neither blocks
    /// the other -- only the one who can open their nonce commits.
    pending: HashMap<(String, String), String>,
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
        pending: HashMap::new(),
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

/// A fresh random nonce, from the same source the fetch challenge uses.
fn new_nonce() -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut buf = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    B64.encode(buf)
}

fn do_register(stream: TcpStream, body: &[u8]) -> std::io::Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
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

    let key = (reg.box_key.clone(), reg.sign_key.clone());
    match reg.proof.as_deref() {
        // Second leg: the caller returns the nonce, which they could only
        // have read by holding the box secret.
        Some(p) => {
            let Some(want) = st.pending.get(&key).cloned() else {
                return reply(
                    stream,
                    "401 Unauthorized",
                    r#"{"error":"no registration in progress for that pair"}"#,
                );
            };
            // Constant-time is not the issue here: the nonce is single-use and
            // random, and a wrong answer destroys the attempt either way.
            if p != want {
                st.pending.remove(&key);
                return reply(
                    stream,
                    "401 Unauthorized",
                    r#"{"error":"proof does not match; start again"}"#,
                );
            }
            st.pending.remove(&key);
            st.owners.insert(reg.box_key.clone(), reg.sign_key.clone());
            let path = st.root.join("owners.json");
            let data = serde_json::to_vec_pretty(&st.owners).unwrap_or_default();
            let _ = std::fs::write(path, data);
            reply(stream, "200 OK", r#"{"ok":true}"#)
        }
        // First leg: issue a nonce the holder of the box secret can read and
        // nobody else can.
        None => {
            let Ok(raw) = B64.decode(&reg.box_key) else {
                return reply(stream, "400 Bad Request", r#"{"error":"bad box key"}"#);
            };
            let Ok(raw): Result<[u8; 32], _> = raw.try_into() else {
                return reply(stream, "400 Bad Request", r#"{"error":"bad box key"}"#);
            };
            let nonce = new_nonce();
            let pk = crypto_box::PublicKey::from_bytes(raw);
            let Ok(ct) = pk.seal(&mut crypto_box::aead::OsRng, nonce.as_bytes()) else {
                return reply(stream, "500 Internal Server Error", r#"{"error":"seal failed"}"#);
            };
            st.pending.insert(key, nonce);
            if st.pending.len() > 10_000 {
                // Bounded like the challenge map. A squatter can fill this
                // with pending claims they can never complete, and clearing
                // it costs legitimate callers one retry.
                st.pending.clear();
            }
            reply(
                stream,
                "200 OK",
                &serde_json::json!({
                    "prove": B64.encode(&ct),
                    "note": "unseal this with your box secret and re-register with it as `proof`"
                })
                .to_string(),
            )
        }
    }
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
