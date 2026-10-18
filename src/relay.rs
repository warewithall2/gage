//! A deliberately stupid store-and-forward relay.
//!
//! It holds sealed envelopes addressed to an X25519 public key and hands them
//! over to whoever can prove they hold the matching secret. It cannot read
//! what it stores, so compromising it leaks metadata -- who has mail waiting,
//! how big, and when -- and no content.
//!
//! The authentication detail that matters: a fetcher must PROVE key
//! possession, not merely name a key. Naming is not proof, and anyone who can
//! read a `gage whoami` line knows your public key, so a name-only scheme
//! would let a stranger drain your inbox. The relay issues a random challenge
//! and requires an ed25519 signature over it.
//!
//! Signing and encryption keys are bound by the ADDRESSING: an envelope is
//! sealed to a box key, and the fetch is authorised by the signing key that
//! was registered alongside it.
//!
//! Registration used to be the one moment the relay took somebody's word --
//! and the word it took was a PUBLIC value. A box key is what you hand out in
//! a `gage whoami` line, so anyone could register someone else's mailbox
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

/// How long a client may take over any single read or write.
///
/// The relay had none. One connection that said nothing held the accept loop
/// for ever, because the loop is sequential and `read_line` blocked in it --
/// a complete denial of service from a single TCP connection, with no
/// credentials and nothing sent. The viewer was given timeouts when the same
/// shape was found there; the relay never was, and it is the part that faces
/// other people.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Connections served at once. A cap rather than unbounded spawning, so a
/// flood costs a bounded amount of memory and the relay refuses politely
/// instead of falling over.
const MAX_INFLIGHT: usize = 64;

/// Caps on the request head, and on how long a whole request may take.
///
/// The viewer was given the first of these the morning after its parser was
/// written. The relay -- the part that faces other people -- never was, and
/// a reviewer found it by reading both: `read_line` appends until a newline
/// with no limit of its own, and the 20-second timeout is per *read*, so a
/// client that streams bytes and never sends a newline keeps every read
/// succeeding while the `String` grows until the cgroup's `MemoryMax` kills
/// the process. `Restart=on-failure` then brings it back for the same
/// connection to do it again. One address, no credentials, no mailbox: a
/// crash loop.
///
/// `DEADLINE` is the other half of the same lesson. A per-operation timeout
/// cannot stop a client that sends one byte every nineteen seconds, which
/// costs an attacker nothing and holds a worker slot indefinitely. A request
/// gets a total budget, not a per-syscall one.
const MAX_HEAD_BYTES: u64 = 64 * 1024;
const MAX_HEADERS: usize = 200;
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Bytes that may be held in memory for request bodies at any one moment.
///
/// Found by reading the deployment rather than the code. The unit on the
/// relay host sets `MemoryMax=200M`, and `MAX_BODY` is 40MB with a
/// concurrency cap of 64 -- so sixty-four concurrent uploads would try to
/// buffer 2.5GB against a 200MB ceiling. systemd kills the process,
/// `Restart=on-failure` brings it back, and the attacker repeats: a
/// trivially triggerable outage, needing no credentials, on exactly the port
/// about to face the internet.
///
/// A connection cap alone cannot express this, because the cost of a
/// connection is not a connection -- it is the body it declares. So the
/// budget is in bytes, reserved from the declared `Content-Length` before a
/// single byte is read, and released when the request is done.
static BODY_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Default ceiling, chosen to sit well inside a 200MB cgroup with room for
/// everything that is not a body.
const MAX_BODY_BYTES_INFLIGHT: usize = 96 * 1024 * 1024;

/// Holds a reservation and gives it back however the request ends -- an
/// early return, an I/O error or a panic. A counter that leaks on the error
/// path is a counter that reaches its ceiling and stays there, which would
/// turn this protection into the outage it prevents.
struct BodyReservation(usize);

impl BodyReservation {
    fn take(n: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = BODY_BYTES.load(Ordering::SeqCst);
        loop {
            if cur + n > MAX_BODY_BYTES_INFLIGHT {
                return None;
            }
            match BODY_BYTES.compare_exchange(cur, cur + n, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(BodyReservation(n)),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        BODY_BYTES.fetch_sub(self.0, std::sync::atomic::Ordering::SeqCst);
    }
}

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
    /// relay sealed to that box key, and when it was issued. Keyed by the
    /// PAIR, so two parties can have a pending claim on the same mailbox at
    /// once and neither blocks the other -- only the one who can open their
    /// nonce commits.
    pending: HashMap<(String, String), (String, std::time::Instant)>,
    /// nonce -> when it was issued, for age-based eviction.
    challenge_age: HashMap<String, std::time::Instant>,
    limits: Limits,
    /// source address -> (requests in the current window, when it opened).
    ///
    /// Per address and not per key, because the abuse that matters on a
    /// public relay -- `/send` and the first leg of `/register` -- needs no
    /// key at all.
    rate: HashMap<String, (u32, std::time::Instant)>,
}

/// What a public relay has to bound, with the reason each one exists.
///
/// All of it was absent, which was safe only because the relay has so far
/// been reachable from one person's tailnet. `/send` takes no authentication
/// by design -- a stranger must be able to send you a first message, which
/// is the whole point of the "not on your list" section of the buddy list --
/// so the answer is not authentication, it is a bound.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bytes one mailbox may hold before it stops accepting.
    pub mailbox_bytes: u64,
    /// Envelopes one mailbox may hold. A thousand one-byte messages is as
    /// effective a flood as one big one, and costs the recipient more.
    pub mailbox_msgs: usize,
    /// Bytes the whole store may hold. The backstop when many mailboxes are
    /// each individually under their limit.
    pub store_bytes: u64,
    /// Requests per minute from one address.
    pub per_min: u32,
    /// Mailboxes that may exist on this relay at all.
    pub mailboxes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Deliberately modest. A relay is a letterbox, not a file host: these
        // are sized so a personal VPS cannot be filled by a stranger, and an
        // operator who wants more says so.
        Self {
            mailbox_bytes: 64 * 1024 * 1024,
            mailbox_msgs: 500,
            store_bytes: 4 * 1024 * 1024 * 1024,
            per_min: 120,
            // Generous for people, small enough that manufacturing mailboxes
            // is not a way to make every registration expensive.
            mailboxes: 2_000,
        }
    }
}

/// Bytes currently stored under a directory, one level deep.
fn dir_bytes(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()
}

fn dir_count(p: &std::path::Path) -> usize {
    std::fs::read_dir(p).map(|rd| rd.flatten().count()).unwrap_or(0)
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
    serve_with(bind, root, Limits::default())
}

pub fn serve_with(bind: &str, root: PathBuf, limits: Limits) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("mail"))?;
    let owners = std::fs::read_to_string(root.join("owners.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    *STATE.lock().unwrap() = Some(State {
        root: root.clone(),
        owners,
        challenges: HashMap::new(),
        challenge_age: HashMap::new(),
        pending: HashMap::new(),
        limits,
        rate: HashMap::new(),
    });
    let l = TcpListener::bind(bind)?;
    println!("gage relay on {bind}, store at {}", root.display());
    println!("  it cannot read what it stores; envelopes are sealed to recipients");
    println!(
        "  limits: {} MB and {} envelopes per mailbox, {} MB total, {} requests/min per address",
        limits.mailbox_bytes / (1024 * 1024),
        limits.mailbox_msgs,
        limits.store_bytes / (1024 * 1024),
        limits.per_min
    );
    println!("  at most {} mailboxes", limits.mailboxes);
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for s in l.incoming() {
        let s = match s {
            Ok(s) => s,
            Err(e) => {
                eprintln!("relay: accept: {e}");
                continue;
            }
        };
        // Timeouts first, before anything reads: a client that connects and
        // says nothing must not be able to hold anything.
        let _ = s.set_read_timeout(Some(IO_TIMEOUT));
        let _ = s.set_write_timeout(Some(IO_TIMEOUT));
        let n = live.load(std::sync::atomic::Ordering::SeqCst);
        if n >= MAX_INFLIGHT {
            // Refusing is the honest answer -- but it happens on its own
            // thread, not in the accept loop. `reply` drains the client's
            // unread request before closing (see there for why), and doing
            // that inline cost up to 200ms per refusal, serially, which
            // stalled accepting for everyone and is the exact disease this
            // cap was meant to cure. The refusal thread is short-lived and
            // deliberately not counted against the cap.
            std::thread::spawn(move || {
                let _ = reply(s, "503 Service Unavailable", r#"{"error":"relay busy, retry"}"#);
            });
            continue;
        }
        live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let live2 = live.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(s) {
                eprintln!("relay: {e}");
            }
            live2.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
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
    s.flush()?;
    // Drain whatever the client sent that nothing read, before closing.
    //
    // Closing a socket that still has unread data in its receive buffer
    // makes BSD send RST rather than FIN, and the RST **discards the reply
    // just written** -- the client sees "connection reset by peer" instead
    // of the 503. The busy path is exactly that shape: it refuses before
    // reading the request at all. Linux delivers the reply anyway, which is
    // why this only showed up when the suite was finally run on macOS.
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(50)));
    let mut sink = [0u8; 4096];
    for _ in 0..16 {
        match s.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
    Ok(())
}

/// Has this address used up its allowance for the current minute?
///
/// A fixed window rather than a token bucket, because the thing it protects
/// against is a flood and the difference at a window edge does not matter
/// here. Keyed by IP, with the port dropped -- a client gets a new source
/// port per connection, so keeping it would make the limit count nothing.
fn over_rate(peer: &str) -> bool {
    // Parsed, not string-split. `rsplit_once(':')` cuts inside an IPv6
    // address -- so distinct clients collapsed into shared buckets while an
    // attacker rotating within one /64 got a fresh bucket per address, which
    // is the wrong answer in both directions at once.
    //
    // IPv6 is keyed on the /64, because one allocation hands out more
    // addresses than any rate limit could enumerate.
    let ip = match peer.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(a)) => a.ip().to_string(),
        Ok(std::net::SocketAddr::V6(a)) => {
            let o = a.ip().octets();
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]
            )
        }
        Err(_) => peer.to_string(),
    };
    let mut g = STATE.lock().unwrap();
    let st = g.as_mut().unwrap();
    let per_min = st.limits.per_min;
    let now = std::time::Instant::now();
    let window = std::time::Duration::from_secs(60);
    st.rate.retain(|_, (_, at)| now.duration_since(*at) < window);
    let e = st.rate.entry(ip).or_insert((0, now));
    if now.duration_since(e.1) >= window {
        *e = (0, now);
    }
    e.0 += 1;
    e.0 > per_min
}

fn handle(stream: TcpStream) -> std::io::Result<()> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if over_rate(&peer) {
        return reply(stream, "429 Too Many Requests", r#"{"error":"slow down"}"#);
    }
    let started = std::time::Instant::now();
    // The buffer wraps the socket ONCE and the cap is applied to a borrow of
    // it while the head is read. The obvious arrangement --
    // `BufReader::new(socket.take(N))`, then rebuilding a reader on the raw
    // socket afterwards -- loses every byte the first buffer had already
    // read ahead, which here is the start of the body. It broke `join`,
    // `push` and the whole challenge handshake, and it broke them exactly
    // when the body happened to arrive in the same packet as the head.
    let mut r = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    {
        // `.take` on the head alone, so a newline that never comes costs
        // 64KB rather than the process.
        let mut head = (&mut r).take(MAX_HEAD_BYTES);
        head.read_line(&mut line)?;
    }
    if line.is_empty() {
        return reply(stream, "400 Bad Request", r#"{"error":"no request line"}"#);
    }
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("/").to_string();

    let mut len = 0usize;
    let mut headers = 0usize;
    let mut head_budget = MAX_HEAD_BYTES.saturating_sub(line.len() as u64);
    loop {
        let mut h = String::new();
        let n = {
            let mut head = (&mut r).take(head_budget);
            head.read_line(&mut h)?
        };
        head_budget = head_budget.saturating_sub(n as u64);
        if head_budget == 0 {
            return reply(
                stream,
                "431 Request Header Fields Too Large",
                r#"{"error":"head too large"}"#,
            );
        }
        if n == 0 || h.trim().is_empty() {
            break;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            return reply(stream, "431 Request Header Fields Too Large", r#"{"error":"too many headers"}"#);
        }
        if started.elapsed() > DEADLINE {
            return reply(stream, "408 Request Timeout", r#"{"error":"took too long"}"#);
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    if len > MAX_BODY {
        return reply(stream, "413 Payload Too Large", r#"{"error":"too large"}"#);
    }
    // Reserved from the DECLARED length, before anything is allocated or
    // read. Checking after the read would be checking after the harm.
    let _reservation = match BodyReservation::take(len) {
        Some(r) => r,
        None => {
            return reply(
                stream,
                "503 Service Unavailable",
                r#"{"error":"relay is busy with other transfers, retry"}"#,
            )
        }
    };
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

/// A fresh random nonce, or None if the system cannot provide randomness.
///
/// The silent fallback this replaces returned 24 zero bytes when
/// /dev/urandom could not be read, which would have made the registration
/// nonce a known constant that any squatter could return as proof without
/// holding the box secret. Unreachable on a healthy host, and a silent
/// catastrophic default is still the wrong shape.
fn new_nonce() -> Option<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut buf = [0u8; 24];
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    f.read_exact(&mut buf).ok()?;
    Some(B64.encode(buf))
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
            let Some((want, _)) = st.pending.get(&key).cloned() else {
                return reply(
                    stream,
                    "401 Unauthorized",
                    r#"{"error":"no registration in progress for that pair"}"#,
                );
            };
            // A wrong proof does NOT touch the pending entry.
            //
            // It used to remove it, which handed anyone a one-request denial
            // of service: both keys are public, so an attacker posted a junk
            // proof for somebody else's pair and deleted the nonce they were
            // about to answer with, repeatable forever. Only the holder of
            // the box secret can produce the right answer, so a wrong one
            // tells the relay nothing except that somebody guessed.
            if p != want {
                return reply(
                    stream,
                    "401 Unauthorized",
                    r#"{"error":"proof does not match"}"#,
                );
            }
            // A cap on how many mailboxes exist at all.
            //
            // There was none. The first leg of registration needs no
            // authentication, and an attacker holds the secrets for keys it
            // has just generated -- so the possession proof, which stops
            // mailbox SQUATTING, does nothing to stop mailbox
            // MANUFACTURING. A reviewer traced where that bites: every
            // registration re-serialises the whole owners map and writes it,
            // so each one costs more than the last and every other request
            // waits behind it.
            if !st.owners.contains_key(&reg.box_key) && st.owners.len() >= st.limits.mailboxes {
                return reply(
                    stream,
                    "507 Insufficient Storage",
                    r#"{"error":"this relay is full"}"#,
                );
            }
            st.pending.remove(&key);
            st.owners.insert(reg.box_key.clone(), reg.sign_key.clone());
            let path = st.root.join("owners.json");
            let data = serde_json::to_vec_pretty(&st.owners).unwrap_or_default();
            // Released BEFORE the disk write. Holding the one global mutex
            // across a filesystem write that grows with the number of
            // mailboxes is how a slow disk becomes everyone's outage.
            drop(g);
            // Written to a temp file and renamed, so a kill or a power cut
            // leaves either the old map or the new one. `fs::write`
            // truncates in place, and startup turns invalid JSON into an
            // EMPTY map -- so an interrupted write silently unregistered
            // every mailbox on the relay.
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, &data).and_then(|_| std::fs::rename(&tmp, &path)).is_err() {
                let _ = std::fs::remove_file(&tmp);
                return reply(
                    stream,
                    "500 Internal Server Error",
                    r#"{"error":"could not record the registration"}"#,
                );
            }
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
            // An existing fresh claim keeps its nonce. Minting a new one on
            // every first-leg request let an attacker rotate the nonce out
            // from under the real owner by replaying leg one, which is the
            // same denial of service by another route. Returning the same
            // sealed nonce is safe: it is sealed to the owner's key, so the
            // asker learns nothing by receiving it again.
            let fresh = st
                .pending
                .get(&key)
                .filter(|(_, at)| at.elapsed() < std::time::Duration::from_secs(600))
                .map(|(n, _)| n.clone());
            let Some(nonce) = fresh.or_else(|| Some(new_nonce()?)) else {
                return reply(
                    stream,
                    "500 Internal Server Error",
                    r#"{"error":"no randomness available"}"#,
                );
            };
            let pk = crypto_box::PublicKey::from_bytes(raw);
            let Ok(ct) = pk.seal(&mut crypto_box::aead::OsRng, nonce.as_bytes()) else {
                return reply(stream, "500 Internal Server Error", r#"{"error":"seal failed"}"#);
            };
            st.pending.insert(key, (nonce, std::time::Instant::now()));
            // Evict by AGE, oldest first, never wholesale. Clearing the whole
            // map at a size limit was an unauthenticated denial of service:
            // the first leg needs no proof of anything, so 10,001 junk claims
            // wiped every legitimate proof in flight, and sustained flooding
            // kept the window shut.
            st.pending.retain(|_, (_, at)| at.elapsed() < std::time::Duration::from_secs(600));
            while st.pending.len() > 10_000 {
                if let Some(oldest) = st
                    .pending
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone())
                {
                    st.pending.remove(&oldest);
                } else {
                    break;
                }
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
    // Three bounds, checked here because `/send` is deliberately open: a
    // stranger has to be able to send a first message, so the protection
    // cannot be authentication.
    //
    // The refusal says the mailbox is full and nothing about who filled it.
    // It is a letterbox, and the person who gets to see who is sending is
    // the recipient, when they collect.
    let incoming = req.envelope.len() as u64;
    if dir_bytes(&box_dir) + incoming > st.limits.mailbox_bytes {
        return reply(stream, "507 Insufficient Storage", r#"{"error":"mailbox is full"}"#);
    }
    if dir_count(&box_dir) >= st.limits.mailbox_msgs {
        return reply(stream, "507 Insufficient Storage", r#"{"error":"mailbox is full"}"#);
    }
    // The backstop, for when many mailboxes are each individually under their
    // own limit. Walked per send, which is fine for a letterbox and would not
    // be for a file host -- said here so nobody later mistakes it for one.
    let mail_root = st.root.join("mail");
    let total: u64 = std::fs::read_dir(&mail_root)
        .map(|rd| rd.flatten().map(|e| dir_bytes(&e.path())).sum())
        .unwrap_or(0);
    if total + incoming > st.limits.store_bytes {
        return reply(stream, "507 Insufficient Storage", r#"{"error":"relay store is full"}"#);
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
    let Some(nonce) = new_nonce() else {
        return reply(stream, "500 Internal Server Error", r#"{"error":"no randomness available"}"#);
    };
    let mut g = STATE.lock().unwrap();
    let st = g.as_mut().unwrap();
    // Issued even for an unknown mailbox, and with the same shape, so the
    // endpoint does not become an oracle for which keys are registered.
    st.challenges.insert(nonce.clone(), req.box_key);
    st.challenge_age.insert(nonce.clone(), std::time::Instant::now());
    // Age-based, oldest-first, for the same reason as `pending`: /challenge
    // needs no authentication at all, so a flood that cleared the map took
    // every legitimate fetch down with it.
    let cutoff = std::time::Duration::from_secs(600);
    st.challenge_age.retain(|_, at| at.elapsed() < cutoff);
    let live: std::collections::HashSet<String> = st.challenge_age.keys().cloned().collect();
    st.challenges.retain(|n, _| live.contains(n));
    while st.challenges.len() > 10_000 {
        if let Some(oldest) = st
            .challenge_age
            .iter()
            .min_by_key(|(_, at)| *at)
            .map(|(k, _)| k.clone())
        {
            st.challenge_age.remove(&oldest);
            st.challenges.remove(&oldest);
        } else {
            break;
        }
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
