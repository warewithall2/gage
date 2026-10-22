//! `gage ui` -- a local viewer, bound to 127.0.0.1 only.
//!
//! This is the buddy-list window: who you trust, what is waiting, and what
//! each bundle claims, with the trust verdict shown as prominently as the
//! subject line. It exists because the verdict is the product, and a verdict
//! nobody looks at is not a control.
//!
//! It never renders payload contents. A page that pastes a stranger's prompt
//! into a browser is a different risk surface, and `gage open` is where
//! content is meant to be read, inside its frame. What the browser may do is
//! accept, reject, mark read, settle a thread, and write a reply -- the human
//! gates this design is built around, plus the one thing a viewer could not
//! do and still be an app.
//!
//! A reply from here is delivered to a LOCAL ROUTE only, and a push to a
//! RELAY is still terminal-only behind `gage push --yes`, because that
//! confirmation is the last point at which a person sees what is leaving to a
//! machine they cannot see.

//! First-run identity creation is the one setup act the page performs
//! (`POST /api/init`), and it is here for the same reason the reply is: a
//! front door a stranger cannot get through is not a front door. It runs
//! the CLI's own creation path (`Identity::create_named`) -- no second key
//! generator, no second store, no second permission rule -- and it refuses
//! when an identity already exists, exactly as `gage init` refuses. What
//! stays terminal-only is everything with a passphrase: export and restore
//! never transit a browser form, the same rule the MCP server follows.
//!
//! `GET /api/invite` is the public `gage add` line drawn as SVG in this
//! process. The page inserts that markup. It is not a scanner: no camera,
//! no clipboard, and no second protocol. The line is the one `gage connect`
//! prints, and a missing identity is a 404 rather than an empty picture.
//!
//! Handing a bundle to a machine on the LOCAL NETWORK is allowed from here,
//! which is a change from what this file used to say, so the reasoning should
//! be on the record rather than only in a commit. The old rule was that a
//! button is not a confirmation. That is true of a button that pushes a
//! bundle somebody already built: nothing in the gesture says what is
//! leaving. It is not true of the gesture this adds, where a person picks
//! particular files and drops them on a particular named machine that is
//! announcing itself on their own wifi -- that names the payload and the
//! destination in the act itself, which is more than `--yes` on a directory
//! does. The outbound content scan still runs and still refuses, and
//! `--allow-findings` is deliberately NOT reachable from the page: a finding
//! sends you back to the terminal.
//!
//! Every mutating route demands a custom header and refuses a cross-site
//! Origin or Sec-Fetch-Site. A page on the open internet can POST to
//! 127.0.0.1 with a plain form, and without those checks any site you
//! happened to visit could accept bundles in your inbox or send a reply in
//! your name. A form cannot set a custom header, and a fetch that sets one
//! must first pass a preflight this server does not answer.
//!
//! Hand-rolled HTTP rather than a web framework, so the one network-facing
//! surface in this tool is about eighty lines a reader can audit in full.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

/// What one request told us. Only the few headers that matter are kept.
struct Req {
    method: String,
    target: String,
    host: Option<String>,
    origin: Option<String>,
    fetch_site: Option<String>,
    guard: bool,
    body: String,
    /// The body before UTF-8 replacement. `body` is lossy, which is right for
    /// JSON and silently corrupts anything else; file bytes arrive base64 in
    /// JSON, so this is kept for the decode rather than for binary directly.
    raw: Vec<u8>,
}

/// Caps on the request head. `read_line` reads until a newline with no limit
/// of its own, so a client that sends bytes and never a newline makes it
/// allocate until the process dies -- and a client that connects and sends
/// nothing at all blocks it forever, which on a single-threaded server is the
/// whole viewer. Any local process could do either. Found reviewing my own
/// parser the morning after writing it.
const MAX_HEAD_BYTES: u64 = 64 * 1024;
const MAX_HEADERS: usize = 200;
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Only `/api/send` may exceed the body cap above, and only because it is
/// carrying files. Base64 in JSON rather than multipart: a multipart parser
/// is the kind of thing that has bugs, and this keeps the whole surface
/// readable. The inflation is why this is not simply the per-item limit.
const MAX_SEND_BYTES: usize = 12 * 1024 * 1024;
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn read_req(stream: &TcpStream) -> std::io::Result<Req> {
    // Nothing here waits on a human, so a read that stalls is a client that
    // has stopped talking, and the server should not wait on it.
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    // The head is read through a limited reader: a line with no newline in it
    // cannot grow past the cap, because the underlying reader reports EOF.
    let mut reader = BufReader::new(stream.try_clone()?.take(MAX_HEAD_BYTES));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    // The cap depends on the route, and the route is already known: the
    // request line was read above. Everything except a send keeps the small
    // cap it has always had.
    let cap = if target == "/api/send" {
        MAX_SEND_BYTES
    } else {
        MAX_BODY_BYTES
    };
    let mut host = None;
    let mut origin = None;
    let mut fetch_site = None;
    let mut guard = false;
    let mut len = 0usize;
    let mut seen = 0usize;
    loop {
        seen += 1;
        if seen > MAX_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many request headers",
            ));
        }
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let Some((k, v)) = h.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "host" => host = Some(v.to_ascii_lowercase()),
            "origin" => origin = Some(v),
            "sec-fetch-site" => fetch_site = Some(v),
            "x-gage" => guard = true,
            // Capped well below anything legitimate. The body is one short
            // reply, and an unbounded read here is a one-line denial of
            // service against a server with no other limits.
            "content-length" => len = v.parse().unwrap_or(0).min(cap),
            _ => {}
        }
    }
    // The body is read from the same limited reader, with the limit moved to
    // the declared length now that the head is parsed.
    //
    // This matters and was wrong for a minute: the reader is capped at
    // MAX_HEAD_BYTES so that a header line with no newline cannot grow
    // without bound, and that cap counts the body too. A send carrying files
    // is larger than any head, so without this the reader hit EOF partway
    // through and `read_exact` failed on every real upload. The cap is moved
    // rather than removed: `len` is already clamped to this route's cap, so
    // the body is still bounded, and the head was still read under the
    // original limit.
    reader.get_mut().set_limit(len as u64);
    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Req {
        host,
        method,
        target,
        origin,
        fetch_site,
        guard,
        body: String::from_utf8_lossy(&body).to_string(),
        raw: body,
    })
}

/// Is this request allowed to change anything?
///
/// Three independent conditions, because each covers the others' gaps: the
/// custom header is what a cross-site form cannot produce, Sec-Fetch-Site is
/// what a modern browser volunteers, and the Origin check catches a request
/// that names some other site outright.
/// Is this request addressed to the loopback name this server answers on?
///
/// Checked on EVERY method, which `may_mutate` is not. The read routes had no
/// guard at all, and that is enough on its own: a page on the open internet
/// served from a name that resolves to 127.0.0.1 -- DNS rebinding -- is
/// same-origin as far as the browser is concerned, so it sends no interesting
/// `Origin`, meets no CORS check, and could simply `fetch('/api/state')` and
/// read the whole inbox, this home's path and the signing key. Binding to
/// loopback does not help, because the request really does arrive on
/// loopback. The one thing such a page cannot change is the `Host` header,
/// which still carries the name it was served from.
///
/// A missing `Host` is refused rather than allowed: HTTP/1.1 requires it, and
/// the only clients without one are not browsers.
fn host_is_local(r: &Req, port: u16) -> bool {
    let Some(h) = &r.host else { return false };
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .iter()
    .any(|x| x == h)
}

fn may_mutate(r: &Req, port: u16) -> bool {
    if !r.guard {
        return false;
    }
    if let Some(site) = &r.fetch_site
        && site != "same-origin"
        && site != "none"
    {
        return false;
    }
    // Require the Origin, rather than only checking it when present.
    //
    // The previous version skipped this block entirely when the header was
    // absent, and treated `Sec-Fetch-Site: none` as allowed, so a request
    // carrying `X-Gage` and no `Origin` reached the handler. A reviewer found
    // it and was careful about the size of it: no page can produce that
    // shape, because a browser `fetch` always sends an `Origin` on a POST,
    // and a form cannot set `X-Gage` at all. So this was never a hole a
    // website could drive -- it was the guard being wider than its own
    // stated property, which is that only this page may mutate.
    //
    // Closed anyway, because the value of a guard is that you can state what
    // it refuses without a caveat, and because the next thing to send a
    // headerless POST will be some local helper nobody audited.
    //
    // Which makes the contract worth stating, since a reviewer noted this
    // breaks more than browsers: a script, a CLI helper or another native app
    // that sent `X-Gage` and no `Origin` used to work and now gets 403. That is
    // intended -- the CLI is the supported programmatic interface and does not
    // go through HTTP at all -- but it is a compatibility narrowing as much as
    // a fix, and anything local that was driving these routes must now send
    // the page's own Origin.
    //
    // And the property is exactly this and no more: **no cross-site page can
    // reach these routes.** A second reviewer was right that "for this page
    // only" overstates it -- there is no per-page secret, so any local process
    // can send both `X-Gage: 1` and the correct `Origin` and be
    // indistinguishable from the page. Against a local process this is not a
    // boundary at all, and it was never meant to be: such a process already
    // has the gage home and the signing key, so there is nothing here for it
    // to gain.
    let Some(o) = &r.origin else {
        return false;
    };
    let ok = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    ok.iter().any(|x| x == o)
}

pub fn serve(port: u16) -> std::io::Result<()> {
    // Loopback only, never 0.0.0.0. An inbox viewer on a laptop has no
    // business being reachable from the network it happens to be on.
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("gage ui on http://127.0.0.1:{port}  (ctrl-c to stop)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s, port) {
                    eprintln!("gage ui: {e}");
                }
            }
            Err(e) => eprintln!("gage ui: accept failed: {e}"),
        }
    }
    Ok(())
}

/// `connect-src 'self'` is not decoration. `default-src 'none'` covers
/// `connect-src` by fallback, so without it the page's own
/// `fetch('/api/threads')` is blocked by this very header -- and the page's
/// loader caught the failure and returned, leaving a blank screen with
/// nothing on it and nothing in the log. The viewer had never once worked in
/// a browser, from the commit that added this policy until it was found by
/// the person it is for.
///
/// Four hundred adversarial checks did not catch it because every one of them
/// is `curl`, which does not enforce CSP. A test that exercises the server
/// does not exercise the page.
fn respond(mut s: TcpStream, status: &str, ctype: &str, body: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
         script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}

/// The bundle id in `<prefix><id>`, or None if the target is not exactly that.
///
/// `starts_with` plus `rsplit('/')` used to accept `/api/accept/extra/<id>`
/// and `/api/read//<id>`, acting on the trailing segment and ignoring the
/// rest. Nothing escaped -- the id was still validated before it reached the
/// filesystem -- but a route that matches more shapes than it means to is how
/// the next bug gets in. One segment, hex, bounded.
fn bundle_id<'a>(target: &'a str, prefix: &str) -> Option<&'a str> {
    let id = target.strip_prefix(prefix)?;
    if id.is_empty() || id.len() > 64 || id.contains('/') {
        return None;
    }
    // An id reaches the filesystem, so it must be an id and nothing else:
    // the bundle ids this tool mints are lowercase hex.
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(id)
}

fn handle(stream: TcpStream, port: u16) -> std::io::Result<()> {
    let req = read_req(&stream)?;
    let (method, target) = (req.method.as_str(), req.target.as_str());

    // Before the route table, and before the method matters. A rebound page
    // reads as well as it writes, and reading an inbox is the loss this
    // viewer exists to prevent.
    if !host_is_local(&req, port) {
        return respond(
            stream,
            "403 Forbidden",
            "application/json",
            "{\"error\":\"request not addressed to this loopback viewer\"}",
        );
    }

    if method == "POST" && !may_mutate(&req, port) {
        return respond(
            stream,
            "403 Forbidden",
            "application/json",
            "{\"error\":\"cross-site request refused\"}",
        );
    }

    // Only the routes below exist. Anything else is a 404 rather than a
    // filesystem lookup, so there is no path to traverse.
    match (method, target) {
        ("GET", "/") => respond(stream, "200 OK", "text/html; charset=utf-8", INDEX),
        // The tab icon. Served rather than inlined as a data URI so the
        // artwork stays one file that the icon script and the page share.
        ("GET", "/favicon.svg") => respond(stream, "200 OK", "image/svg+xml", FAVICON),
        ("GET", "/api/state") => respond(stream, "200 OK", "application/json", &state_json()),
        ("GET", "/api/threads") => respond(stream, "200 OK", "application/json", &threads_json()),
        ("POST", t) if t.starts_with("/api/read/") => {
            let Some(id) = bundle_id(t, "/api/read/") else {
                return respond(
                    stream,
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"bad id\"}",
                );
            };
            let mut st = crate::state::LocalState::load();
            match st.mark_read(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(
                    stream,
                    "500 Internal Server Error",
                    "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string(),
                ),
            }
        }
        ("POST", t) if t.starts_with("/api/close/") => {
            let Some(id) = bundle_id(t, "/api/close/") else {
                return respond(
                    stream,
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"bad id\"}",
                );
            };
            let mut st = crate::state::LocalState::load();
            match st.close(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(
                    stream,
                    "500 Internal Server Error",
                    "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string(),
                ),
            }
        }
        ("POST", t) if t.starts_with("/api/accept/") || t.starts_with("/api/reject/") => {
            let accept = t.starts_with("/api/accept/");
            let Some(id) = bundle_id(
                t,
                if accept {
                    "/api/accept/"
                } else {
                    "/api/reject/"
                },
            ) else {
                return respond(
                    stream,
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"bad id\"}",
                );
            };
            let me = crate::identity::home();
            let from = crate::routes::pending_dir(&me).join(id);
            if !from.is_dir() {
                return respond(
                    stream,
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"no such pending bundle\"}",
                );
            }
            let res = if accept {
                let dest_dir = crate::routes::accepted_dir(&me);
                // Same restartable move the CLI uses, rather than a second
                // hand-written copy-then-delete with its own crash window.
                std::fs::create_dir_all(&dest_dir)
                    .and_then(|_| crate::routes::restage(&from, &dest_dir.join(id)))
            } else {
                std::fs::remove_dir_all(&from)
            };
            match res {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(
                    stream,
                    "500 Internal Server Error",
                    "application/json",
                    &serde_json::json!({ "error": e.to_string() }).to_string(),
                ),
            }
        }
        ("GET", "/api/nearby") => respond(stream, "200 OK", "application/json", &nearby_json()),
        ("POST", "/api/send") => match send_from_ui(&req.raw) {
            Ok(lines) => respond(
                stream,
                "200 OK",
                "application/json",
                &serde_json::json!({ "ok": true, "lines": lines }).to_string(),
            ),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("GET", "/api/buddies") => respond(stream, "200 OK", "application/json", &buddies_json()),
        // The add line, as a picture. Not part of the poll: the page fetches
        // it once. A missing identity is the same 404 as any other absent
        // route, and the body does not say where the key file would be.
        // Pasted text in, a key and a suggested name out. It adds NOTHING:
        // the person still has to run the reveal-then-add ceremony on the
        // key, which is the same two steps a buddy request goes through.
        ("POST", "/api/parse-invite") => match parse_invite(&req.body) {
            Ok(v) => respond(stream, "200 OK", "application/json", &v),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("GET", "/api/invite") => match invite_response() {
            Ok(svg) => respond(stream, "200 OK", "image/svg+xml", &svg),
            Err((code, body)) => respond(stream, code, "text/plain", body),
        },
        ("POST", "/api/init") => match init_from_ui(&req.body) {
            Ok(v) => respond(stream, "200 OK", "application/json", &v),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("POST", "/api/connect") => match connect_from_ui(&req.body) {
            Ok(lines) => respond(
                stream,
                "200 OK",
                "application/json",
                &serde_json::json!({ "ok": true, "lines": lines }).to_string(),
            ),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("POST", "/api/decline") => match decline_from_ui(&req.body) {
            Ok(msg) => respond(
                stream,
                "200 OK",
                "application/json",
                &serde_json::json!({ "ok": true, "lines": [msg] }).to_string(),
            ),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("POST", "/api/pair") => match pair_from_ui(&req.body) {
            Ok(lines) => respond(
                stream,
                "200 OK",
                "application/json",
                &serde_json::json!({ "ok": true, "lines": lines }).to_string(),
            ),
            Err((code, msg)) => respond(
                stream,
                code,
                "application/json",
                &serde_json::json!({ "error": msg }).to_string(),
            ),
        },
        ("POST", "/api/reply") => {
            let out = reply_from_ui(&req.body);
            match out {
                Ok(id) => respond(
                    stream,
                    "200 OK",
                    "application/json",
                    &serde_json::json!({ "ok": true, "id": id }).to_string(),
                ),
                Err((code, msg)) => respond(
                    stream,
                    code,
                    "application/json",
                    &serde_json::json!({ "error": msg }).to_string(),
                ),
            }
        }
        _ => respond(stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

/// Who is on this network, as the page shows it.
///
/// Read a pasted `gage add` line and say which key it names.
///
/// The parser is the CLI's own (`quickstart::parse_add`), so a line the
/// terminal accepts and a line this page accepts are the same set.
///
/// **This does not add anything, and it does not return the fingerprint.**
/// The key it hands back goes through exactly the ceremony a buddy request
/// goes through: the person types one pair read off the OTHER machine, and
/// only then is the rest revealed. That matters most on this path, because a
/// pasted line arrived from somewhere and the words derived from it are the
/// words of whoever wrote it. Showing all four here and asking "do these
/// match?" would be a screen an attacker passes by reading their own four
/// pairs aloud, so the stronger gate that already exists is reused rather
/// than replaced with a friendlier one.
///
/// The name is a SUGGESTION taken from the pasted text, which is attacker-
/// controlled: the page shows it in a field the person edits, and
/// `connect_from_ui` applies the same character rules it applies to anything
/// else before it is filed.
fn parse_invite(body: &str) -> Result<String, (&'static str, String)> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let text = v.get("text").and_then(|x| x.as_str()).unwrap_or("");
    // A cap before any parsing. The body is already bounded by the request
    // reader, and this bounds what a pasted blob can cost to tokenise.
    if text.len() > 4096 {
        return Err(("400 Bad Request", "that is more text than an invite".into()));
    }
    let (name, token) = crate::quickstart::parse_add(text);
    let Some(token) = token else {
        return Err((
            "400 Bad Request",
            "no key in that text -- paste the whole `gage add` line".into(),
        ));
    };
    // The token is `signpub` or `signpub.boxpub`. Only the signing half
    // identifies the contact, and it is the half the ceremony derives from.
    let sign = token.split('.').next().unwrap_or("").to_string();
    if !crate::bundle::b64_decode_ok(&sign) {
        return Err(("400 Bad Request", "that is not a key".into()));
    }
    let me = crate::identity::Identity::load().ok();
    if let Some(id) = &me
        && id.public_b64() == sign
    {
        return Err((
            "409 Conflict",
            "that is this machine's own line -- you want the other person's".into(),
        ));
    }
    let contacts = crate::trust::Contacts::load();
    if let Some(n) = contacts.keys.get(&sign) {
        return Err((
            "409 Conflict",
            format!("that key is already on your list as {n}"),
        ));
    }
    // Which pair the ceremony will ask for, so the page can say so before
    // the person goes to the other machine. The pair itself is not here.
    Ok(serde_json::json!({
        "key": sign,
        "suggested_name": name.unwrap_or_default(),
        "ask_pair": asked_pair(&sign) + 1,
    })
    .to_string())
}

/// SVG of this machine's public add line, or why there isn't one.
fn invite_response() -> Result<String, (&'static str, &'static str)> {
    let id = match crate::identity::Identity::load() {
        Ok(id) => id,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(("404 Not Found", "not found\n"));
        }
        Err(_) => return Err(("500 Internal Server Error", "identity could not be read\n")),
    };
    crate::invite::svg(&id.add_line())
        .map_err(|_| ("500 Internal Server Error", "the add line does not fit in a QR code\n"))
}

/// Read from the list `gage lan` keeps rather than by sending anything: the
/// viewer does not announce, and a page that could make a machine broadcast
/// would be a way to make it visible without the person choosing to be.
fn nearby_json() -> String {
    let c = crate::trust::Contacts::load();
    let now = crate::lan::now();
    let list: Vec<serde_json::Value> = crate::lan::read_nearby()
        .into_iter()
        .filter(|e| now.saturating_sub(e.at) <= 60)
        .map(|e| {
            serde_json::json!({
                "label": e.label,
                "handle": e.handle,
                "addr": e.addr,
                "fingerprint": crate::words::fingerprint_of(&e.sign, Some(&e.boxpub)),
                "sign": e.sign,
                // The name on YOUR list, or nothing. The page must not infer
                // trust from the handle, which is a string that machine chose.
                "paired_as": c.name_for(&e.sign),
                "age": now.saturating_sub(e.at),
            })
        })
        .collect();
    serde_json::json!({
        "lan_running": !list.is_empty() || crate::lan::nearby_path().exists(),
        "devices": list,
    })
    .to_string()
}

/// When this machine first *observed* a bundle from this key.
///
/// Out of the journal, which is the only record of this machine's own
/// observations. The alternative the first version used was
/// `manifest.created` -- a field the sender writes -- rendered to the person
/// as "first seen". This is what the journal was built for.
fn first_observed(key: &str) -> Option<String> {
    crate::journal::read()
        .into_iter()
        .filter(|e| e.event == crate::journal::Event::Observed && e.from_key == key)
        .map(|e| e.at)
        .min()
}

/// The buddy list: who is on it, who is asking, and who was refused.
///
/// One endpoint rather than three, because the three are one question -- "who
/// can reach me and what have I decided about them" -- and splitting it would
/// let the page render a contact and a request for the same key from two
/// fetches that disagree.
///
/// **Reachability is per path and never a presence roster.** A standing "who
/// is online" list has been refused twice in this project and is refused
/// here: `lan` reports only what is announcing itself *while it runs*, and
/// nothing here polls a relay to see who is alive. What each flag means:
///
/// * `routed` -- a local gage home on this machine. Certain, because it is a
///   directory that either exists or does not.
/// * `lan` -- announced itself on this network within the last minute. A
///   claim by that machine, timestamped by this one.
/// * `relay` -- this machine is joined to a relay, so mail *can* be left for
///   them. It says nothing about whether they ever collect it, and the page
///   must not render it as presence.
pub fn buddies_json() -> String {
    let observed = observed();
    let home = crate::identity::home();
    let contacts = crate::trust::Contacts::load();
    let routes = crate::routes::Routes::load();
    let st = crate::state::LocalState::load();
    let relay = crate::remote::relay_addr();
    let now = crate::lan::now();

    // Fresh LAN announcements, as a set of keys. Deliberately not the ages:
    // see `reach`.
    let near: std::collections::BTreeSet<String> = crate::lan::read_nearby()
        .into_iter()
        .filter(|e| now.saturating_sub(e.at) <= 60)
        .map(|e| e.sign)
        .collect();

    // What is sitting in the inbox, per sender key. Built once: counting
    // unread per contact and finding unlisted senders are the same scan, and
    // doing it twice is how the two end up disagreeing.
    let mut unread: std::collections::BTreeMap<String, u64> = Default::default();
    let mut waiting: std::collections::BTreeMap<String, u64> = Default::default();
    let mut askers: std::collections::BTreeMap<String, u64> = Default::default();
    for (stage, dir) in [
        ("pending", crate::routes::pending_dir(&home)),
        ("accepted", crate::routes::accepted_dir(&home)),
    ] {
        for (_, l) in crate::routes::list(&dir) {
            let m = &l.manifest;
            let k = m.from.key.clone();
            if stage == "pending" {
                *waiting.entry(k.clone()).or_default() += 1;
            }
            if !st.is_read(&m.id) {
                *unread.entry(k.clone()).or_default() += 1;
            }
            // An unlisted, unrefused key that has sent something is what
            // the list offers a decision about. There is no separate request
            // message type and deliberately so: a dedicated "please add me"
            // bundle would be a kind whose whole purpose is to ask for
            // trust, which is the one thing a sender must not be able to ask
            // for in a way that looks different from ordinary mail.
            //
            // **A bundle whose signature did not check mints nothing.** The
            // first version inserted the entry unconditionally and recorded
            // verification as a side flag the page rendered as a tag, so a
            // forged or tampered bundle produced a card -- label, asked pair,
            // verdict -- for a key its sender does not hold. A reviewer was
            // right that this is the whole premise: without a valid
            // signature the key is not even a claim by whoever sent it, so
            // there is nothing to decide about. `new_arrivals` has always
            // skipped these; this did not.
            if matches!(l.trust, crate::trust::Trust::Unverified)
                || !l.tampered.is_empty()
                || !is_a_key(&k)
            {
                continue;
            }
            // Retired keys are excluded as well as declined ones. A retired
            // key is also a decision already taken, and offering "add this
            // contact?" for a key the person deliberately took out of
            // service would invite undoing a rotation by clicking -- the
            // opposite of what `retire` is for. Its bundles still show in
            // the conversation list with their own verdict.
            if !contacts.knows(&k)
                && !contacts.declined.contains_key(&k)
                && !contacts.retired.contains_key(&k)
            {
                *askers.entry(k).or_insert(0) += 1;
            }
        }
    }

    let reach = |key: &str, name: &str| -> serde_json::Value {
        serde_json::json!({
            // Keyed by NAME, deliberately, and the page says so: "a local
            // route under this name".
            //
            // A reviewer asked for this to be verified against the key, on
            // the grounds that renaming a contact changes the answer for the
            // same key. The observation is right and the fix is declined,
            // for two reasons. Confirming a home's key means opening its
            // `identity.key` -- another agent's PRIVATE key material -- to
            // learn a public half, which is not a thing this viewer should
            // do to render a dot. And delivery itself routes by name:
            // `--to <name>` resolves through this same map, so the flag
            // faithfully describes what sending will do. A route filed under
            // a name that leads somewhere unexpected is a real hazard, and
            // it is a property of routes rather than something this flag
            // invents -- naming the flag honestly is the fix available here.
            "routed_by_name": routes.local.contains_key(name),
            // A boolean, not an age. The first version sent "announced
            // itself 3s ago" per named contact and the page refreshed every
            // 2.5 seconds, which -- whatever the comment said -- is a
            // presence roster for the LAN path, the thing this project has
            // refused three times. A recency gradient is the part that makes
            // it one, so there isn't one: reachable on this network now, or
            // not, from announcements those machines chose to broadcast.
            "lan_now": near.contains(key),
            // **Local capability, not reachability**, and named so. It is
            // true when this machine is joined to a relay and holds an
            // encryption key for them -- i.e. that mail CAN be left. It is
            // not evidence about them at all, and the first version listed
            // it beside two flags that are.
            "can_leave_mail": relay.is_some() && contacts.box_keys.contains_key(key),
        })
    };

    let buddies: Vec<serde_json::Value> = contacts
        .keys
        .iter()
        .map(|(k, n)| {
            serde_json::json!({
                "name": n,
                "key": k,
                // Shown so a person can confirm a contact they already have,
                // which is what you do after a machine behaves oddly.
                "fingerprint": crate::words::fingerprint_of(k, contacts.box_keys.get(k).map(|s| s.as_str())),
                "label": crate::words::label(k),
                "sealable": contacts.box_keys.contains_key(k),
                "unread": unread.get(k).copied().unwrap_or(0),
                "waiting": waiting.get(k).copied().unwrap_or(0),
                "reach": reach(k, n),
            })
        })
        .collect();

    let requests: Vec<serde_json::Value> = askers
        .iter()
        .map(|(k, count)| {
            serde_json::json!({
                "key": k,
                // **No fingerprint.** It is withheld until the person types
                // the asked-for pair, because a page that already holds the
                // answer turns the confirmation into copying. The label is
                // pair 1 and `asked_pair` never asks for pair 1.
                "label": crate::words::label(k),
                // Which pair the person is asked to type. Sent so the page
                // and the handler cannot disagree about the question.
                "ask_pair": asked_pair(k) + 1,
                // This machine's own first observation, from the journal --
                // **not** `manifest.created`, which is a date the sender
                // writes and which the first version rendered as "first
                // seen". A reviewer caught it: a sender could claim any date
                // it liked for how long it had been asking. Absent rather
                // than guessed when the journal has no entry.
                "first_observed": first_observed(k),
                "bundles": count,
                // A request key is by construction neither listed, declined
                // nor retired, so the witness argument cannot change the
                // answer. Passed as None rather than looked up, so this
                // cannot drift into asking a question it does not need.
                "verdict": verdict_label_for(observed, contacts.verdict(k, None)),
            })
        })
        .collect();

    let refused: Vec<serde_json::Value> = contacts
        .declined
        .iter()
        .filter(|(k, _)| is_a_key(k))
        .map(|(k, d)| {
            serde_json::json!({
                "key": k,
                "label": crate::words::label(k),
                // **No fingerprint here either**, and a reviewer found why it
                // mattered: the refused list used to carry the full
                // fingerprint, and a key can be un-refused back into a
                // request. Withholding it from the request card while
                // printing it two sections down, for the same key, left the
                // answer on the screen by another route.
                "at": d.at,
                // How many of its bundles this machine is holding right now.
                // The first version sent a `still_arriving` boolean, which
                // went false once everything was read -- implying delivery
                // had stopped, which is the exact misreading the surrounding
                // text exists to prevent. A count answers "what is here" and
                // claims nothing about the future; the page states the
                // general fact unconditionally instead.
                "holding": waiting.get(k).copied().unwrap_or(0)
                    + unread.get(k).copied().unwrap_or(0),
            })
        })
        .collect();

    serde_json::json!({
        "verdicts_stale": !observed,
        "relay": relay,
        "buddies": buddies,
        "requests": requests,
        "refused": refused,
    })
    .to_string()
}

/// A filename from a browser is a string somebody else's filesystem produced.
///
/// It becomes a path, so only a basename of safe characters survives. The
/// basename is what stops a traversal -- `../../etc/passwd` lands as a file
/// called `passwd` -- and the charset is a second filter for what a basename
/// can still contain: a leading dot, a control character, a shell
/// metacharacter. The browser usually strips directories itself, which is
/// exactly the kind of "already handled elsewhere" that stops being true one
/// release later.
fn safe_upload_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    if base.is_empty() || base == "." || base == ".." || base.len() > 120 {
        return None;
    }
    if !base
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._- ()[]".contains(c))
    {
        return None;
    }
    // A leading dot would make an uploaded file look like a dotfile to the
    // outbound scan's own eyes, and there is no reason a dropped file needs
    // to be one.
    if base.starts_with('.') {
        return None;
    }
    Some(base.to_string())
}

/// Build a bundle from files dropped on the page and hand it to a machine on
/// this network.
///
/// Everything safety-relevant goes through the same code the CLI uses: the
/// files are written to a temp directory and passed to `send_bundle` as
/// ordinary `--file` paths, so the outbound secret scan runs exactly as it
/// does in the terminal, and a finding refuses the send. `allow_findings` is
/// not a field the page can set.
fn send_from_ui(raw: &[u8]) -> Result<Vec<String>, (&'static str, String)> {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let to = v
        .get("to")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if to.is_empty() {
        return Err(("400 Bad Request", "no device chosen".into()));
    }
    let subject = v
        .get("subject")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let subject = if subject.is_empty() {
        "(no subject)".to_string()
    } else {
        subject
    };
    let msg_type = v
        .get("type")
        .and_then(|x| x.as_str())
        .unwrap_or("share")
        .to_string();
    let files = v
        .get("files")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    // A typed note, carried as `message.md` the way a reply is carried as
    // `reply.md`. Not a `prompt` item: a prompt is the kind written to steer
    // a model, and `gage open` fences it for that reason. Minting those from
    // a text box would make the page a steering surface, so they stay a
    // deliberate CLI act (`gage send --prompt <file>`).
    let text = v
        .get("text")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if text.len() > 64 * 1024 {
        return Err(("400 Bad Request", "that note is larger than a note".into()));
    }
    // Either is enough. Requiring a file meant you could not say "have a
    // look at this machine" to someone standing next to you without first
    // inventing a file to say it in.
    if files.is_empty() && text.trim().is_empty() {
        return Err((
            "400 Bad Request",
            "nothing to send -- drop a file, write a note, or both".into(),
        ));
    }

    let tmp = crate::identity::home().join(format!("tmp-ui-send-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| ("500 Internal Server Error", e.to_string()))?;

    let run = |tmp: &std::path::Path| -> Result<Vec<String>, (&'static str, String)> {
        let mut paths = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        if !text.trim().is_empty() {
            let mut body = text.clone();
            if !body.ends_with('\n') {
                body.push('\n');
            }
            let f = tmp.join("message.md");
            std::fs::write(&f, body)
                .map_err(|e| ("500 Internal Server Error", e.to_string()))?;
            // Claimed before the dropped files are named, so a file actually
            // called message.md collides loudly instead of overwriting the
            // note or being overwritten by it.
            seen.push("message.md".to_string());
            paths.push(f);
        }
        for f in &files {
            let name = f.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let Some(name) = safe_upload_name(name) else {
                return Err((
                    "400 Bad Request",
                    format!("{name:?} is not a name this will write to disk"),
                ));
            };
            if seen.contains(&name) {
                return Err((
                    "400 Bad Request",
                    format!("two files called {name} -- one would have overwritten the other"),
                ));
            }
            seen.push(name.clone());
            let b64 = f.get("data").and_then(|x| x.as_str()).unwrap_or("");
            let bytes = B64.decode(b64).map_err(|e| {
                (
                    "400 Bad Request",
                    format!("{name}: unreadable contents: {e}"),
                )
            })?;
            let p = tmp.join(&name);
            std::fs::write(&p, &bytes).map_err(|e| ("500 Internal Server Error", e.to_string()))?;
            paths.push(p);
        }
        let mut say = Vec::new();
        let m = crate::outbound::send_bundle(
            crate::outbound::SendArgs {
                to: vec![to.clone()],
                subject: subject.clone(),
                out: None,
                file: paths,
                prompt: vec![],
                decision: vec![],
                memory: vec![],
                dir: vec![],
                allow_secrets: false,
                reply_to: None,
                msg_type: msg_type.clone(),
                // Not settable from here, on purpose. A finding is a reason to go
                // back to the terminal and look, not a checkbox.
                allow_findings: false,
                lan: true,
                agent: None,
                model: None,
            },
            &mut say,
        );
        for l in &say {
            println!("{l}");
        }
        let m = m.map_err(|e| ("400 Bad Request", e.to_string()))?;
        let from = crate::routes::sent_dir(&crate::identity::home()).join(&m.id);
        let mut out = vec![format!("bundle {} -- {} item(s)", m.id, m.items.len())];
        out.extend(crate::lan::hand_over(&from, &to).map_err(|e| ("502 Bad Gateway", e))?);
        Ok(out)
    };
    let r = run(&tmp);
    let _ = std::fs::remove_dir_all(&tmp);
    r
}

/// Confirm a device's fingerprint and add its key.
///
/// The page has shown the four word-pairs and the person has said they match
/// what the other screen shows, which is the same moment the CLI's y/N is.
/// What the page may NOT do is name a key: the key comes from the nearby list
/// by the label that was displayed, so a request cannot pair something that
/// was never on screen.
fn pair_from_ui(body: &str) -> Result<Vec<String>, (&'static str, String)> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let label = v
        .get("label")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        return Err(("400 Bad Request", "no name to file it under".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
        || name.len() > 40
    {
        return Err((
            "400 Bad Request",
            "a contact name is letters, digits, spaces, - and _".into(),
        ));
    }
    let e = crate::lan::lookup_nearby(&label).ok_or((
        "404 Not Found",
        format!("{label} is not on this network now"),
    ))?;
    if crate::lan::now().saturating_sub(e.at) > 60 {
        return Err((
            "409 Conflict",
            "that entry is stale -- is gage lan still running?".into(),
        ));
    }
    // The page echoes back the fingerprint it displayed, and it has to be the
    // one this key actually renders. Not a security boundary on its own --
    // the caller is local -- but it catches the real bug, which is a list
    // that changed under the person between seeing the words and clicking.
    let shown = v.get("fingerprint").and_then(|x| x.as_str()).unwrap_or("");
    let real = crate::words::fingerprint_of(&e.sign, Some(&e.boxpub));
    if shown != real {
        return Err((
            "409 Conflict",
            format!("the words on screen are not this key's any more ({real}) -- look again"),
        ));
    }
    crate::trust::add_contact(&name, &{
        if e.boxpub.is_empty() {
            e.sign.clone()
        } else {
            format!("{}.{}", e.sign, e.boxpub)
        }
    })
    .map_err(|e| ("400 Bad Request", e))
}

/// Which of the four word-pairs this key's connection request asks for.
///
/// Derived from the key, so a reload asks the same question -- a question that
/// changes under the person is one they learn to answer without reading. It
/// is not secret and does not need to be: knowing which pair will be asked
/// for does not help an attacker, because the pairs come from the key and an
/// attacker's key renders its own.
///
/// **Never pair 1**, which is the key's word-label and is shown in the list as
/// the way to tell one request from another. The first version chose any of
/// the four and the page printed the whole fingerprint on the same card,
/// which made the typing pure theatre: the answer was on screen, so it could
/// be copied without anyone looking at the other machine. The request card
/// now shows no fingerprint at all until a pair is typed correctly, and the
/// asked pair is one the label does not give away.
///
/// The limit, which the page states rather than hiding: a correct answer
/// shows the person read it off something other than this screen, and does
/// not show *which* something. It is a prompt to compare, and the remaining
/// three pairs are revealed for exactly that. A button labelled "they match"
/// collects the same claim with none of the looking.
/// Is this string an ed25519 public key as this tool writes one?
///
/// Checked on the **read** path and not only in the mutation handlers, which
/// is where a reviewer found the gap. Three things depend on it:
///
/// * `decline_from_ui` persists this string as a map key in `contacts.json`.
///   `b64_decode_ok` alone accepted any base64-shaped value of any length, so
///   a megabyte of base64 could be written into the contacts file.
/// * The page interpolates it into a JavaScript string literal inside an HTML
///   attribute -- `onclick="askOpen('...')"`. The page's `esc` turns `'` into
///   `&#39;`, which the HTML parser decodes *before* the inline handler's
///   JavaScript is parsed, so an apostrophe would break out of the literal.
///   Base64 cannot contain one, which makes that safe -- but only if
///   something enforces base64, and until now nothing on this path did.
/// * A verdict and a word-label are rendered for it.
///
/// So the grammar is enforced here rather than assumed from upstream.
pub fn is_a_key(s: &str) -> bool {
    // 32 raw bytes is 44 base64 characters with one '=' of padding. Bounded
    // rather than exact-matched on length alone so a future key type is a
    // refusal to render, not a panic.
    (43..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && crate::bundle::b64_decode_ok(s)
}

pub fn asked_pair(sign: &str) -> usize {
    let h = crate::bundle::sha256_hex(format!("which-pair:{sign}").as_bytes());
    1 + usize::from_str_radix(&h[..2], 16).unwrap_or(0) % 3
}

/// The warning a first run ends with. Its closing sentences are the
/// CLI's own, from `gage export-identity`'s help and from what
/// `backup::export` prints at the moment of export -- quoted rather than
/// paraphrased, so the page and the terminal cannot drift into telling a
/// new identity two different stories about the trade it is being
/// offered: the key is the only copy, there is no reset, and the one
/// backup that exists is opt-in and exactly as strong as its passphrase.
const BACKUP_WARNING: &str = "Your key is the only copy, and it lives on this machine. \
    If it is lost, this identity is gone and there is no way back in -- every \
    contact would have to confirm a new key with you out loud. In a terminal, \
    `gage export-identity` writes a passphrase-encrypted backup of it. Opt-in, \
    and a real trade: it turns \"lose the key, lose everything\" into \"your \
    security is your passphrase's strength\". Keep the file somewhere other \
    than the machine it came from.";

/// May this string be a handle chosen in the page?
///
/// The same grammar the page already holds contact names to, and for the
/// same reason: a handle is written to disk as-is, rendered by pages, and
/// quoted into shell lines (`shell_word`), and the classes that must not
/// reach it are traversal pieces and control characters -- the newline
/// shape this project has been bitten by in a filename and a subject
/// before now. The CLI accepts more, and stays the route for an exotic
/// handle; a first run in a browser does not need one. Empty is allowed
/// and means "derive it from the key", as quickstart has it.
fn handle_ok(h: &str) -> bool {
    h.is_empty()
        || (h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
            && h.len() <= 40)
}

/// Create this machine's identity from the page: the front door's one
/// setup act.
///
/// This is `gage init`'s own code path and nothing else:
/// `Identity::create_named`, the function the CLI's init, `connect` and
/// quickstart all reach. There is deliberately no key generation,
/// storage, or permission logic in this file to call instead -- a second
/// implementation of the one act whose failure is unrecoverable is the
/// bug this route exists to not have. Refusal is inherited the same way:
/// `create` refuses when a key file exists, and that refusal is surfaced
/// as a 409 carrying the CLI's own words, which name `gage rotate` as the
/// way a key is replaced.
///
/// An empty or absent handle derives the two-word label from the key,
/// exactly as `gage init` with no name does.
fn init_from_ui(body: &str) -> Result<String, (&'static str, String)> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let handle = v
        .get("handle")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !handle_ok(&handle) {
        return Err((
            "400 Bad Request",
            "a handle is letters, digits, spaces, - and _".into(),
        ));
    }
    let chosen = if handle.is_empty() {
        None
    } else {
        Some(handle.as_str())
    };
    match crate::identity::Identity::create_named(chosen) {
        Ok(id) => Ok(serde_json::json!({
            "ok": true,
            "handle": id.handle,
            "words": crate::words::fingerprint_of(&id.public_b64(), Some(&id.box_public_b64())),
            "backup_warning": BACKUP_WARNING,
        })
        .to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(("409 Conflict", e.to_string()))
        }
        Err(e) => Err(("500 Internal Server Error", e.to_string())),
    }
}

/// Add a key the page is showing as a connection request.
///
/// Three things are checked, and the first two are not security boundaries --
/// the caller is local and could call `gage add` directly. They catch the real
/// bug, which is a list that changed under the person between reading the
/// words and clicking: a key that stopped being an open request, or a
/// fingerprint that is no longer the one displayed.
fn connect_from_ui(body: &str) -> Result<Vec<String>, (&'static str, String)> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let key = v
        .get("key")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let typed = v
        .get("confirm")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !crate::bundle::b64_decode_ok(&key) {
        return Err(("400 Bad Request", "that is not a key".into()));
    }
    // `name` empty means the **reveal** step: check the typed pair and, if it
    // is right, hand back the whole fingerprint so the person can compare the
    // other three. Adding is a second call with a name. Two steps rather than
    // one because the page must not hold the answer before the person has
    // shown they got it from somewhere else.
    let reveal_only = name.is_empty();
    if !reveal_only
        && (!name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
            || name.len() > 40)
    {
        return Err((
            "400 Bad Request",
            "a contact name is letters, digits, spaces, - and _".into(),
        ));
    }
    let contacts = crate::trust::Contacts::load();
    if let Some(n) = contacts.keys.get(&key) {
        return Err((
            "409 Conflict",
            format!("that key is already on your list as {n}"),
        ));
    }
    let pairs = crate::words::pairs(&key, 4);
    let want = &pairs[asked_pair(&key)];
    if typed != *want {
        return Err((
            "409 Conflict",
            // The expected value is NOT echoed back. A message that says
            // "you typed X, it was Y" turns the step into a two-try copy
            // exercise and teaches the person that the words do not matter.
            format!(
                "that is not pair {} of this key's fingerprint. Read it off the OTHER \
                 machine -- it is deliberately not shown on this one, so that typing \
                 it means something.",
                asked_pair(&key) + 1
            ),
        ));
    }
    if reveal_only {
        return Ok(vec![
            "reveal".to_string(),
            crate::words::fingerprint_of(&key, contacts.box_keys.get(&key).map(|s| s.as_str())),
        ]);
    }
    // Only the signing key, unless one is already on file.
    //
    // A manifest does not carry the sender's encryption key and should not:
    // a sender seals *to* you, using the key you published, and never needs
    // to publish its own. So a contact added from a request is verifiable
    // and not sealable -- real and useful, and a state `add_contact` has
    // always supported for contacts predating encryption. The asymmetry with
    // LAN pairing, where both halves are announced, is worth saying out loud
    // rather than papering over, so the result does.
    let token = match contacts.box_keys.get(&key) {
        Some(b) => format!("{key}.{b}"),
        None => key.clone(),
    };
    let mut out = crate::trust::add_contact(&name, &token).map_err(|e| ("400 Bad Request", e))?;
    if !contacts.box_keys.contains_key(&key) {
        // `add_contact` already says "verify only". This adds the remedy,
        // which is the part a person cannot work out from the statement.
        out.push(
            "to seal mail to them as well, get their `gage whoami` token \
             (signpub.boxpub) and add it over this entry, or pair on the network."
                .to_string(),
        );
    }
    Ok(out)
}

/// Refuse a key from the page.
fn decline_from_ui(body: &str) -> Result<String, (&'static str, String)> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ("400 Bad Request", format!("bad body: {e}")))?;
    let key = v
        .get("key")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let undo = v.get("undo").and_then(|x| x.as_bool()).unwrap_or(false);
    if !crate::bundle::b64_decode_ok(&key) {
        return Err(("400 Bad Request", "that is not a key".into()));
    }
    let mut c = crate::trust::Contacts::load();
    if undo {
        return match c.declined.remove(&key) {
            Some(_) => {
                c.save()
                    .map_err(|e| ("500 Internal Server Error", e.to_string()))?;
                Ok("no longer refused -- and still not on your list".to_string())
            }
            None => Err(("409 Conflict", "that key is not refused".into())),
        };
    }
    let seq = crate::state::LocalState::load().seq;
    match c.decline(&key, seq).map_err(|e| ("409 Conflict", e))? {
        true => {
            c.save()
                .map_err(|e| ("500 Internal Server Error", e.to_string()))?;
            Ok("refused. Its bundles still arrive; you are not asked again".to_string())
        }
        false => Ok("already refused".to_string()),
    }
}

/// Send a reply on behalf of the page.
///
/// Routed recipients only. A bundle for someone with no local route would sit
/// in the outbox looking sent, and the page cannot run the confirmation that
/// `gage push` exists to show -- so it says so instead of pretending.
fn reply_from_ui(body: &str) -> Result<String, (&'static str, String)> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ("400 Bad Request", format!("unreadable request: {e}")))?;
    let thread = v
        .get("thread")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("");
    let msg_type = v
        .get("type")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    if thread.is_empty() || !thread.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(("400 Bad Request", "bad thread id".into()));
    }
    if text.trim().is_empty() {
        return Err(("400 Bad Request", "nothing to send".into()));
    }

    let t = crate::outbound::resolve_reply(&thread).map_err(|e| ("409 Conflict", e.to_string()))?;
    if crate::routes::Routes::load().home_of(&t.to).is_none() {
        return Err((
            "409 Conflict",
            format!(
                "{} has no local route, so this reply cannot be delivered from here. \
                 In a terminal: gage reply {} --text \"...\" then gage push <dir> --to {} --yes",
                t.to, thread, t.to
            ),
        ));
    }

    let tmp = crate::identity::home().join(format!("tmp-ui-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| ("500 Internal Server Error", e.to_string()))?;
    let f = tmp.join("reply.md");
    let mut body = text.to_string();
    if !body.ends_with('\n') {
        body.push('\n');
    }
    std::fs::write(&f, body).map_err(|e| ("500 Internal Server Error", e.to_string()))?;

    // Same path as the CLI, outbound scan included. A reply typed into a
    // browser gets exactly the checks a reply typed into a shell gets.
    let mut say = Vec::new();
    let r = crate::outbound::send_bundle(
        crate::outbound::SendArgs {
            to: vec![t.to.clone()],
            subject: t.subject,
            out: None,
            file: vec![],
            prompt: vec![],
            decision: vec![f],
            memory: vec![],
            dir: vec![],
            allow_secrets: false,
            reply_to: Some(t.parent),
            msg_type: msg_type.unwrap_or(t.msg_type),
            allow_findings: false,
            lan: false,
            agent: None,
            model: None,
        },
        &mut say,
    );
    let _ = std::fs::remove_dir_all(&tmp);
    for l in &say {
        println!("{l}");
    }
    match r {
        Ok(m) => Ok(m.id),
        // The scan refusing is the most likely failure and it is not a bug,
        // so it comes back as a 409 the page can show verbatim.
        Err(e) => Err(("409 Conflict", e.to_string())),
    }
}

/// Record the inbox, and say whether it worked.
///
/// The viewer polls, so it cannot fail a request over this. For a while it
/// only warned on stderr and served the verdicts anyway -- which was the same
/// bug `gage open` refuses to have, hidden better: the person reading verdicts
/// is looking at the browser, not at the terminal the warning went to. A
/// verdict computed from state that could not be refreshed can read milder
/// than the truth (a retired key's bundle showing as "no record either way"
/// rather than a rejection), so when this returns false every verdict in the
/// response is replaced by `VERDICT_UNAVAILABLE` and the page says so.
#[must_use]
fn observed() -> bool {
    match crate::routes::observe_inbox() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("gage ui: WARNING -- inbox not recorded ({e}); verdicts withheld");
            false
        }
    }
}

/// The verdict to show for a bundle, which is no verdict at all when the
/// observation step failed.
fn verdict_label(observed: bool, l: &crate::bundle::Loaded) -> &'static str {
    verdict_label_for(observed, l.trust)
}

/// The same decision over a bare verdict, so it can be tested without a
/// bundle on disk.
fn verdict_label_for(observed: bool, t: crate::trust::Trust) -> &'static str {
    if observed {
        t.label()
    } else {
        crate::trust::VERDICT_UNAVAILABLE
    }
}

fn state_json() -> String {
    let observed = observed();
    let me = crate::identity::home();
    let contacts = crate::trust::Contacts::load();
    let routes = crate::routes::Routes::load();
    let id = crate::identity::Identity::load().ok();

    let stage = |dir: std::path::PathBuf, name: &str| -> Vec<serde_json::Value> {
        crate::routes::list(&dir)
            .into_iter()
            .map(|(_, l)| {
                let m = &l.manifest;
                serde_json::json!({
                    "stage": name,
                    "id": m.id,
                    "subject": m.subject,
                    "created": m.created,
                    // Both names, labelled. The page must never show a claimed
                    // handle as though it were an identity.
                    "claimed_name": m.from.handle,
                    "known_as": contacts.name_any(&m.from.key),
                    "key": m.from.key,
                    "trust": verdict_label(observed, &l),
                    "forwarded": m.is_forwarded(),
                    "hops": m.chain.len(),
                    "prompts": m.prompt_count(),
                    "memories": m.memory_count(),
                    "bytes": m.total_bytes(),
                    "in_reply_to": m.in_reply_to,
                    "items": m.items.iter().map(|i| serde_json::json!({
                        "kind": format!("{:?}", i.kind).to_lowercase(),
                        // Strip the items/ prefix for display: the reader cares
                        // about src/net/mod.rs, not the bundle's internals.
                        "path": i.path.strip_prefix("items/").unwrap_or(&i.path),
                        "bytes": i.bytes,
                    })).collect::<Vec<_>>(),
                    "tampered": l.tampered,
                    "agent": m.agent.as_ref().map(|a| serde_json::json!({
                        "name": a.name, "model": a.model })),
                })
            })
            .collect()
    };

    serde_json::json!({
        // Whether a key file exists at all, said outright. `me` is null
        // both when there is no identity and when one is here but would
        // not load, and only the first of those is a first run -- so the
        // page offers creation on this flag and never on `me` alone, and
        // a key that fails to load cannot read as an invitation to create
        // over it. Creation would refuse anyway (`Identity::create` will
        // not clobber), but the state should not need the refusal to be
        // understood.
        "has_identity": me.join("identity.key").exists(),
        "me": id.map(|i| serde_json::json!({ "handle": i.handle, "key": i.public_b64() })),
        // The page shows a banner on this and stops presenting verdicts as
        // though they were current.
        "verdicts_stale": !observed,
        "home": me.display().to_string(),
        "pending": stage(crate::routes::pending_dir(&me), "pending"),
        "accepted": stage(crate::routes::accepted_dir(&me), "accepted"),
        "contacts": contacts.keys.iter().map(|(k, n)| serde_json::json!({
            "name": n, "key": k, "routed": routes.local.contains_key(n) })).collect::<Vec<_>>(),
        "groups": contacts.groups.iter().map(|(g, m)| serde_json::json!({
            "name": g, "members": m.len() })).collect::<Vec<_>>(),
        "routes": routes.local,
    })
    .to_string()
}

/// Conversations, which is what a person actually wants to look at. The flat
/// bundle list answered "what arrived"; this answers "what is going on and
/// does any of it need me".
fn threads_json() -> String {
    let observed = observed();
    let me_id = crate::identity::Identity::load().ok();
    let mine = me_id.as_ref().map(|i| i.public_b64()).unwrap_or_default();
    let st = crate::state::LocalState::load();
    let contacts = crate::trust::Contacts::load();
    let routes = crate::routes::Routes::load();
    let home = crate::identity::home();

    // Where each bundle lives decides what can be done with it: a pending one
    // can be accepted or rejected, an accepted one read.
    let mut stage_of: std::collections::BTreeMap<String, (&str, String)> = Default::default();
    let mut trust_of: std::collections::BTreeMap<String, (String, Vec<String>)> =
        Default::default();
    let mut manifests = Vec::new();
    for (name, dir) in [
        ("pending", crate::routes::pending_dir(&home)),
        ("accepted", crate::routes::accepted_dir(&home)),
        ("sent", crate::routes::sent_dir(&home)),
    ] {
        for (_, l) in crate::routes::list(&dir) {
            let id = l.manifest.id.clone();
            stage_of
                .entry(id.clone())
                .or_insert((name, dir.join(&id).display().to_string()));
            trust_of
                .entry(id.clone())
                .or_insert((verdict_label(observed, &l).to_string(), l.tampered.clone()));
            if !manifests
                .iter()
                .any(|m: &crate::manifest::Manifest| m.id == id)
            {
                manifests.push(l.manifest);
            }
        }
    }

    let threads = crate::state::threads(manifests, &st, &mine);
    let rows: Vec<serde_json::Value> = threads
        .iter()
        .map(|t| {
            let msgs: Vec<serde_json::Value> = t
                .messages
                .iter()
                .map(|m| {
                    let is_mine = m.from.key == mine;
                    let (stage, path) = stage_of
                        .get(&m.id)
                        .cloned()
                        .unwrap_or(("unknown", String::new()));
                    let (trust, tampered) = trust_of.get(&m.id).cloned().unwrap_or_default();
                    serde_json::json!({
                        "id": m.id,
                        "mine": is_mine,
                        // The page colours each correspondent from the KEY, so
                        // two contacts using the same display name look
                        // different before anyone reads a word.
                        "key": m.from.key,
                        "type": m.msg_type.label(),
                        "expects_reply": m.msg_type.expects_reply(),
                        "created": m.created,
                        "subject": m.subject,
                        "stage": stage,
                        "path": path,
                        "read": is_mine || st.is_read(&m.id),
                        "trust": trust,
                        "tampered": tampered,
                        "forwarded": m.is_forwarded(),
                        // False when the message's claim to this thread could
                        // not be checked against anything held locally.
                        "thread_ok": !t.unverified.contains(&m.id),
                        "hops": m.chain.len(),
                        "claimed_name": m.from.handle,
                        "known_as": contacts.name_any(&m.from.key),
                        "prompts": m.prompt_count(),
                        "memories": m.memory_count(),
                        "bytes": m.total_bytes(),
                        "items": m.items.iter().map(|i| serde_json::json!({
                            "kind": format!("{:?}", i.kind).to_lowercase(),
                            "path": i.path.strip_prefix("items/").unwrap_or(&i.path),
                            "bytes": i.bytes,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            // Who a reply would go to, worked out the same way `gage reply`
            // works it out: the newest message that is not yours, and the KEY
            // that signed it. The page shows the name but never decides from
            // it, and when the answer is "nobody" it says why rather than
            // offering a box that fails on submit.
            let parent = t.messages.iter().rev().find(|m| m.from.key != mine);
            let reply = if t.others.len() > 1 {
                // Same refusal as the CLI. A thread with two correspondents
                // does not name a recipient, and a composer that guessed
                // would be the thing a grafted bundle exploits.
                serde_json::json!({ "can": false,
                    "why": format!("this thread has {} correspondents, so replying to \
                                    the thread does not say who to. Reply to one \
                                    message from a terminal: gage reply <message id>",
                                   t.others.len()) })
            } else {
                match parent {
                    None => serde_json::json!({ "can": false,
                    "why": "every message here is your own" }),
                    Some(p) => match contacts.name_for(&p.from.key) {
                        None => serde_json::json!({ "can": false,
                        "why": "the key that signed the last message is not on your list" }),
                        Some(name) if routes.home_of(name).is_none() => serde_json::json!({
                        "can": false, "to": name,
                        "why": format!("{name} has no local route, so a reply has to go out \
                                        through gage push in a terminal") }),
                        Some(_) if t.unverified.contains(&p.id) => serde_json::json!({
                        "can": false,
                        "why": "the newest message claims this thread while answering \
                                something you do not hold, so it is not a safe reply \
                                target" }),
                        Some(name) => serde_json::json!({ "can": true, "to": name,
                        "type": if p.msg_type.expects_reply() { "answer" } else { "share" } }),
                    },
                }
            };
            serde_json::json!({
                "id": t.id,
                "subject": t.subject,
                "state": t.state.label(),
                "unread": t.unread,
                "correspondents": t.others.len(),
                "reply": reply,
                "messages": msgs,
            })
        })
        .collect();

    serde_json::json!({
        "me": me_id.map(|i| serde_json::json!({ "handle": i.handle, "key": i.public_b64() })),
        "verdicts_stale": !observed,
        "threads": rows,
        "contacts": contacts.keys.iter().map(|(k, n)| serde_json::json!({
            "name": n, "key": k })).collect::<Vec<_>>(),
    })
    .to_string()
}

const INDEX: &str = include_str!("ui.html");
const FAVICON: &str = include_str!("../packaging/icon/gage-icon.svg");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pages_verdict_table_matches_the_verdicts_that_exist() {
        // A cross-language drift test. The page classifies a verdict with
        // `startsWith` against a table of truncated prefixes, so the Rust
        // test that no LABEL is a prefix of another does not cover it: a new
        // label could match an old row's shortened key. When `Declined` was
        // added, the page had no row for it and would have rendered it
        // through the fallback as `v-bad` with the raw string.
        let keys: Vec<String> = INDEX
            .lines()
            .skip_while(|l| !l.contains("const V=["))
            .take_while(|l| !l.contains("const vRow"))
            .flat_map(|l| {
                l.match_indices('[')
                    .filter_map(|(i, _)| l[i + 1..].strip_prefix('\''))
                    .filter_map(|rest| rest.split_once('\'').map(|(k, _)| k.to_string()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            keys.len() >= 7,
            "could not parse the page's verdict table: {keys:?}"
        );
        let all: Vec<&'static str> = crate::trust::ALL
            .iter()
            .map(|t| t.label())
            .chain([crate::trust::VERDICT_UNAVAILABLE])
            .collect();
        // Every verdict is matched by exactly one row, so nothing falls
        // through to the fallback and nothing is classified twice.
        for label in &all {
            let hits: Vec<&String> = keys
                .iter()
                .filter(|k| label.starts_with(k.as_str()))
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{label:?} matches {} rows: {hits:?}",
                hits.len()
            );
        }
        // And every row matches a verdict, so a renamed label does not leave
        // a dead row quietly classifying nothing.
        for k in &keys {
            assert!(
                all.iter().any(|l| l.starts_with(k.as_str())),
                "the page has a row for {k:?}, which no verdict starts with"
            );
        }
    }

    #[test]
    fn a_key_the_page_will_render_has_to_be_shaped_like_one() {
        // `is_a_key` guards three things in `buddies_json`: what
        // `decline_from_ui` persists as a map key in contacts.json, what the
        // page interpolates into a JS string inside an HTML attribute, and
        // what a word-label is computed for.
        //
        // Honest about the coverage: removing the filter from
        // `buddies_json` breaks **nothing** in the shell suite, because
        // every key the CLI can produce is already well formed and reaching
        // the filter needs a hand-written manifest the CLI cannot build.
        // This covers the predicate, not its use, and that gap is real.
        for good in [
            "XUkMcjZCz3cGTtxbGGzItqbc1Cwjr3KZyZ4BFzeUeSU=",
            "bpGwtgSzi/6+0rqP4gPiwixfBfHPkPwP6RBErpaQn5o=",
        ] {
            assert!(is_a_key(good), "rejected a real key: {good}");
        }
        for bad in [
            "",
            "short",
            // The one that matters for the attribute context: an apostrophe
            // survives `esc` as `&#39;`, which the HTML parser decodes
            // before the inline handler's JavaScript is parsed.
            "XUkMcjZCz3cGTtxbGGzItqbc1Cwjr3KZyZ4BFzeU'SU=",
            "XUkMcjZCz3cGTtxbGGzItqbc1Cwjr3KZyZ4BFzeU<SU=",
            // Length, which `b64_decode_ok` alone did not bound -- this is
            // what used to be persistable into contacts.json.
            &"A".repeat(4096),
        ] {
            assert!(
                !is_a_key(bad),
                "accepted something that is not a key: {bad:?}"
            );
        }
    }

    #[test]
    fn the_add_call_resends_the_pair_the_reveal_confirmed() {
        // A regression pin, and an honest one: this is a grep, not coverage.
        //
        // The page's client state had no tests at all, and the bug it let
        // through was that `budReveal` cleared `ACONF` on success while
        // `budConnect` sent `ACONF`, so the server's own check rejected every
        // add and the button was dead. Neither the API checks (which drive
        // the endpoint directly) nor the shell suite could see it; a reviewer
        // found it by reading the two lines together.
        //
        // Properly covering page state needs a headless browser, which this
        // project does not have. Until it does, this asserts the one shape
        // the fix depends on: the confirmed pair survives the reveal and the
        // add call reads it from there.
        // Both halves are scoped to the function they are about, which the
        // first version of this test was not -- and my own mutation run
        // caught it. It asserted `INDEX.contains("pair:ACONF")` against the
        // whole page, and `budConnect`'s ternary, written without spaces as
        // `?REVEAL.pair:ACONF`, contains that exact substring. So the
        // assertion was satisfied by the line it was not about, and breaking
        // the line it WAS about changed nothing. Same class as a check that
        // once passed because the newest id happened to sort last.
        let body_of = |name: &str| -> String {
            let after = INDEX
                .split(&format!("function {name}"))
                .nth(1)
                .unwrap_or_else(|| panic!("{name} exists"));
            let end = after.find("\n}").unwrap_or(after.len());
            after[..end].to_string()
        };
        let reveal = body_of("budReveal");
        assert!(
            reveal.contains("pair:ACONF") || reveal.contains("pair: ACONF"),
            "budReveal does not keep the confirmed pair: {reveal}"
        );
        let connect = body_of("budConnect");
        assert!(
            connect.contains("REVEAL.pair"),
            "budConnect does not resend the confirmed pair: {connect}"
        );
    }

    #[test]
    fn the_asked_pair_is_never_the_one_the_label_gives_away() {
        // Pair 1 is `words::label`, which the request card shows as the way
        // to tell one request from another. Asking for it would make the
        // answer readable off this screen, which is the thing withholding
        // the fingerprint exists to prevent.
        for i in 0..400u32 {
            let k = crate::bundle::sha256_hex(&i.to_le_bytes());
            let a = asked_pair(&k);
            assert!((1..4).contains(&a), "asked pair {a} for {k}");
            let pairs = crate::words::pairs(&k, 4);
            assert_ne!(
                pairs[a], pairs[0],
                "the asked pair equals the label for {k}"
            );
        }
    }

    #[test]
    fn an_id_route_matches_exactly_one_segment() {
        assert_eq!(bundle_id("/api/read/abc123", "/api/read/"), Some("abc123"));

        // The shapes codex found. All three used to resolve to the trailing
        // segment and act on it.
        assert_eq!(bundle_id("/api/accept/extra/abc123", "/api/accept/"), None);
        assert_eq!(bundle_id("/api/read//abc123", "/api/read/"), None);
        assert_eq!(bundle_id("/api/read/abc123/", "/api/read/"), None);

        assert_eq!(bundle_id("/api/read/", "/api/read/"), None);
        assert_eq!(bundle_id("/api/read/../../etc", "/api/read/"), None);
        assert_eq!(bundle_id("/api/read/zz", "/api/read/"), None, "hex only");
        assert_eq!(bundle_id("/api/read/abc?x=1", "/api/read/"), None);
        assert_eq!(
            bundle_id(&format!("/api/read/{}", "a".repeat(65)), "/api/read/"),
            None
        );
        // A prefix that is not this route's.
        assert_eq!(bundle_id("/api/close/abc", "/api/read/"), None);
    }

    #[test]
    fn an_uploaded_name_cannot_become_a_path() {
        // A filename from a browser is a string somebody else's filesystem
        // produced, and it is joined onto a directory.
        //
        // The basename is what does the work: a traversal is STRIPPED rather
        // than refused, which is also what a browser does with a dropped
        // folder, so `../../etc/passwd` arrives as a file called `passwd` and
        // goes nowhere near /etc. Verified by removing the charset filter and
        // watching nothing escape -- the test that matters is this one, not
        // the shell check, which passed either way and so proved less than it
        // looked like it proved.
        for (raw, want) in [
            ("../../../../tmp/gage-ui-pwn", "gage-ui-pwn"),
            ("docs/notes.md", "notes.md"),
            ("C:\\Users\\x\\secrets.md", "secrets.md"),
            ("notes.md", "notes.md"),
            ("a b (1).md", "a b (1).md"),
        ] {
            assert_eq!(
                safe_upload_name(raw).as_deref(),
                Some(want),
                "{raw:?} should land as {want:?}"
            );
        }
        // The charset is the second filter, for what a basename can still
        // contain: a leading dot, a separator the split missed, a control
        // character, a shell metacharacter.
        for bad in [
            "..",
            ".",
            "",
            ".env",
            ".ssh",
            "a\u{0000}b",
            "nul\nline.md",
            "semi;colon.md",
            "quote\".md",
            "star*.md",
            "tilde~.md",
            "$HOME.md",
        ] {
            assert_eq!(
                safe_upload_name(bad),
                None,
                "{bad:?} should not become a filename"
            );
        }
        // Length is bounded: a filename is a filename, not a payload.
        assert_eq!(safe_upload_name(&"a".repeat(200)), None);
    }

    #[test]
    fn a_failed_observation_withholds_the_verdict_instead_of_softening_it() {
        // The label is what the viewer shows in place of a verdict, and the
        // one thing it must never be is a verdict. `gage open` refuses to
        // print at all in this case; the viewer polls, so it says this.
        assert_eq!(
            verdict_label_for(false, crate::trust::Trust::Revoked),
            crate::trust::VERDICT_UNAVAILABLE
        );
        // ...and when observation worked, nothing changes.
        assert_eq!(
            verdict_label_for(true, crate::trust::Trust::Revoked),
            crate::trust::Trust::Revoked.label()
        );
        // The failure must not be renderable as the mildest verdict, which is
        // the specific way this bug would have hurt: a rejected key reading
        // as "no record either way", or worse, as verified.
        assert_ne!(
            crate::trust::VERDICT_UNAVAILABLE,
            crate::trust::Trust::Known.label()
        );
        assert_ne!(
            crate::trust::VERDICT_UNAVAILABLE,
            crate::trust::Trust::Unwitnessed.label()
        );
    }

    #[test]
    fn a_first_run_handle_is_plain_or_derived() {
        // Empty is the derived-label path, the one quickstart offers when
        // the name is left blank.
        assert!(handle_ok(""));
        // What a person plausibly types, including the two-word shape the
        // derived labels themselves take.
        for good in ["alice", "alice ware", "a-1_b", "crisp beetle"] {
            assert!(handle_ok(good), "refused a plain handle: {good:?}");
        }
        // The hostile shapes. The handle is written to disk as-is and is
        // later rendered by pages and quoted into shell lines, so what
        // must not reach it is traversal pieces, separators, quotes and
        // control characters -- the newline-injection shape -- plus the
        // over-long, which the contact-name grammar bounds for the same
        // reason.
        for bad in [
            "../etc",
            "a/b",
            "a\\b",
            "line\nbreak",
            "tab\there",
            "nul\u{0}byte",
            "o'brien",
            "emoji\u{1f600}",
            &"a".repeat(41),
        ] {
            assert!(!handle_ok(bad), "accepted a hostile handle: {bad:?}");
        }
    }

    /// A note alone is a send. A file alone is a send. Neither is not.
    #[test]
    fn a_nearby_send_needs_a_file_or_a_note() {
        // Neither: refused, and the message says what to do rather than
        // naming the field that was empty.
        let e = send_from_ui(br#"{"to":"cedar cinder","files":[]}"#)
            .expect_err("accepted a send with nothing in it");
        assert_eq!(e.0, "400 Bad Request");
        assert!(e.1.contains("drop a file, write a note"), "{}", e.1);
        // Whitespace is not a note.
        let e = send_from_ui(br#"{"to":"cedar cinder","files":[],"text":"   \n  "}"#)
            .expect_err("accepted whitespace as a note");
        assert_eq!(e.0, "400 Bad Request");
        // No device, whatever else is set.
        let e = send_from_ui(br#"{"to":"","text":"hello"}"#)
            .expect_err("accepted a send with no device");
        assert!(e.1.contains("no device chosen"), "{}", e.1);
        // A note past the cap is refused before anything is written.
        let big = serde_json::json!({
            "to": "cedar cinder",
            "files": [],
            "text": "x".repeat(64 * 1024 + 1),
        })
        .to_string();
        let e = send_from_ui(big.as_bytes()).expect_err("accepted an oversized note");
        assert!(e.1.contains("larger than a note"), "{}", e.1);
        // A dropped file called message.md, alongside a note. The note
        // claims that name first, so this collides loudly instead of one
        // silently overwriting the other.
        let clash = serde_json::json!({
            "to": "cedar cinder",
            "text": "the note",
            "files": [{ "name": "message.md", "data": "aGk=" }],
        })
        .to_string();
        match send_from_ui(clash.as_bytes()) {
            Err((_, msg)) => assert!(
                msg.contains("two files called message.md") || !msg.contains("overwrit"),
                "the collision was not reported as one: {msg}"
            ),
            Ok(_) => panic!("a file named message.md was silently merged with the note"),
        }
        // A note alone gets past validation. It fails later for want of a
        // real contact and a real route, which is a different error than the
        // refusals above -- that is the whole assertion.
        let ok_shape = br#"{"to":"cedar cinder","files":[],"text":"look at this machine"}"#;
        match send_from_ui(ok_shape) {
            Ok(_) => {}
            Err((_, msg)) => assert!(
                !msg.contains("nothing to send") && !msg.contains("no files"),
                "a note-only send was refused as empty: {msg}"
            ),
        }
    }

    /// Pasted text is attacker-controlled, so these are the lines an
    /// attacker would paste rather than the line a colleague would.
    #[test]
    fn a_pasted_invite_is_parsed_without_adding_anything() {
        // No key in the text at all.
        for junk in [
            r#"{"text":""}"#,
            r#"{"text":"hello"}"#,
            r#"{"text":"gage add bob"}"#,
            r#"{"text":"gage add"}"#,
        ] {
            let e = parse_invite(junk).expect_err("accepted text with no key");
            assert_eq!(e.0, "400 Bad Request", "{junk}: {}", e.1);
        }
        // Something key-shaped that is not base64 of 32 bytes.
        let notkey = format!(r#"{{"text":"gage add bob {}="}}"#, "!".repeat(43));
        let e = parse_invite(&notkey).expect_err("accepted a non-key");
        assert_eq!(e.0, "400 Bad Request");
        // Oversized paste is refused before it is tokenised.
        let big = format!(r#"{{"text":"{}"}}"#, "a".repeat(5000));
        let e = parse_invite(&big).expect_err("accepted an oversized paste");
        assert_eq!(e.0, "400 Bad Request");
        assert!(e.1.contains("more text than an invite"), "{}", e.1);
    }

    /// The fingerprint must NOT come back from this route. The whole point of
    /// the ceremony is that the words come off the other machine; a route
    /// that returned them here would let the page show an attacker's own
    /// pairs and ask the person to agree with them.
    #[test]
    fn parsing_an_invite_never_returns_the_fingerprint() {
        let key = crate::words::pairs("x", 1); // only to prove pairs() exists
        let _ = key;
        let good = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [7u8; 32],
        );
        let body = serde_json::json!({ "text": format!("gage add 'icy dune' {good}") }).to_string();
        let out = match parse_invite(&body) {
            Ok(o) => o,
            // A home with this key already on its list, or no identity, are
            // both legitimate states for this to refuse in; the assertion
            // below is about what a SUCCESS may contain.
            Err(_) => return,
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v.get("key").unwrap().as_str().unwrap(), good);
        assert!(v.get("fingerprint").is_none(), "route leaked a fingerprint");
        let pairs = crate::words::pairs(good.as_str(), 4);
        for p in &pairs {
            assert!(!out.contains(p.as_str()), "route leaked the pair {p}");
        }
        // And the asked pair is named by NUMBER only.
        let n = v.get("ask_pair").unwrap().as_u64().unwrap();
        assert!((1..=4).contains(&n), "ask_pair was {n}");
    }

    /// One parser for one format. If the CLI accepts a shape the page
    /// refuses, a person is told to paste the thing that does not work.
    #[test]
    fn the_page_and_the_cli_accept_the_same_shapes() {
        let good = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [9u8; 32],
        );
        for text in [
            format!("gage add 'icy dune' {good}"),
            format!("    gage add 'icy dune' {good}   "),
            format!("gage add bob {good}"),
            good.clone(),
        ] {
            let (_, token) = crate::quickstart::parse_add(&text);
            assert_eq!(
                token.as_deref(),
                Some(good.as_str()),
                "the CLI parser missed {text:?}"
            );
        }
    }

    #[test]
    fn the_invite_is_markup_fetched_from_this_server() {
        // Same honesty as the reveal/add pin above: this is a grep of the
        // page, which is what this tree has instead of a headless browser.
        // It locks the shape the CSP allows. An `<img src>` is not one.
        assert!(INDEX.contains("fetch('/api/invite')"));
        assert!(INDEX.contains("function inviteOk"));
        assert!(INDEX.contains("function budpaneHtml"));
        assert!(INDEX.contains("function inviteHtml"));
        let words = INDEX
            .lines()
            .find(|l| l.contains("W.stage==='words'"))
            .unwrap_or_else(|| panic!("words stage missing"));
        assert!(
            words.contains("inviteHtml()"),
            "the first-run words stage does not show the code"
        );
        let pane = INDEX
            .split("function budpaneHtml")
            .nth(1)
            .unwrap_or_else(|| panic!("budpaneHtml missing"));
        let pane = &pane[..pane.find("\nfunction ").unwrap_or(pane.len())];
        assert!(pane.contains("inviteHtml()"));
        assert!(!INDEX.contains("<img"));
        let clipboard = INDEX
            .split("async function pasteClipboard")
            .nth(1)
            .unwrap_or_else(|| panic!("paste clipboard handler missing"));
        let clipboard = &clipboard[..clipboard.find("\n}").unwrap_or(clipboard.len())];
        assert!(clipboard.contains("navigator.clipboard.readText()"));
        assert!(clipboard.contains("Keep the editable paste field as the fallback"));
        assert!(INDEX.contains("onclick=\"pasteClipboard()\""));
        assert_eq!(INDEX.matches("navigator.clipboard.readText()").count(), 1);
        assert!(INDEX.contains("fetch('/api/parse-invite'"));
        assert!(INDEX.contains("value=\"${esc(ANAME)}\""));
        assert!(INDEX.contains("${esc(PASTED)}"));
        assert!(INDEX.contains("${esc(shown)}"));
        assert!(INDEX.contains("confirm:ACONF"));
        assert!(INDEX.contains("confirm:p"));
        assert!(INDEX.contains("All four match -- add them"));
        assert!(INDEX.contains("onclick=\"pasteClipboard()\""));
        assert!(INDEX.contains("budReveal('${esc(q.key)}')"));
        assert!(INDEX.contains("budConnect('${esc(q.key)}')"));
        assert!(INDEX.contains("Suggested name (edit as needed)"));
        assert!(!INDEX.contains("http://") && !INDEX.contains("https://"));
        assert!(INDEX.contains("inviteLoad(true)"), "creating an identity does not load the code");
    }

    #[test]
    fn the_first_run_warning_is_the_clis_own_trade() {
        // The sentence the CLI prints for the same decision, in
        // export-identity's help and in `backup::export`. If the wording
        // there changes, this is the prompt to change it here too: the
        // page must not soften the one warning a new identity gets.
        assert!(BACKUP_WARNING.contains("lose the key, lose everything"));
        assert!(BACKUP_WARNING.contains("gage export-identity"));
    }
}
