//! `ctx ui` -- a local viewer, bound to 127.0.0.1 only.
//!
//! This is the buddy-list window: who you trust, what is waiting, and what
//! each bundle claims, with the trust verdict shown as prominently as the
//! subject line. It exists because the verdict is the product, and a verdict
//! nobody looks at is not a control.
//!
//! It never renders payload contents. A page that pastes a stranger's prompt
//! into a browser is a different risk surface, and `ctx open` is where
//! content is meant to be read, inside its frame. What the browser may do is
//! accept, reject, mark read, settle a thread, and write a reply -- the human
//! gates this design is built around, plus the one thing a viewer could not
//! do and still be an app.
//!
//! A reply from here is delivered to a LOCAL ROUTE only. Sending off the
//! machine stays in the terminal behind `ctx push --yes`, because that
//! confirmation is the last point at which a person sees what is leaving, and
//! a button in a web page is not that.
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
        let Some((k, v)) = h.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "host" => host = Some(v.to_ascii_lowercase()),
            "origin" => origin = Some(v),
            "sec-fetch-site" => fetch_site = Some(v),
            "x-ctx" => guard = true,
            // Capped well below anything legitimate. The body is one short
            // reply, and an unbounded read here is a one-line denial of
            // service against a server with no other limits.
            "content-length" => len = v.parse().unwrap_or(0).min(MAX_BODY_BYTES),
            _ => {}
        }
    }
    // The body is read from the limited reader too, and `read_exact` now has
    // a timeout behind it: a client that declares a length and then goes quiet
    // fails rather than parking the server.
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
    if let Some(site) = &r.fetch_site {
        if site != "same-origin" && site != "none" {
            return false;
        }
    }
    if let Some(o) = &r.origin {
        let ok = [
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
            format!("http://[::1]:{port}"),
        ];
        if !ok.iter().any(|x| x == o) {
            return false;
        }
    }
    true
}

pub fn serve(port: u16) -> std::io::Result<()> {
    // Loopback only, never 0.0.0.0. An inbox viewer on a laptop has no
    // business being reachable from the network it happens to be on.
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("ctx ui on http://127.0.0.1:{port}  (ctrl-c to stop)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s, port) {
                    eprintln!("ctx ui: {e}");
                }
            }
            Err(e) => eprintln!("ctx ui: accept failed: {e}"),
        }
    }
    Ok(())
}

fn respond(mut s: TcpStream, status: &str, ctype: &str, body: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\r\n\
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
        ("GET", "/api/state") => {
            respond(stream, "200 OK", "application/json", &state_json())
        }
        ("GET", "/api/threads") => {
            respond(stream, "200 OK", "application/json", &threads_json())
        }
        ("POST", t) if t.starts_with("/api/read/") => {
            let Some(id) = bundle_id(t, "/api/read/") else {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            };
            let mut st = crate::state::LocalState::load();
            match st.mark_read(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(stream, "500 Internal Server Error", "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string()),
            }
        }
        ("POST", t) if t.starts_with("/api/close/") => {
            let Some(id) = bundle_id(t, "/api/close/") else {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            };
            let mut st = crate::state::LocalState::load();
            match st.close(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(stream, "500 Internal Server Error", "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string()),
            }
        }
        ("POST", t) if t.starts_with("/api/accept/") || t.starts_with("/api/reject/") => {
            let accept = t.starts_with("/api/accept/");
            let Some(id) = bundle_id(t, if accept { "/api/accept/" } else { "/api/reject/" })
            else {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            };
            let me = crate::identity::home();
            let from = crate::routes::pending_dir(&me).join(id);
            if !from.is_dir() {
                return respond(stream, "404 Not Found", "application/json", "{\"error\":\"no such pending bundle\"}");
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
        ("POST", "/api/reply") => {
            let out = reply_from_ui(&req.body);
            match out {
                Ok(id) => respond(stream, "200 OK", "application/json",
                    &serde_json::json!({ "ok": true, "id": id }).to_string()),
                Err((code, msg)) => respond(stream, code, "application/json",
                    &serde_json::json!({ "error": msg }).to_string()),
            }
        }
        _ => respond(stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

/// Send a reply on behalf of the page.
///
/// Routed recipients only. A bundle for someone with no local route would sit
/// in the outbox looking sent, and the page cannot run the confirmation that
/// `ctx push` exists to show -- so it says so instead of pretending.
fn reply_from_ui(body: &str) -> Result<String, (&'static str, String)> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ("400 Bad Request", format!("unreadable request: {e}")))?;
    let thread = v.get("thread").and_then(|t| t.as_str()).unwrap_or("").trim().to_string();
    let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("");
    let msg_type = v.get("type").and_then(|t| t.as_str()).map(|s| s.to_string());
    if thread.is_empty() || !thread.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(("400 Bad Request", "bad thread id".into()));
    }
    if text.trim().is_empty() {
        return Err(("400 Bad Request", "nothing to send".into()));
    }

    let t = crate::outbound::resolve_reply(&thread)
        .map_err(|e| ("409 Conflict", e.to_string()))?;
    if crate::routes::Routes::load().home_of(&t.to).is_none() {
        return Err((
            "409 Conflict",
            format!(
                "{} has no local route, so this reply cannot be delivered from here. \
                 In a terminal: ctx reply {} --text \"...\" then ctx push <dir> --to {} --yes",
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
    let r = crate::outbound::send_bundle(crate::outbound::SendArgs {
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
        agent: None,
        model: None,
    });
    let _ = std::fs::remove_dir_all(&tmp);
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
/// bug `ctx open` refuses to have, hidden better: the person reading verdicts
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
            eprintln!("ctx ui: WARNING -- inbox not recorded ({e}); verdicts withheld");
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
    if observed { t.label() } else { crate::trust::VERDICT_UNAVAILABLE }
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
    let mut trust_of: std::collections::BTreeMap<String, (String, Vec<String>)> = Default::default();
    let mut manifests = Vec::new();
    for (name, dir) in [
        ("pending", crate::routes::pending_dir(&home)),
        ("accepted", crate::routes::accepted_dir(&home)),
        ("sent", crate::routes::sent_dir(&home)),
    ] {
        for (_, l) in crate::routes::list(&dir) {
            let id = l.manifest.id.clone();
            stage_of.entry(id.clone()).or_insert((name, dir.join(&id).display().to_string()));
            trust_of
                .entry(id.clone())
                .or_insert((verdict_label(observed, &l).to_string(), l.tampered.clone()));
            if !manifests.iter().any(|m: &crate::manifest::Manifest| m.id == id) {
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
            // Who a reply would go to, worked out the same way `ctx reply`
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
                                    message from a terminal: ctx reply <message id>",
                                   t.others.len()) })
            } else { match parent {
                None => serde_json::json!({ "can": false,
                    "why": "every message here is your own" }),
                Some(p) => match contacts.name_for(&p.from.key) {
                    None => serde_json::json!({ "can": false,
                        "why": "the key that signed the last message is not on your list" }),
                    Some(name) if routes.home_of(name).is_none() => serde_json::json!({
                        "can": false, "to": name,
                        "why": format!("{name} has no local route, so a reply has to go out \
                                        through ctx push in a terminal") }),
                    Some(_) if t.unverified.contains(&p.id) => serde_json::json!({
                        "can": false,
                        "why": "the newest message claims this thread while answering \
                                something you do not hold, so it is not a safe reply \
                                target" }),
                    Some(name) => serde_json::json!({ "can": true, "to": name,
                        "type": if p.msg_type.expects_reply() { "answer" } else { "share" } }),
                },
            } };
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(bundle_id(&format!("/api/read/{}", "a".repeat(65)), "/api/read/"), None);
        // A prefix that is not this route's.
        assert_eq!(bundle_id("/api/close/abc", "/api/read/"), None);
    }

    #[test]
    fn a_failed_observation_withholds_the_verdict_instead_of_softening_it() {
        // The label is what the viewer shows in place of a verdict, and the
        // one thing it must never be is a verdict. `ctx open` refuses to
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
        assert_ne!(crate::trust::VERDICT_UNAVAILABLE, crate::trust::Trust::Known.label());
        assert_ne!(crate::trust::VERDICT_UNAVAILABLE, crate::trust::Trust::Unwitnessed.label());
    }
}
