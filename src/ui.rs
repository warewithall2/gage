//! `ctx ui` -- a local viewer, bound to 127.0.0.1 only.
//!
//! This is the buddy-list window: who you trust, what is waiting, and what
//! each bundle claims, with the trust verdict shown as prominently as the
//! subject line. It exists because the verdict is the product, and a verdict
//! nobody looks at is not a control.
//!
//! Deliberately read-plus-accept only. The browser can accept or reject a
//! pending bundle, because that is the human gate this design is built
//! around, but it cannot render payload contents: a page that pastes a
//! stranger's prompt into a browser is a different risk surface, and
//! `ctx open` is where content is meant to be read, inside its frame.
//!
//! Hand-rolled HTTP rather than a web framework, so the one network-facing
//! surface in this tool is about eighty lines a reader can audit in full.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

pub fn serve(port: u16) -> std::io::Result<()> {
    // Loopback only, never 0.0.0.0. An inbox viewer on a laptop has no
    // business being reachable from the network it happens to be on.
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("ctx ui on http://127.0.0.1:{port}  (ctrl-c to stop)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s) {
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

fn handle(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    // Only the three routes below exist. Anything else is a 404 rather than a
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
            let id = t.rsplit('/').next().unwrap_or("");
            if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            }
            let mut st = crate::state::LocalState::load();
            match st.mark_read(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(stream, "500 Internal Server Error", "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string()),
            }
        }
        ("POST", t) if t.starts_with("/api/close/") => {
            let id = t.rsplit('/').next().unwrap_or("");
            if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            }
            let mut st = crate::state::LocalState::load();
            match st.close(id) {
                Ok(()) => respond(stream, "200 OK", "application/json", "{\"ok\":true}"),
                Err(e) => respond(stream, "500 Internal Server Error", "application/json",
                    &serde_json::json!({"error": e.to_string()}).to_string()),
            }
        }
        ("POST", t) if t.starts_with("/api/accept/") || t.starts_with("/api/reject/") => {
            let accept = t.starts_with("/api/accept/");
            let id = t.rsplit('/').next().unwrap_or("");
            // An id reaches the filesystem, so it must be an id and nothing
            // else: the bundle ids this tool mints are lowercase hex.
            if id.is_empty()
                || id.len() > 64
                || !id.chars().all(|c| c.is_ascii_hexdigit())
            {
                return respond(stream, "400 Bad Request", "application/json", "{\"error\":\"bad id\"}");
            }
            let me = crate::identity::home();
            let from = crate::routes::pending_dir(&me).join(id);
            if !from.is_dir() {
                return respond(stream, "404 Not Found", "application/json", "{\"error\":\"no such pending bundle\"}");
            }
            let res = if accept {
                let dest_dir = crate::routes::accepted_dir(&me);
                std::fs::create_dir_all(&dest_dir)
                    .and_then(|_| crate::routes::deliver(&from, &dest_dir.join(id)))
                    .and_then(|_| std::fs::remove_dir_all(&from))
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
        _ => respond(stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

fn state_json() -> String {
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
                    "known_as": contacts.name_for(&m.from.key),
                    "key": m.from.key,
                    "trust": l.trust.label(),
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
    let me_id = crate::identity::Identity::load().ok();
    let mine = me_id.as_ref().map(|i| i.public_b64()).unwrap_or_default();
    let st = crate::state::LocalState::load();
    let contacts = crate::trust::Contacts::load();
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
            trust_of.entry(id.clone()).or_insert((l.trust.label().to_string(), l.tampered.clone()));
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
                        "hops": m.chain.len(),
                        "claimed_name": m.from.handle,
                        "known_as": contacts.name_for(&m.from.key),
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
            serde_json::json!({
                "id": t.id,
                "subject": t.subject,
                "state": t.state.label(),
                "unread": t.unread,
                "messages": msgs,
            })
        })
        .collect();

    serde_json::json!({
        "me": me_id.map(|i| serde_json::json!({ "handle": i.handle, "key": i.public_b64() })),
        "threads": rows,
        "contacts": contacts.keys.iter().map(|(k, n)| serde_json::json!({
            "name": n, "key": k })).collect::<Vec<_>>(),
    })
    .to_string()
}

const INDEX: &str = include_str!("ui.html");
