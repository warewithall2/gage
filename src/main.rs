//! ctx -- hand context between agents, with a trust boundary.
//!
//! Transport-agnostic on purpose. A bundle is a directory, so it moves over
//! anything you already have: a shared folder for two agents on one machine,
//! git, email, a file drop. No server is required, and none is included,
//! because agents are invoked rather than online -- presence is the part of
//! the instant-messenger model that does not transfer.

mod bundle;
mod collect;
mod identity;
mod manifest;
mod open;
mod relay;
mod remote;
mod routes;
mod seal;
mod ui;
mod trust;

use clap::{Parser, Subcommand};
use manifest::AgentInfo;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ctx", about = "Hand context between agents, with provenance")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your identity keypair
    Init { handle: String },
    /// Print your public handle and key, to give to someone else
    Whoami,
    /// Add someone's key to your buddy list (the signpub.boxpub token)
    Add { name: String, key: String },
    /// Encrypt a bundle for one recipient. Nothing leaves this machine unsealed.
    Seal {
        dir: PathBuf,
        #[arg(long)] to: String,
        #[arg(long)] out: PathBuf,
    },
    /// Decrypt an envelope back into a bundle directory
    Unseal {
        file: PathBuf,
        #[arg(long)] out: PathBuf,
    },
    /// List your contacts and groups
    Contacts,
    /// Build a bundle
    Send {
        #[arg(long)] to: Vec<String>,
        #[arg(long)] subject: String,
        /// Where to write it. Omit when --to is a routed local handle.
        #[arg(long)] out: Option<PathBuf>,
        #[arg(long)] file: Vec<PathBuf>,
        #[arg(long)] prompt: Vec<PathBuf>,
        #[arg(long)] decision: Vec<PathBuf>,
        /// An agent's persistent memory (CLAUDE.md, AGENTS.md, memory/*.md).
        /// Fenced hardest on receipt: it outlives the session that accepts it.
        #[arg(long)] memory: Vec<PathBuf>,
        /// A whole directory, structure preserved, build dirs and
        /// secret-looking files skipped
        #[arg(long)] dir: Vec<PathBuf>,
        /// Include files that look like secrets (.env, *.pem, *.key). Off by
        /// default, and you should have a reason.
        #[arg(long)] allow_secrets: bool,
        /// Bundle id this one answers
        #[arg(long)] reply_to: Option<String>,
        #[arg(long)] agent: Option<String>,
        #[arg(long)] model: Option<String>,
    },
    /// Summarise a bundle without putting its contents in context
    Inspect { dir: PathBuf },
    /// Render a bundle for an agent to read, inside a trust frame
    Open {
        dir: PathBuf,
        /// Show contents even when the signature does not verify
        #[arg(long)] reveal: bool,
    },
    /// Map a handle to a local ctx home, so --to delivers with no --out
    Route { handle: String, home: PathBuf },
    /// What is waiting for you
    Inbox {
        /// machine-readable, for an agent harness
        #[arg(long)] json: bool,
        /// include already-accepted bundles
        #[arg(long)] all: bool,
    },
    /// Move a pending bundle to accepted. Arrival is not consent.
    Accept { id: String },
    /// Delete a pending bundle without reading it
    Reject { id: String },
    /// Run a relay (on the box that will hold mail)
    Relay {
        /// Bind address. Default is the tailnet-only loopback-equivalent:
        /// pass the tailnet IP explicitly rather than 0.0.0.0.
        #[arg(long, default_value = "127.0.0.1:7788")] bind: String,
        #[arg(long)] store: Option<PathBuf>,
    },
    /// Point this identity at a relay and register your mailbox
    Join { addr: String },
    /// Push a sealed envelope to the relay for a contact
    Push {
        dir: PathBuf,
        #[arg(long)] to: String,
    },
    /// Collect anything waiting for you on the relay into inbox/pending
    Pull {
        /// leave envelopes on the relay instead of deleting them
        #[arg(long)] keep: bool,
    },
    /// Serve the local viewer on 127.0.0.1
    Ui {
        #[arg(long, default_value = "7777")] port: u16,
    },
    /// Re-sign a bundle for someone else, appending to its chain
    Forward {
        dir: PathBuf,
        #[arg(long)] to: Vec<String>,
        #[arg(long)] out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ctx: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Init { handle } => {
            let id = identity::Identity::create(&handle)?;
            println!("identity created in {}", identity::home().display());
            println!("handle : {handle}");
            println!("key    : {}", id.public_b64());
            println!("\nGive the line above to anyone who should be able to send to you.");
        }
        Cmd::Whoami => {
            let id = identity::Identity::load()?;
            println!("{}\t{}", id.handle, id.full_key());
        }
        Cmd::Add { name, key } => {
            let (sign, boxpub) = identity::split_key(&key);
            if !bundle::b64_decode_ok(&sign) {
                return Err("that signing key is not valid base64".into());
            }
            if let Some(b) = &boxpub {
                if !bundle::b64_decode_ok(b) {
                    return Err("that encryption key is not valid base64".into());
                }
            }
            let mut c = trust::Contacts::load();
            c.keys.insert(sign.clone(), name.clone());
            match &boxpub {
                Some(b) => {
                    c.box_keys.insert(sign, b.clone());
                    println!("added {name} (verify + encrypt)");
                }
                None => println!(
                    "added {name} (verify only -- no encryption key, so you cannot seal to them)"
                ),
            }
            c.save()?;
        }
        Cmd::Seal { dir, to, out } => {
            let c = trust::Contacts::load();
            let Some(sign) = c.key_for_name(&to) else {
                return Err(format!("no contact named {to}; ctx add {to} <key>").into());
            };
            let Some(boxpub) = c.box_keys.get(&sign) else {
                return Err(format!(
                    "{to} has no encryption key on file. Get their current \
                     `ctx whoami` token (signpub.boxpub) and re-add them."
                )
                .into());
            };
            let env = seal::seal_dir(&dir, boxpub)?;
            std::fs::write(&out, serde_json::to_vec(&env)?)?;
            let n = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
            println!("sealed to {to} -> {} ({n} bytes)", out.display());
            println!("  the envelope reveals only their key, its size and the time it was made");
        }
        Cmd::Unseal { file, out } => {
            let id = identity::Identity::load()?;
            let env: seal::Envelope = serde_json::from_slice(&std::fs::read(&file)?)?;
            seal::unseal_to_dir(&env, &id, &out)?;
            println!("unsealed -> {}", out.display());
            println!("  decryption proves nothing about the sender; run ctx open to see the");
            println!("  signature verdict, which is what attributes it");
        }
        Cmd::Contacts => {
            let c = trust::Contacts::load();
            if c.keys.is_empty() {
                println!("no contacts yet");
            }
            for (k, n) in &c.keys {
                println!("{n}\t{}…", k.chars().take(16).collect::<String>());
            }
            for (g, members) in &c.groups {
                println!("group:{g}\t{} member(s)", members.len());
            }
        }
        Cmd::Send {
            to, subject, out, file, prompt, decision, memory, dir,
            allow_secrets, reply_to, agent, model,
        } => {
            let id = identity::Identity::load()?;
            let c = collect::collect(&file, &prompt, &decision, &memory, &dir, allow_secrets)?;
            // Skips are printed BEFORE the bundle is built, so a sender sees
            // what is not going out while they can still change their mind.
            if !c.skipped_secret.is_empty() {
                println!("skipped (look like secrets, --allow-secrets to include):");
                for f in &c.skipped_secret {
                    println!("  {f}");
                }
            }
            if !c.skipped_big.is_empty() {
                println!("skipped (over the per-item size limit):");
                for f in &c.skipped_big {
                    println!("  {f}");
                }
            }
            if !c.skipped_dir.is_empty() {
                let mut d = c.skipped_dir.clone();
                d.sort();
                d.dedup();
                println!("skipped build/cache dirs: {}", d.join(", "));
            }
            let skipped = c.skipped_secret.len() + c.skipped_big.len();
            let specs = c.items;
            if specs.is_empty() {
                // Distinguish "you passed nothing" from "everything you passed
                // was filtered". The second read as the first, which sends you
                // looking for a flag you already used.
                if skipped > 0 {
                    return Err(format!(
                        "nothing left to send: all {skipped} item(s) were skipped \
                         (listed above). Rename them, pick different paths, or pass \
                         --allow-secrets if you are sure."
                    )
                    .into());
                }
                return Err("nothing to send: pass --file, --dir, --prompt, --decision or --memory".into());
            }
            if to.is_empty() {
                return Err("no recipient: pass --to <handle|group:name>".into());
            }
            let ag = agent.map(|name| AgentInfo { name, model });
            // Built once into a staging dir, then delivered to each routed
            // recipient. Building per-recipient would give one payload a
            // different content id for every person who received it.
            let routes = routes::Routes::load();
            let stage = out.clone().unwrap_or_else(|| {
                identity::home().join(format!("outbox/{}", std::process::id()))
            });
            let m = bundle::create(&stage, &id, &subject, &to, ag, reply_to, &specs)?;
            let mut delivered = Vec::new();
            for who in &to {
                if let Some(h) = routes.home_of(who) {
                    let dest = routes::pending_dir(&h).join(&m.id);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    routes::deliver(&stage, &dest)?;
                    delivered.push(format!("{who} -> {}", dest.display()));
                }
            }
            println!(
                "bundle {} -- {} item(s), {} bytes, signed by {}",
                m.id, m.items.len(), m.total_bytes(), id.handle
            );
            if m.memory_count() > 0 {
                println!(
                    "  {} MEMORY item(s): these persist in whoever accepts them",
                    m.memory_count()
                );
            }
            for d in &delivered {
                println!("  delivered {d}");
            }
            let unrouted: Vec<String> =
                to.iter().filter(|w| routes.home_of(w).is_none()).cloned().collect();
            if !unrouted.is_empty() {
                println!("  no local route for: {}", unrouted.join(", "));
                println!("  bundle is at {} -- move it yourself, or", stage.display());
                println!("  ctx route <handle> <their-ctx-home> to deliver automatically");
            }
        }
        Cmd::Inspect { dir } => {
            let l = bundle::load(&dir)?;
            let m = &l.manifest;
            println!("id       : {}", m.id);
            println!("subject  : {}", m.subject);
            println!("trust    : {}", l.trust.label());
            println!("from     : {} ({}…)", m.from.handle, m.from.key.chars().take(16).collect::<String>());
            println!("forwarded: {}", if m.is_forwarded() { "yes" } else { "no" });
            println!("to       : {}", m.to.join(", "));
            for it in &m.items {
                println!("  {:?}\t{}\t{} bytes", it.kind, it.path, it.bytes);
            }
            if !l.tampered.is_empty() {
                println!("TAMPERED : {}", l.tampered.join(", "));
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Open { dir, reveal } => {
            let l = bundle::load(&dir)?;
            print!("{}", open::render(&l, reveal));
            // Non-zero when the content could not be attributed, so a script
            // or agent harness can branch on it instead of parsing prose.
            if !l.tampered.is_empty() || matches!(l.trust, trust::Trust::Unverified) {
                return Ok(ExitCode::from(2));
            }
        }
        Cmd::Route { handle, home } => {
            let mut r = routes::Routes::load();
            r.local.insert(handle.clone(), home.display().to_string());
            r.save()?;
            println!("{handle} -> {}", home.display());
        }
        Cmd::Inbox { json, all } => {
            let me = identity::home();
            let pending = routes::list(&routes::pending_dir(&me));
            let accepted = if all { routes::list(&routes::accepted_dir(&me)) } else { vec![] };
            if json {
                let rows: Vec<serde_json::Value> = pending
                    .iter()
                    .map(|(_, l)| {
                        serde_json::json!({
                            "stage": "pending",
                            "id": l.manifest.id,
                            "subject": l.manifest.subject,
                            "from_handle_claimed": l.manifest.from.handle,
                            "from_key": l.manifest.from.key,
                            "trust": l.trust.label(),
                            "forwarded": l.manifest.is_forwarded(),
                            "prompts": l.manifest.prompt_count(),
                            "items": l.manifest.items.len(),
                            "tampered": l.tampered,
                        })
                    })
                    .chain(accepted.iter().map(|(_, l)| {
                        serde_json::json!({
                            "stage": "accepted",
                            "id": l.manifest.id,
                            "subject": l.manifest.subject,
                            "from_key": l.manifest.from.key,
                            "trust": l.trust.label(),
                        })
                    }))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                let contacts = trust::Contacts::load();
                if pending.is_empty() {
                    println!("nothing pending");
                }
                for (_, l) in &pending {
                    let m = &l.manifest;
                    let who = contacts
                        .name_for(&m.from.key)
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| format!("\"{}\" (unlisted key)", m.from.handle));
                    let p = if m.prompt_count() > 0 {
                        format!("  [{} prompt(s)]", m.prompt_count())
                    } else {
                        String::new()
                    };
                    println!("{}  from {}  {}{}", m.id, who, m.subject, p);
                    println!("      {}", l.trust.label());
                    if !l.tampered.is_empty() {
                        println!("      TAMPERED: {}", l.tampered.join(", "));
                    }
                }
                if !pending.is_empty() {
                    println!("\nctx accept <id> to stage it, ctx reject <id> to drop it unread");
                }
                for (_, l) in &accepted {
                    println!("[accepted] {}  {}", l.manifest.id, l.manifest.subject);
                }
            }
        }
        Cmd::Accept { id } => {
            let me = identity::home();
            let from = routes::pending_dir(&me).join(&id);
            if !from.is_dir() {
                return Err(format!("no pending bundle {id}").into());
            }
            let to_dir = routes::accepted_dir(&me);
            std::fs::create_dir_all(&to_dir)?;
            let dest = to_dir.join(&id);
            routes::deliver(&from, &dest)?;
            std::fs::remove_dir_all(&from)?;
            println!("accepted {id}");
            println!("  ctx open {}", dest.display());
        }
        Cmd::Reject { id } => {
            let p = routes::pending_dir(&identity::home()).join(&id);
            if !p.is_dir() {
                return Err(format!("no pending bundle {id}").into());
            }
            std::fs::remove_dir_all(&p)?;
            println!("rejected {id}, deleted unread");
        }
        Cmd::Relay { bind, store } => {
            let root = store.unwrap_or_else(|| identity::home().join("relaystore"));
            relay::serve(&bind, root)?;
        }
        Cmd::Join { addr } => {
            let id = identity::Identity::load()?;
            let body = serde_json::json!({
                "sign_key": id.public_b64(), "box_key": id.box_public_b64() })
                .to_string();
            remote::post(&addr, "/register", &body)?;
            remote::set_relay(&addr)?;
            println!("registered with {addr} and saved it as your relay");
            println!("  the relay holds sealed envelopes; it cannot read them");
        }
        Cmd::Push { dir, to } => {
            let addr = remote::relay_addr().ok_or("no relay set; ctx join <addr> first")?;
            let c = trust::Contacts::load();
            let sign = c.key_for_name(&to).ok_or(format!("no contact named {to}"))?;
            let boxpub = c
                .box_keys
                .get(&sign)
                .ok_or(format!("{to} has no encryption key on file; re-add them"))?;
            let env = seal::seal_dir(&dir, boxpub)?;
            let body = serde_json::json!({
                "to_box": boxpub, "envelope": serde_json::to_string(&env)? })
                .to_string();
            let resp = remote::post(&addr, "/send", &body)?;
            println!("pushed to {to} via {addr}");
            println!("  {}", resp.trim());
        }
        Cmd::Pull { keep } => {
            let addr = remote::relay_addr().ok_or("no relay set; ctx join <addr> first")?;
            let id = identity::Identity::load()?;
            // Prove possession of the signing key registered for this mailbox.
            // Naming a key is not proof: anyone who has seen a `ctx whoami`
            // line knows it.
            let ch = remote::post(
                &addr,
                "/challenge",
                &serde_json::json!({ "box_key": id.box_public_b64() }).to_string(),
            )?;
            let nonce = serde_json::from_str::<serde_json::Value>(&ch)
                .ok()
                .and_then(|v| v.get("nonce").and_then(|n| n.as_str()).map(String::from))
                .ok_or("relay did not issue a challenge")?;
            let body = serde_json::json!({
                "box_key": id.box_public_b64(),
                "nonce": nonce,
                "sig": id.sign_b64(nonce.as_bytes()),
                "delete": !keep,
            })
            .to_string();
            let resp = remote::post(&addr, "/fetch", &body)?;
            let v: serde_json::Value = serde_json::from_str(&resp)?;
            let items = v.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
            if items.is_empty() {
                println!("nothing waiting on {addr}");
            }
            let pending = routes::pending_dir(&identity::home());
            std::fs::create_dir_all(&pending)?;
            let mut n = 0;
            for it in &items {
                let Some(raw) = it.get("envelope").and_then(|e| e.as_str()) else { continue };
                let env: seal::Envelope = match serde_json::from_str(raw) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("  skipped an unreadable envelope: {e}");
                        continue;
                    }
                };
                // Unseal into a temp dir first, read the id from the manifest,
                // then move it into place: the relay does not get to choose
                // the directory name an envelope lands in.
                let tmp = identity::home().join(format!("tmp-pull-{}-{n}", std::process::id()));
                let _ = std::fs::remove_dir_all(&tmp);
                if let Err(e) = seal::unseal_to_dir(&env, &id, &tmp) {
                    eprintln!("  skipped: {e}");
                    let _ = std::fs::remove_dir_all(&tmp);
                    continue;
                }
                let loaded = bundle::load(&tmp)?;
                let dest = pending.join(&loaded.manifest.id);
                if dest.exists() {
                    println!("  already have {} -- left in place", loaded.manifest.id);
                } else {
                    routes::deliver(&tmp, &dest)?;
                    println!(
                        "  {}  {}  ({})",
                        loaded.manifest.id,
                        loaded.manifest.subject,
                        loaded.trust.label()
                    );
                    n += 1;
                }
                let _ = std::fs::remove_dir_all(&tmp);
            }
            if n > 0 {
                println!("\n{n} bundle(s) in inbox/pending -- ctx inbox, then accept or reject");
            }
        }
        Cmd::Ui { port } => {
            ui::serve(port)?;
        }
        Cmd::Forward { dir, to, out } => {
            let id = identity::Identity::load()?;
            if to.is_empty() {
                return Err("no recipient: pass --to".into());
            }
            let m = bundle::forward(&dir, &out, &id, &to)?;
            println!("forwarded {} as {} hop(s) to {}", m.id, m.chain.len(), to.join(", "));
        }
    }
    Ok(ExitCode::SUCCESS)
}
