//! ctx -- hand context between agents, with a trust boundary.
//!
//! Transport-agnostic on purpose. A bundle is a directory, so it moves over
//! anything you already have: a shared folder for two agents on one machine,
//! git, email, a file drop. No server is required, and none is included,
//! because agents are invoked rather than online -- presence is the part of
//! the instant-messenger model that does not transfer.

mod bundle;
mod identity;
mod manifest;
mod open;
mod routes;
mod ui;
mod trust;

use clap::{Parser, Subcommand};
use manifest::{AgentInfo, ItemKind};
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
    /// Add someone's key to your buddy list
    Add { name: String, key: String },
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
            println!("{}\t{}", id.handle, id.public_b64());
        }
        Cmd::Add { name, key } => {
            if !bundle::b64_decode_ok(&key) {
                return Err("that key is not valid base64".into());
            }
            let mut c = trust::Contacts::load();
            c.keys.insert(key.trim().to_string(), name.clone());
            c.save()?;
            println!("added {name}");
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
        Cmd::Send { to, subject, out, file, prompt, decision, agent, model } => {
            let id = identity::Identity::load()?;
            let mut specs: Vec<(ItemKind, PathBuf)> = Vec::new();
            specs.extend(file.into_iter().map(|p| (ItemKind::File, p)));
            specs.extend(prompt.into_iter().map(|p| (ItemKind::Prompt, p)));
            specs.extend(decision.into_iter().map(|p| (ItemKind::Decision, p)));
            if specs.is_empty() {
                return Err("nothing to send: pass --file, --prompt or --decision".into());
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
            let m = bundle::create(&stage, &id, &subject, &to, ag, &specs)?;
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
            println!("bundle {} -- {} item(s), signed by {}", m.id, m.items.len(), id.handle);
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
