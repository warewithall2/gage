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
mod notify;
mod outbound;
mod open;
mod relay;
mod remote;
mod rotate;
mod routes;
mod scrub;
mod state;
mod seal;
mod ui;
mod trust;

use clap::{Parser, Subcommand};
use outbound::{all_manifests, resolve_reply, send_bundle, SendArgs};
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
    /// Replace your keypair, keeping the old one on record
    Rotate {
        /// The old key was STOLEN. Drops your copy of its secrets and makes
        /// the notice unsigned by it, because a thief can sign too.
        #[arg(long)] compromised: bool,
    },
    /// Your key history: what is current, what is retired
    Keys,
    /// Check a contact's rotation notice, and apply it only if told to
    Keychange {
        file: PathBuf,
        /// Actually move the contact onto the new key
        #[arg(long)] accept: bool,
    },
    /// Take a contact's key out of service without a replacement
    Retire {
        name: String,
        /// Their key was stolen, so even their old bundles stop counting
        #[arg(long)] compromised: bool,
        /// Also condemn every earlier key you held for them. For when you
        /// learn they were compromised long before you found out.
        #[arg(long)] all: bool,
    },
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
        /// Bundle id this one answers. Inherits that bundle's thread.
        #[arg(long)] reply_to: Option<String>,
        /// share | question | answer | review-request | ack
        #[arg(long, default_value = "share")] r#type: String,
        /// Proceed despite findings from the outbound content scan. Prints
        /// what it is overriding.
        #[arg(long)] allow_findings: bool,
        #[arg(long)] agent: Option<String>,
        #[arg(long)] model: Option<String>,
    },
    /// Answer a thread without typing its id or working out the recipient
    Reply {
        /// Thread or message id. A unique prefix is enough.
        id: String,
        /// The reply itself, as text. Scanned on the way out like any file.
        #[arg(long)] text: Option<String>,
        #[arg(long)] file: Vec<PathBuf>,
        #[arg(long)] prompt: Vec<PathBuf>,
        #[arg(long)] decision: Vec<PathBuf>,
        #[arg(long)] memory: Vec<PathBuf>,
        #[arg(long)] dir: Vec<PathBuf>,
        /// Override the inferred type (answer for a question, otherwise share)
        #[arg(long)] r#type: Option<String>,
        /// Override the inferred subject
        #[arg(long)] subject: Option<String>,
        #[arg(long)] allow_secrets: bool,
        #[arg(long)] allow_findings: bool,
        #[arg(long)] agent: Option<String>,
        #[arg(long)] model: Option<String>,
        #[arg(long)] out: Option<PathBuf>,
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
    /// Conversations, grouped, newest activity first
    Threads {
        /// only threads where the ball is in your court
        #[arg(long)] mine: bool,
    },
    /// Every message in one thread, oldest first
    Thread { id: String },
    /// Mark a thread settled regardless of what the messages imply
    Close { thread: String },
    /// What is waiting for you
    Inbox {
        /// machine-readable, for an agent harness
        #[arg(long)] json: bool,
        /// include already-accepted bundles
        #[arg(long)] all: bool,
        /// only what you have not opened
        #[arg(long)] unread: bool,
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
        /// Skip the confirmation. Required for a non-interactive push, so an
        /// agent has to state that it meant to send this off the machine.
        #[arg(long)] yes: bool,
    },
    /// Collect anything waiting for you on the relay into inbox/pending
    Pull {
        /// leave envelopes on the relay instead of deleting them
        #[arg(long)] keep: bool,
    },
    /// Poll the relay and notify when something new arrives
    Watch {
        /// seconds between polls
        #[arg(long, default_value = "120")] every: u64,
        /// check once and exit, for a systemd timer or a cron entry
        #[arg(long)] once: bool,
        /// print instead of firing a desktop notification
        #[arg(long)] quiet: bool,
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

/// Restore the default SIGPIPE disposition. Declared here rather than taking
/// a libc dependency for one constant.
#[cfg(unix)]
unsafe fn libc_signal_default() {
    unsafe extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
    }
    const SIGPIPE: i32 = 13;
    const SIG_DFL: usize = 0;
    unsafe { signal(SIGPIPE, SIG_DFL) };
}

/// Collect anything waiting on the relay into inbox/pending.
///
/// Shared by `pull` and `watch` rather than duplicated: a watcher that
/// collected differently from a manual pull would announce bundles the user
/// could then not find.
fn pull_once(keep: bool) -> Result<(), Box<dyn std::error::Error>> {
    pull_inner(keep, false)
}

/// `quiet` suppresses the nothing-to-do line. A watcher polls on an interval,
/// and a line per poll turns its journal into noise that hides the one entry
/// that mattered.
fn pull_inner(keep: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let addr = remote::relay_addr().ok_or("no relay set; ctx join <addr> first")?;
    let id = identity::Identity::load()?;
    let mut total = 0;
    let mut saw_any = false;

    // The current mailbox, then any retired one whose secrets were kept.
    //
    // A rotation does not reach the people who already sealed something to
    // your old key and pushed it. Draining only the new mailbox would lose
    // that mail silently, which is the kind of cost that teaches people never
    // to rotate -- so the old mailbox keeps being collected until its
    // envelopes are gone.
    let mut boxes = vec![(id.box_public_b64(), String::new())];
    for r in id.retired() {
        if r.can_collect() {
            boxes.push((r.box_pub.clone(), format!(" (retired key, {})", r.retired_at)));
        }
    }

    for (box_pub, label) in &boxes {
        match fetch_mailbox(&addr, &id, box_pub, keep, label) {
            Ok((n, had)) => {
                total += n;
                saw_any |= had;
            }
            Err(e) if label.is_empty() => return Err(e),
            // A retired mailbox may simply not exist on this relay -- it was
            // registered before the relay was rebuilt, or never registered at
            // all. That is not a failed pull.
            Err(e) => {
                if !quiet {
                    eprintln!("  retired mailbox{label}: {e}");
                }
            }
        }
    }
    if !saw_any && !quiet {
        println!("nothing waiting on {addr}");
    }
    if total > 0 {
        println!("\n{total} bundle(s) in inbox/pending -- ctx inbox, then accept or reject");
    }
    Ok(())
}

/// Drain one mailbox. Returns (bundles delivered, anything was waiting).
fn fetch_mailbox(
    addr: &str,
    id: &identity::Identity,
    box_pub: &str,
    keep: bool,
    label: &str,
) -> Result<(usize, bool), Box<dyn std::error::Error>> {
    // Prove possession of the signing key registered for this mailbox.
    // Naming a key is not proof: anyone who has seen a `ctx whoami`
    // line knows it.
    let ch = remote::post(
        addr,
        "/challenge",
        &serde_json::json!({ "box_key": box_pub }).to_string(),
    )?;
    let nonce = serde_json::from_str::<serde_json::Value>(&ch)
        .ok()
        .and_then(|v| v.get("nonce").and_then(|n| n.as_str()).map(String::from))
        .ok_or("relay did not issue a challenge")?;
    let sig = id
        .sign_for_box(box_pub, nonce.as_bytes())
        .ok_or("no signing key for that mailbox any more")?;
    let body = serde_json::json!({
        "box_key": box_pub,
        "nonce": nonce,
        "sig": sig,
        "delete": !keep,
    })
    .to_string();
    let resp = remote::post(addr, "/fetch", &body)?;
    let v: serde_json::Value = serde_json::from_str(&resp)?;
    let items = v.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
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
        if let Err(e) = seal::unseal_to_dir(&env, id, &tmp) {
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
                "  {}  {}  ({}){}",
                loaded.manifest.id,
                loaded.manifest.subject,
                loaded.trust.label(),
                label
            );
            n += 1;
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
    Ok((n, !items.is_empty()))
}

fn main() -> ExitCode {
    // Rust sets SIGPIPE to ignore, so writing to a closed pipe returns an
    // error that `println!` turns into a panic. `ctx threads | head` then
    // prints a Rust backtrace instead of just stopping. Restoring the default
    // makes the process die quietly when its reader goes away, which is what
    // every other command-line tool does.
    #[cfg(unix)]
    unsafe {
        libc_signal_default();
    }
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
        Cmd::Rotate { compromised } => {
            let at = bundle::now_rfc3339();
            let (id, notice) = identity::Identity::rotate(compromised, &at)?;
            let np = identity::home().join("rotation.json");
            std::fs::write(&np, &notice.json)?;
            println!("rotated at {at}");
            println!("  old key : {}", notice.old_key);
            println!("  new key : {}", notice.new_key);
            if compromised {
                // Said first and said plainly. The secrets are gone, which
                // means anything already sealed to the old key and still
                // sitting on a relay is now unreadable BY YOU -- the thief
                // could read it either way, so this is the right trade, but
                // it is a loss and should not be discovered later.
                println!("\n  the old secrets are destroyed. Envelopes already sealed to");
                println!("  that key can no longer be opened here, by you or anyone");
                println!("  using this machine.");
                println!("  the notice is NOT countersigned by the old key: a thief holds");
                println!("  it, so a countersignature from it would prove nothing. Your");
                println!("  contacts must confirm this change with you directly.");
            } else {
                println!("\n  the old secrets are kept so mail already sealed to them can");
                println!("  still be collected. ctx pull drains both mailboxes.");
            }
            println!("\nnotice written to {}", np.display());
            println!("  send it to each contact; they run: ctx keychange <file>");
            if remote::relay_addr().is_some() {
                let addr = remote::relay_addr().unwrap();
                let body = serde_json::json!({
                    "sign_key": id.public_b64(), "box_key": id.box_public_b64() })
                    .to_string();
                match remote::post(&addr, "/register", &body) {
                    Ok(_) => println!("\nregistered the new mailbox with {addr}"),
                    Err(e) => println!("\ncould not register with {addr}: {e}\n  run ctx join {addr} once it is reachable"),
                }
            }
        }
        Cmd::Keys => {
            let id = identity::Identity::load()?;
            println!("current\t{}\t{}", id.handle, id.full_key());
            for r in id.retired() {
                println!(
                    "retired\t{}\t{}.{}\t{}{}",
                    r.retired_at,
                    r.sign_pub,
                    r.box_pub,
                    r.reason,
                    if r.can_collect() { "" } else { " (secrets destroyed)" }
                );
            }
        }
        Cmd::Keychange { file, accept } => {
            let n: rotate::Notice = serde_json::from_slice(&std::fs::read(&file)?)?;
            let v = rotate::verify_notice(&n).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let mut c = trust::Contacts::load();
            let known = c.name_for(&v.old_sign).map(|s| s.to_string());
            println!("rotation notice");
            println!("  claims handle : {} (their own text, not identity)", v.claim.handle);
            println!("  old key       : {}…", v.old_sign.chars().take(16).collect::<String>());
            println!("  new key       : {}…", v.new_sign.chars().take(16).collect::<String>());
            println!("  dated         : {}", v.claim.at);
            println!("  reason        : {}", v.claim.reason);
            println!("  new key signed: yes");
            println!(
                "  old key signed: {}",
                if v.old_signed { "yes" } else { "NO" }
            );
            match &known {
                Some(name) => println!("  the old key is on your list as: {name}"),
                None => println!("  the old key is NOT on your list"),
            }
            if c.retired_record(&v.old_sign).is_some() && c.knows(&v.new_sign) {
                println!("\nalready applied; nothing to do");
                return Ok(ExitCode::SUCCESS);
            }
            let Some(name) = known else {
                return Err("you have never accepted the old key, so this notice \
                            upgrades nothing. If you trust the new key, confirm it \
                            with them directly and run: ctx add <name> <newkey>"
                    .into());
            };
            if !v.old_signed {
                // The whole point of the countersignature. Without it the
                // notice is a stranger's assertion about your contact, and
                // accepting it on sight is how you get handed an attacker's
                // key. Refusing here costs a confirmed-by-voice step; not
                // refusing costs the contact.
                return Err(format!(
                    "NOT APPLIED: this notice is not countersigned by {name}'s current \
                     key, so nothing here shows that {name} authorised it. Confirm the \
                     new key with them over a channel that is not this one, then:\n  \
                     ctx retire {name} {}\n  ctx add {name} {}",
                    if v.claim.reason == "compromised" { "--compromised" } else { "" },
                    v.claim.new_key
                )
                .into());
            }
            if !accept {
                println!("\nnot applied. The countersignature shows the holder of the old");
                println!("key authorised this -- which is also true if that key was stolen.");
                println!("Confirm with {name} directly, then re-run with --accept.");
                return Ok(ExitCode::SUCCESS);
            }
            let compromised = v.claim.reason == "compromised";
            c.retire(&v.old_sign, &v.claim.at, compromised, Some(v.new_sign.clone()));
            c.keys.insert(v.new_sign.clone(), name.clone());
            match &v.new_box {
                Some(b) => {
                    c.box_keys.insert(v.new_sign.clone(), b.clone());
                }
                None => println!("note: the new key has no encryption half; you cannot seal to it"),
            }
            c.save()?;
            println!("\n{name} moved onto the new key.");
            println!("  their old bundles stay verifiable, marked as signed with a retired key");
            println!("  anything NEW signed with the old key is now rejected");
        }
        Cmd::Retire { name, compromised, all } => {
            let mut c = trust::Contacts::load();
            if all && !compromised {
                return Err("--all only makes sense with --compromised: it condemns \
                            keys, and an ordinary retirement condemns nothing"
                    .into());
            }
            // A name with nothing live is still worth condemning: you learn
            // the machine was owned a week after you already retired the key,
            // and there has to be a way to act on that without editing JSON.
            if c.key_for_name(&name).is_none() && all && !c.retired_keys_for(&name).is_empty() {
                let keys: Vec<String> =
                    c.retired_keys_for(&name).iter().map(|(k, _)| k.clone()).collect();
                c.mark_history_compromised(&name, &keys);
                c.save()?;
                println!("{name} has no key in service; condemned {} retired key(s)", keys.len());
                println!("  everything they ever signed now reads as rejected");
                return Ok(ExitCode::SUCCESS);
            }
            let Some(key) = c.key_for_name(&name) else {
                return Err(format!("no contact named {name}").into());
            };
            let earlier: Vec<String> = c
                .retired_keys_for(&name)
                .iter()
                .filter(|(_, r)| !r.compromised)
                .map(|(k, _)| k.clone())
                .collect();
            c.retire(&key, &bundle::now_rfc3339(), compromised, None);
            if all {
                c.mark_history_compromised(&name, &earlier);
            }
            c.save()?;
            println!("retired {name}'s key");
            if compromised {
                println!("  marked COMPROMISED: every bundle it signed is now rejected,");
                println!("  old ones included, because a thief chooses the date too");
            } else {
                println!("  bundles it signed BEFORE now stay attributable; newer ones are rejected");
            }
            // Said out loud rather than left to be discovered. Someone who
            // runs this believing it covers everything from that person, when
            // it covers one key, has a false sense of what they just did.
            if !earlier.is_empty() {
                if all {
                    println!(
                        "  and {} earlier key(s) you held for {name} are condemned too",
                        earlier.len()
                    );
                } else {
                    println!(
                        "\n  NOTE: {} earlier key(s) you held for {name} are untouched, so",
                        earlier.len()
                    );
                    println!("  bundles signed with those still read as attributable. A stolen key");
                    println!("  is not evidence its predecessor was stolen -- but if you think it");
                    println!("  was, re-run with --compromised --all.");
                }
            }
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
            // Adding an existing name under a DIFFERENT key used to just
            // overwrite it, which is key rotation performed by accident and
            // with no record: every bundle the old key signed turned into
            // SENDER UNVERIFIABLE, and a stranger's key could take over a
            // trusted name in one command. `keychange` is the operation that
            // does this with evidence; `retire` is the one that does it
            // deliberately without.
            if let Some(existing) = c.key_for_name(&name) {
                if existing != sign {
                    return Err(format!(
                        "{name} is already on your list under a different key. This would \
                         replace it and orphan everything that key signed.\n  \
                         If they rotated: ctx keychange <their notice file> --accept\n  \
                         If you are doing it by hand: ctx retire {name}, then add them \
                         again under a name you choose"
                    )
                    .into());
                }
            }
            if let Some(r) = c.retired_record(&sign) {
                if r.compromised {
                    return Err(format!(
                        "that key is recorded as COMPROMISED (retired {}). Re-adding it \
                         undoes that decision; if it really is safe again, edit \
                         contacts.json deliberately.",
                        r.retired_at
                    )
                    .into());
                }
                println!(
                    "note: you retired this key on {} -- re-adding it puts it back in service",
                    r.retired_at
                );
                let k = sign.clone();
                c.retired.remove(&k);
            }
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
                return Err(match c.retired_by_name(&to) {
                    Some((_, r)) => format!(
                        "{to}'s key was retired on {}{}. Sealing to a retired key would \
                         send mail only its old holder can open; get their current \
                         `ctx whoami` token and add it first.",
                        r.retired_at,
                        if r.compromised { " as compromised" } else { "" }
                    ),
                    None => format!("no contact named {to}; ctx add {to} <key>"),
                }
                .into());
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
            allow_secrets, reply_to, r#type, allow_findings, agent, model,
        } => {
            send_bundle(SendArgs {
                to, subject, out, file, prompt, decision, memory, dir,
                allow_secrets, reply_to, msg_type: r#type, allow_findings, agent, model,
            })?;
        }
        Cmd::Reply {
            id, text, file, prompt, decision, memory, dir, r#type, subject,
            allow_secrets, allow_findings, agent, model, out,
        } => {
            let t = resolve_reply(&id)?;
            // --text is written to a file rather than handled specially, so a
            // typed reply goes through the same collection and the same
            // outbound scan as everything else. A secret pasted into a reply
            // is caught exactly like a secret in a file.
            let tmp = identity::home().join(format!("tmp-reply-{}", std::process::id()));
            let mut decision = decision;
            if let Some(body) = &text {
                std::fs::create_dir_all(&tmp)?;
                let f = tmp.join("reply.md");
                let mut body = body.clone();
                if !body.ends_with('\n') {
                    body.push('\n');
                }
                std::fs::write(&f, body)?;
                decision.push(f);
            }
            let has_items = !file.is_empty()
                || !prompt.is_empty()
                || !decision.is_empty()
                || !memory.is_empty()
                || !dir.is_empty();
            if !has_items {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err("nothing to reply with: pass --text \"...\" or a file".into());
            }
            println!("replying to {} ({})", t.parent, t.to);
            let r = send_bundle(SendArgs {
                to: vec![t.to.clone()],
                subject: subject.unwrap_or(t.subject),
                out,
                file, prompt, decision, memory, dir,
                allow_secrets,
                reply_to: Some(t.parent),
                msg_type: r#type.unwrap_or(t.msg_type),
                allow_findings,
                agent, model,
            });
            let _ = std::fs::remove_dir_all(&tmp);
            r?;
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
            // Read state is set by rendering, not by listing: having seen a
            // subject line in an inbox is not having read the thing.
            state::LocalState::load().mark_read(&l.manifest.id)?;
            // Non-zero when the content could not be attributed, so a script
            // or agent harness can branch on it instead of parsing prose.
            // `Revoked` is in here and `Retired` is not. A retired key with
            // a bundle that predates its retirement is attributable, so a
            // harness should carry on; a revoked one is not, so it should
            // stop, exactly as it does for a bad signature.
            if !l.tampered.is_empty()
                || matches!(l.trust, trust::Trust::Unverified | trust::Trust::Revoked)
            {
                return Ok(ExitCode::from(2));
            }
        }
        Cmd::Route { handle, home } => {
            let mut r = routes::Routes::load();
            r.local.insert(handle.clone(), home.display().to_string());
            r.save()?;
            println!("{handle} -> {}", home.display());
        }
        Cmd::Inbox { json, all, unread } => {
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
                let st = state::LocalState::load();
                let pending: Vec<_> = pending
                    .into_iter()
                    .filter(|(_, l)| !unread || !st.is_read(&l.manifest.id))
                    .collect();
                if pending.is_empty() {
                    println!("nothing pending");
                }
                for (_, l) in &pending {
                    let m = &l.manifest;
                    let who = contacts
                        .name_for(&m.from.key)
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| format!("\"{}\" (unlisted key)", m.from.handle));
                    let mut tags = Vec::new();
                    if m.prompt_count() > 0 {
                        tags.push(format!("{} prompt", m.prompt_count()));
                    }
                    if m.memory_count() > 0 {
                        tags.push(format!("{} MEMORY", m.memory_count()));
                    }
                    let tag = if tags.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", tags.join(", "))
                    };
                    let mark = if st.is_read(&m.id) { " " } else { "*" };
                    println!(
                        "{mark} {}  {:<14} from {}  {}{}",
                        m.id,
                        m.msg_type.label(),
                        who,
                        m.subject,
                        tag
                    );
                    if m.msg_type.expects_reply() {
                        println!("      -> expects a reply");
                    }
                    println!("      {}", l.trust.label());
                    if !l.tampered.is_empty() {
                        println!("      TAMPERED: {}", l.tampered.join(", "));
                    }
                }
                if !pending.is_empty() {
                    println!("\n* = unread.  ctx accept <id> to stage it, ctx reject <id> to drop it unread");
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
        Cmd::Push { dir, to, yes } => {
            let addr = remote::relay_addr().ok_or("no relay set; ctx join <addr> first")?;
            // The human gate on the way OUT, and it belongs HERE rather than
            // on `send`: `send` either delivers to a local route or writes a
            // directory you still have to move, so nothing has left the
            // machine yet. `push` is the moment it does. An earlier version
            // gated `send` and broke every send to an unrouted handle,
            // because "has no local route" is not the same as "is leaving".
            let loaded = bundle::load(&dir)?;
            if !yes {
                println!("about to send OFF THIS MACHINE, via {addr}:");
                println!("  to      : {to}");
                println!("  subject : {}", loaded.manifest.subject);
                println!("  bundle  : {}", loaded.manifest.id);
                for it in &loaded.manifest.items {
                    println!(
                        "  {:?}  {}  ({} bytes)",
                        it.kind,
                        it.path.strip_prefix("items/").unwrap_or(&it.path),
                        it.bytes
                    );
                }
                return Err("not sent. Re-run with --yes once you have read the list above.".into());
            }
            let c = trust::Contacts::load();
            let sign = match c.key_for_name(&to) {
                Some(k) => k,
                None => {
                    return Err(match c.retired_by_name(&to) {
                        Some((_, r)) => format!(
                            "{to}'s key was retired on {}; add their current key before \
                             pushing to them",
                            r.retired_at
                        ),
                        None => format!("no contact named {to}"),
                    }
                    .into())
                }
            };
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
            pull_once(keep)?;
        }
        Cmd::Threads { mine } => {
            let st = state::LocalState::load();
            let me = identity::Identity::load().map(|i| i.public_b64()).unwrap_or_default();
            let contacts = trust::Contacts::load();
            let ts = state::threads(all_manifests(), &st, &me);
            let shown: Vec<_> = ts
                .iter()
                .filter(|t| !mine || t.state == state::ThreadState::AwaitingYou)
                .collect();
            if shown.is_empty() {
                println!("no threads");
            }
            for t in shown {
                let who: Vec<String> = {
                    let mut v: Vec<String> = t
                        .messages
                        .iter()
                        .map(|m| {
                            if m.from.key == me {
                                "you".to_string()
                            } else {
                                contacts
                                    .name_for(&m.from.key)
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| format!("\"{}\"", m.from.handle))
                            }
                        })
                        .collect();
                    v.sort();
                    v.dedup();
                    v
                };
                let unread = if t.unread > 0 {
                    format!(", {} unread", t.unread)
                } else {
                    String::new()
                };
                println!(
                    "{}  {}  [{}]",
                    t.id,
                    t.subject,
                    t.state.label()
                );
                println!(
                    "      {} message(s){}  between {}",
                    t.messages.len(),
                    unread,
                    who.join(", ")
                );
            }
        }
        Cmd::Thread { id } => {
            let st = state::LocalState::load();
            let me = identity::Identity::load().map(|i| i.public_b64()).unwrap_or_default();
            let contacts = trust::Contacts::load();
            let ts = state::threads(all_manifests(), &st, &me);
            let Some(t) = ts.iter().find(|t| t.id == id || t.id.starts_with(&id)) else {
                return Err(format!("no thread {id}").into());
            };
            println!("{}  [{}]\n", t.subject, t.state.label());
            for m in &t.messages {
                let who = if m.from.key == me {
                    "you".to_string()
                } else {
                    contacts
                        .name_for(&m.from.key)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("\"{}\" (unlisted)", m.from.handle))
                };
                // Your own message is never unread to you. The count already
                // excluded them; the marker did not, so every thread you
                // started showed your own words as something to catch up on.
                let mine_msg = m.from.key == me;
                let mark = if mine_msg || st.is_read(&m.id) { " " } else { "*" };
                println!("{mark} {}  {:<14} {}  {}", m.created, m.msg_type.label(), who, m.id);
                for it in &m.items {
                    println!("      {:?}  {}", it.kind, it.path.strip_prefix("items/").unwrap_or(&it.path));
                }
            }
            println!("\nctx open <path> to read one, ctx reply {} --text \"...\" to answer", t.id);
        }
        Cmd::Close { thread } => {
            let mut st = state::LocalState::load();
            st.close(&thread)?;
            println!("thread {thread} marked closed locally");
            println!("  (your view only -- the other side decides their own)");
        }
        Cmd::Watch { every, once, quiet } => {
            // The interval is a trade: shorter means you hear sooner, and it
            // also tells the relay operator more precisely when you are
            // active, since fetch timing is metadata they can see. Two
            // minutes is slow enough not to be a presence feed.
            let every = every.max(10);
            loop {
                // Pull before counting, so arrivals are collected and then
                // announced once, rather than announced and collected later.
                if remote::relay_addr().is_some() {
                    if let Err(e) = pull_inner(false, true) {
                        eprintln!("ctx watch: pull failed: {e}");
                    }
                }
                let arrivals = notify::new_arrivals();
                if !arrivals.is_empty() {
                    let (title, body) = notify::summarise(&arrivals);
                    let urgent = arrivals.iter().any(|a| a.expects_reply);
                    if quiet || !notify::desktop(&title, &body, urgent) {
                        println!("{title}\n{body}");
                    }
                    let ids: Vec<String> = arrivals.iter().map(|a| a.id.clone()).collect();
                    notify::mark_announced(&ids);
                } else if once {
                    println!("nothing new");
                }
                if once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(every));
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
