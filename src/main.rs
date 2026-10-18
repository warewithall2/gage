//! ctx -- hand context between agents, with a trust boundary.
//!
//! Transport-agnostic on purpose. A bundle is a directory, so it moves over
//! anything you already have: a shared folder for two agents on one machine,
//! git, email, a file drop. No server is required, and none is included,
//! because agents are invoked rather than online -- presence is the part of
//! the instant-messenger model that does not transfer.

mod authority;
mod autoaccept;
mod journal;
mod lan;
mod words;
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
#[command(
    name = "ctx",
    about = "Hand context between agents, with provenance",
    // The version carries the build's commit, because "which ctx is this"
    // is the first question when two machines disagree -- and with the
    // journal freezing verdicts, "a ctx upgrade changed what a verdict
    // means" is an explanation an auditor has to be able to rule out.
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CTX_BUILD_REV"), ")")
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your identity keypair. With no name, it is named after its own
    /// key -- two words nobody chose, like LocalSend's device names except
    /// that they are derived rather than picked.
    Init { handle: Option<String> },
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
    /// Refuse a key, so it stops being offered as a new connection. The
    /// opposite of `add`, and the third state: a list can say yes and an
    /// absence says "not asked yet", but neither can say no. A declined key's
    /// bundles still arrive -- nothing can stop delivery -- and still sit
    /// behind the accept gate; what changes is that the frame and the viewer
    /// say you already refused it rather than offering the decision again
    Decline { key: String },
    /// Take back a decline, without adding the key
    Undecline { key: String },
    /// Say a key out loud: the four word-pairs to confirm when pairing
    Fingerprint {
        /// A contact's name, or nothing for your own key
        name: Option<String>,
    },
    /// Show what your authority file pre-authorises. Prints only -- there is
    /// deliberately no command that WRITES a grant, because an agent that
    /// can be talked into running a command could be talked into granting
    /// itself the authority to obey whatever talked it into it. Edit the
    /// file yourself.
    Authority,
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
        /// Hand it straight to a machine on this network once it is built,
        /// so sending is one command rather than a build and then a push.
        /// --to may be a word-pair from the `ctx lan` list.
        #[arg(long)] lan: bool,
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
        /// megabytes one mailbox may hold before it stops accepting
        #[arg(long, default_value = "64")] max_mailbox_mb: u64,
        /// envelopes one mailbox may hold -- a thousand small ones flood as
        /// well as one big one, and cost the recipient more
        #[arg(long, default_value = "500")] max_mailbox_msgs: usize,
        /// megabytes the whole store may hold
        #[arg(long, default_value = "4096")] max_store_mb: u64,
        /// requests per minute from one address
        #[arg(long, default_value = "120")] rate_per_min: u32,
    },
    /// Point this identity at a relay and register your mailbox
    Join { addr: String },
    /// Push a sealed envelope to the relay for a contact
    Push {
        dir: PathBuf,
        #[arg(long)] to: String,
        /// Hand it to them over this network instead of the relay. Finds
        /// their address by a signed query, which only they can answer.
        #[arg(long)] lan: bool,
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
        /// Run this command when an arrival is covered by a grant in your
        /// authority file. It is given CTX_BUNDLE_ID, CTX_FROM, CTX_FROM_KEY,
        /// CTX_TYPE, CTX_SUBJECT, CTX_EXPECTS_REPLY and CTX_GRANT in its
        /// environment -- never the bundle's contents, and it does not accept
        /// the bundle. Arrivals with no grant notify as usual and run nothing
        #[arg(long)] on_arrival: Option<String>,
        /// seconds before a hook that has not finished is killed
        #[arg(long, default_value = "300")] hook_timeout: u64,
        /// Accept arrivals that a grant says may be accepted unattended,
        /// within that grant's max-exchanges for the thread. Only grants
        /// written `auto-accept` qualify, and only replies to something this
        /// machine sent. Every such acceptance records which grant allowed
        /// it. Acceptance moves the bundle; it never opens or runs anything
        #[arg(long)] auto_accept: bool,
    },
    /// What this machine did with what arrived: one line per event
    Journal {
        /// only this bundle
        #[arg(long)] bundle: Option<String>,
        /// the raw JSONL, for a tool rather than a person
        #[arg(long)] json: bool,
        /// how many of the most recent entries to show
        #[arg(long, default_value = "40")] last: usize,
        /// Walk the hash chain and report every break. A clean pass means no
        /// line has been changed, removed or reordered since chaining began
        /// -- unless whoever did it also recomputed every following link,
        /// which anything running as you can do. Evidence against a script
        /// quietly dropping the line that incriminates it; not proof against
        /// a determined local process
        #[arg(long)] verify: bool,
    },
    /// Serve the local viewer on 127.0.0.1
    Ui {
        #[arg(long, default_value = "7777")] port: u16,
    },
    /// Be on this network: visible, discoverable and reachable, for exactly
    /// as long as this runs. The whole of it in one command -- start it on
    /// both machines and they can see and send to each other. Stop it and
    /// this machine is silent again.
    Lan {
        #[arg(long, default_value_t = lan::LISTEN_PORT)] port: u16,
    },
    /// Who is announcing themselves on this network, right now
    Nearby {
        /// Also announce YOURSELF, for this many seconds. Off by default:
        /// ctx has never had presence, and a laptop broadcasting its handle
        /// and public key onto every network it joins would change that
        /// quietly. This is the pairing mode, and it stops on its own.
        #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "60")]
        announce: Option<u64>,
        /// How long to listen
        #[arg(long, default_value = "10")] r#for: u64,
    },
    /// Confirm a nearby machine's fingerprint out of band, then add its key.
    /// Not needed to send -- an unpaired machine's bundle arrives as SENDER
    /// NOT ON YOUR LIST, behind the same accept gate as everything else.
    /// This is what turns "some machine on this wifi" into "the key I
    /// checked", which is what a grant should require before an agent acts
    /// on a message unattended.
    Pair {
        /// What to call them on YOUR list
        name: String,
        /// Which machine, by the word-pair `ctx lan` shows. Only needed when
        /// more than one unpaired machine is on the network.
        r#as: Option<String>,
        /// The four word-pairs the other machine shows. Given here, they are
        /// compared for you and the pairing fails on any difference -- which
        /// is stricter than a person squinting at a y/n prompt. Omit it to
        /// be shown the words and asked.
        #[arg(long)] confirm: Option<String>,
        #[arg(long, default_value = "20")] r#for: u64,
    },
    /// Be reachable on this network: answer address queries from keys on your
    /// list, and accept a sealed bundle straight from them. No announcing.
    Listen {
        #[arg(long, default_value = "0.0.0.0")] bind: String,
        #[arg(long, default_value_t = lan::LISTEN_PORT)] port: u16,
    },
    /// Re-sign a bundle for someone else, appending to its chain
    Forward {
        dir: PathBuf,
        #[arg(long)] to: Vec<String>,
        #[arg(long)] out: PathBuf,
    },
}

/// Observe the inbox, and say so loudly if it could not be done.
///
/// Every caller is about to print a trust verdict, and the verdict depends on
/// this having run. Swallowing the error would silently downgrade a rejected
/// bundle to "no record either way", which is the milder label.
fn observe_or_warn() {
    if let Err(e) = routes::observe_inbox() {
        eprintln!(
            "ctx: WARNING -- could not record what is in your inbox ({e}). A retired-key \
             verdict below may read as ARRIVAL UNRECORDED when it should be a rejection. \
             Re-run once no other ctx process is writing."
        );
    }
}

/// Both legs of registration: claim a mailbox, then prove it by opening a
/// nonce the relay sealed to it.
///
/// Naming a box key proves nothing -- it is in every `ctx whoami` line -- so
/// a relay that took the claim at face value could have its mailboxes squatted
/// by anyone who had seen one.
fn register_with_proof(
    addr: &str,
    id: &identity::Identity,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = remote::post(addr, "/register", body)?;
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();
    // An older relay, or one that already knows this pair, asks for nothing.
    let Some(sealed) = v.get("prove").and_then(|p| p.as_str()) else {
        return Ok(());
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let ct = B64
        .decode(sealed.trim())
        .map_err(|e| format!("relay sent an unreadable registration challenge: {e}"))?;
    let nonce = id
        .unseal(&ct)
        .map_err(|e| format!("could not open the relay's registration challenge: {e}"))?;
    let again = serde_json::json!({
        "sign_key": id.public_b64(),
        "box_key": id.box_public_b64(),
        "proof": String::from_utf8_lossy(&nonce) })
        .to_string();
    remote::post(addr, "/register", &again)?;
    Ok(())
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
        // The id becomes a directory name, so its shape is checked before the
        // join. A signed manifest carrying `id: "../../../../tmp/ctx-pwn"`
        // would otherwise have written a bundle outside the inbox entirely.
        if !manifest::id_is_safe(&loaded.manifest.id) {
            eprintln!(
                "  refused: a bundle whose id is not an id ({:?}) -- it would have become \
                 a path",
                loaded.manifest.id.chars().take(40).collect::<String>()
            );
            let _ = std::fs::remove_dir_all(&tmp);
            continue;
        }
        // And a bundle that does not verify never enters the inbox from the
        // relay. Local delivery is written by the sender and cannot be gated
        // here, which is what the trust verdict on read is for -- but mail
        // the relay handed us is ours to refuse.
        if !loaded.tampered.is_empty() {
            eprintln!("  refused {}: {}", loaded.manifest.id, loaded.tampered.join(", "));
            let _ = std::fs::remove_dir_all(&tmp);
            continue;
        }
        let dest = pending.join(&loaded.manifest.id);
        if dest.exists() {
            println!("  already have {} -- left in place", loaded.manifest.id);
        } else {
            routes::deliver(&tmp, &dest)?;
            // Observe, then re-read the verdict. The line printed here used to
            // come from the load of the TEMPORARY directory, before the
            // delivered copy had been observed at all -- so a valid old-key
            // bundle pulled after a retirement printed ARRIVAL UNRECORDED
            // when observing it first would have placed it after the cut and
            // called it a rejection.
            observe_or_warn();
            let verdict = bundle::load(&dest)
                .map(|l| l.trust.label().to_string())
                .unwrap_or_else(|e| format!("could not be read back: {e}"));
            println!(
                "  {}  {}  ({}){}",
                loaded.manifest.id, loaded.manifest.subject, verdict, label
            );
            n += 1;
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
    // Witness the arrivals now, in the same run that collected them. Waiting
    // for the next listing would leave a window in which a retirement could
    // be recorded first, turning mail that really did arrive earlier into
    // ARRIVAL UNRECORDED.
    if n > 0 {
        let _ = routes::observe_inbox();
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
            let id = identity::Identity::create_named(handle.as_deref())?;
            println!("identity created in {}", identity::home().display());
            println!("handle : {}", id.handle);
            println!("key    : {}", id.public_b64());
            println!("\nGive the line above to anyone who should be able to send to you.");
        }
        Cmd::Whoami => {
            let id = identity::Identity::load()?;
            // Line one is unchanged on purpose: it is what scripts cut a key
            // out of, here and in the test suite.
            println!("{}\t{}", id.handle, id.full_key());
            // The words go to STDERR, so `whoami | cut -f2` still yields a
            // key and nothing else. Learned immediately: cut passes a line
            // with no delimiter through unchanged, so three extra stdout
            // lines turned every script that reads this command into one that
            // read a paragraph. Same reason the id note in `open` is on
            // stderr.
            eprintln!();
            eprintln!("  this key says : {}", words::fingerprint(&id.public_b64()));
            eprintln!("  shown as      : {}", words::label(&id.public_b64()));
            eprintln!();
            eprintln!("  Those words come from the key, so nobody picks their own.");
            eprintln!("  When you pair with another machine, both screens must show");
            eprintln!("  the same four pairs. The short label is only for telling");
            eprintln!("  devices apart in a list -- never confirm against it alone.");
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
                println!("  the notice IS countersigned by the old key, signed before those");
                println!("  secrets were destroyed. That proves possession, not authorship, so");
                println!("  your contacts still have to confirm this change with you directly --");
                println!("  but a notice with no countersignature at all proves even less.");
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
                match register_with_proof(&addr, &id, &body) {
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
        Cmd::Fingerprint { name } => {
            let (who, key) = match &name {
                None => {
                    let id = identity::Identity::load()?;
                    (id.handle.clone(), id.public_b64())
                }
                Some(n) => {
                    let c = trust::Contacts::load();
                    match c.key_for_name(n) {
                        Some(k) => (n.clone(), k),
                        None => match c.retired_by_name(n) {
                            Some((k, r)) => {
                                println!("note: {n} is a key you retired on {}", r.retired_at);
                                (n.clone(), k.to_string())
                            }
                            None => return Err(format!("no contact named {n}").into()),
                        },
                    }
                }
            };
            // One line on stdout, and the short form on stderr. The same
            // shape as `whoami`, for the same reason: `ctx fingerprint x |
            // cut -f2` is the obvious thing to write, and `cut` passes a
            // second line straight through, so two lines here turn one value
            // into two. Found by writing exactly that in the LAN test.
            println!("{who}\t{}", words::fingerprint(&key));
            eprintln!("{who}\t{}\t(the label only -- never confirm against this)", words::label(&key));
        }
        Cmd::Authority => {
            let a = authority::Authority::load();
            let p = authority::path();
            if !a.present {
                println!("no authority file at {}", p.display());
                println!("nothing is pre-authorised; every request gets reported to you");
            } else if let Some(e) = &a.error {
                println!("{}", e);
                println!("the file grants NOTHING while it does not parse, which is the safe direction");
            } else if a.grants.is_empty() {
                println!("{} is present and grants nothing", p.display());
            } else {
                println!("{}", p.display());
                for g in &a.grants {
                    let who = match &g.subject {
                        authority::Subject::Key(k) => format!("key {k}"),
                        authority::Subject::Name(n) => {
                            let c = trust::Contacts::load();
                            match c.key_for_name(n) {
                                Some(k) => format!("contact {n} (key {k})"),
                                // Worth saying out loud: the grant is inert
                                // rather than wrong, and the usual cause is
                                // a contact not added yet or renamed.
                                None => format!("contact {n} -- NO SUCH CONTACT, so this grants nothing"),
                            }
                        }
                    };
                    println!("  line {}\t{}\t{}", g.line, g, who);
                }
                println!();
                println!("a grant applies only to a SENDER VERIFIED bundle, and only to the");
                println!("kind of message it names -- never to what the contents ask for");
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
            // Never presented as reassurance. A valid countersignature proves
            // control of the old key and nothing about who is holding it.
            if v.old_signed {
                println!("  old key signed: yes -- this proves control of the old key, and");
                println!("                  nothing about WHO holds it. If that key was");
                println!("                  stolen, the thief can produce this signature too.");
            } else {
                println!("  old key signed: NO -- nothing here connects this notice to the");
                println!("                  party you already trusted.");
            }
            match &known {
                Some(name) => println!("  the old key is on your list as: {name}"),
                None => println!("  the old key is NOT on your list"),
            }
            if c.retired_record(&v.old_sign).is_some() && c.knows(&v.new_sign) {
                println!("\nalready applied; nothing to do");
                return Ok(ExitCode::SUCCESS);
            }
            // An accept that died between the retirement and the cut. The
            // retirement is saved, the old key is gone from `keys`, and the
            // new key was never inserted -- so `known` is None and the bail
            // below would fire with "you have never accepted the old key",
            // leaving the contact retired at sequence 0 for good. Every
            // bundle from the old key then reads rejected or unrecorded,
            // permanently, with no command that fixes it.
            //
            // The comment on the retire-first ordering claimed re-running
            // would relax it to the real cut. It would not, and both
            // reviewers said so. This is what makes that claim true.
            let resuming = match c.retired_record(&v.old_sign) {
                Some(r)
                    if !c.knows(&v.new_sign)
                        && r.retired_seq == 0
                        // Only resume the rotation this very notice began.
                        // Without this, any notice naming a retired key as
                        // its OLD key would be treated as a resumption and
                        // could finish with a different destination.
                        && r.replaced_by.as_deref() == Some(v.new_sign.as_str()) =>
                {
                    Some(r.name.clone())
                }
                _ => None,
            };
            if resuming.is_some() {
                println!("  an earlier accept of this notice did not finish: the key is");
                println!("  retired at observation 0, which rejects everything it signed.");
                println!("  re-running takes the real cut.");
            }
            let Some(name) = known.or(resuming.clone()) else {
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
            // The destination key is chosen by whoever wrote the notice, so
            // it gets the checks `ctx add` already applies to a key a person
            // typed -- and one more, because a person typing a key has
            // decided something and a notice has not.
            if let Some(r) = c.retired_record(&v.new_sign) {
                // Without this, `keys.insert` below puts a retired key back
                // into service while its retired record stays, and
                // `Contacts::verdict` tests `knows()` first -- so a bundle
                // that read SENDER KEY REJECTED with its contents withheld
                // reopens as SENDER VERIFIED, exit 0, contents shown. That is
                // revocation undone by a message.
                //
                // Refused here rather than fixed in `verdict`, which was the
                // other candidate: reordering `verdict` would stop this class
                // of reactivation but change what every verdict means, and
                // `ctx add` deliberately *removes* a non-compromised retired
                // record when a person re-adds a key by hand. So the
                // contradictory state should not exist at all, and this is
                // the only path that creates it.
                return Err(format!(
                    "NOT APPLIED: this notice rotates onto a key you RETIRED on {}{}. \
                     Applying it would put that key back in service while the \
                     retirement still stands, and bundles you had rejected would \
                     read as verified again. If you really mean to trust that key \
                     again, that is a decision to make by hand and in the open:\n  \
                     ctx add {name} {}",
                    r.retired_at,
                    if r.compromised { " as COMPROMISED" } else { "" },
                    v.claim.new_key
                )
                .into());
            }
            if let Some(other) = c.name_for(&v.new_sign) {
                if other != name {
                    // `keys.insert` overwrites by key, so the other contact
                    // simply vanished -- no message, and their bundles then
                    // opened under this contact's name with a NAME MISMATCH.
                    return Err(format!(
                        "NOT APPLIED: that new key is already on your list as {other}. \
                         Applying this would replace {other} with {name} on the same \
                         key and lose {other} entirely. Two contacts cannot share a \
                         signing key: confirm with both which of them holds it."
                    )
                    .into());
                }
            }
            let compromised = v.claim.reason == "compromised";
            // The cutoff is MY clock, at the moment I accept. Whoever wrote
            // the notice chose `at`, and adopting it let them set the
            // retirement anywhere they liked: far in the future and the old
            // key keeps working, far in the past and a stretch of real
            // history stops being attributable. Their date is kept as what it
            // is -- a claim.
            let now = bundle::now_rfc3339();
            // Collect before retiring, as one operation. Accepting a notice
            // closes the set of bundles that can ever be attributed to the old
            // key, so mail still sitting on the relay would be stranded by the
            // very act of accepting -- and the person doing it has no reason
            // to expect that. If the pull fails, nothing is retired: a partial
            // transaction here costs attribution permanently.
            if remote::relay_addr().is_some() {
                println!("collecting anything still on the relay before retiring the key...");
                pull_once(false).map_err(|e| -> Box<dyn std::error::Error> {
                    format!(
                        "not applied: could not collect from the relay first ({e}). \
                         Retiring now would strand any mail still waiting there, \
                         permanently unattributable. Fix the relay and re-run."
                    )
                    .into()
                })?;
            }
            // Everything in the inbox is witnessed, and the cut is taken
            // after that, so honest mail already here stays attributable
            // while anything arriving later does not.
            // Retire the key BEFORE taking the cut, with a cut of 0 so that
            // nothing at all is below it.
            //
            // The order matters and the first version had it backwards: the
            // cut was taken, then contacts were saved, and in between the old
            // key was still in `keys` -- so a concurrent read returned
            // SENDER VERIFIED for a bundle delivered after the retirement
            // decision. A crash in that window left the key trusted
            // indefinitely. Fail-open, immediately after a revocation
            // decision, which is the worst possible moment for it.
            //
            // Retiring first inverts that: during the window every bundle
            // from the old key reads as rejected or unrecorded, and a crash
            // leaves it over-strict rather than over-trusting. Re-running
            // keychange then relaxes it to the real cut.
            if resuming.is_none() {
                c.retire(&v.old_sign, &now, 0, compromised, Some(v.new_sign.clone()));
                if let Some(r) = c.retired.get_mut(&v.old_sign) {
                    r.claimed_at = Some(v.claim.at.clone());
                }
                c.save()?;
            }
            let seq = state::LocalState::observe_and_cut(routes::scan_inbox_knowing)?;
            if let Some(r) = c.retired.get_mut(&v.old_sign) {
                r.retired_seq = seq;
            }
            c.keys.insert(v.new_sign.clone(), name.clone());
            match &v.new_box {
                Some(b) => {
                    c.box_keys.insert(v.new_sign.clone(), b.clone());
                }
                None => println!("note: the new key has no encryption half; you cannot seal to it"),
            }
            c.save()?;
            println!("\n{name} moved onto the new key.");
            println!("  cutoff recorded at {now}, observation {seq} (this machine's own");
            println!("  record). They state they rotated at {} -- that is their", v.claim.at);
            println!("  claim, and it is not what the verdict uses.");
            // Said because the consequence is surprising: the same bundle can
            // read as attributable on one machine and not on another.
            println!("  this is recorded for THIS ctx home only. Another machine sharing");
            println!("  your identity has its own record and needs its own keychange,");
            println!("  and until then the old key is still live over there.");
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
            // Fail-closed first, then the real cut. See the comment in
            // keychange: a window in which the key is still trusted is a
            // window opened by the act of revoking it.
            let now = bundle::now_rfc3339();
            c.retire(&key, &now, 0, compromised, None);
            if all {
                c.mark_history_compromised(&name, &earlier);
            }
            c.save()?;
            let seq = state::LocalState::observe_and_cut(routes::scan_inbox_knowing)?;
            if let Some(r) = c.retired.get_mut(&key) {
                r.retired_seq = seq;
            }
            c.save()?;
            println!("retired {name}'s key");
            if compromised {
                println!("  marked COMPROMISED: every bundle it signed is now rejected,");
                println!("  old ones included, because a thief signs as well as the owner");
            } else {
                println!("  bundles this machine had already seen stay attributable; anything");
                println!("  arriving later is rejected, and a bundle with no record either way");
                println!("  reads as ARRIVAL UNRECORDED rather than as an accusation");
            }
            println!("  recorded for THIS ctx home only -- another machine on the same");
            println!("  identity keeps its own record");
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
            for l in trust::add_contact(&name, &key)? {
                println!("{l}");
            }
        }
        Cmd::Decline { key } => {
            let (sign, _) = identity::split_key(&key);
            let mut c = trust::Contacts::load();
            let seq = state::LocalState::load().seq;
            match c.decline(&sign, seq)? {
                true => {
                    c.save()?;
                    println!("declined {}", words::label(&sign));
                    println!("  {sign}");
                    println!("  its bundles still arrive and still need accepting; what");
                    println!("  changes is that you are not offered this decision again.");
                    println!("  ctx undecline <key> takes it back.");
                }
                false => println!("already declined"),
            }
        }
        Cmd::Undecline { key } => {
            let (sign, _) = identity::split_key(&key);
            let mut c = trust::Contacts::load();
            match c.declined.remove(&sign) {
                Some(d) => {
                    c.save()?;
                    println!("undeclined {} (was declined {})", words::label(&sign), d.at);
                    println!("  it is NOT on your list. ctx add <name> <key> does that.");
                }
                None => println!("that key is not declined"),
            }
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
            allow_secrets, reply_to, r#type, allow_findings, lan, agent, model,
        } => {
            let targets = to.clone();
            let m = send_bundle(SendArgs {
                to, subject, out, file, prompt, decision, memory, dir,
                allow_secrets, reply_to, msg_type: r#type, allow_findings, lan, agent, model,
            })?;
            if lan {
                // Pushed from our own kept copy rather than the staging dir,
                // which is the same bytes and is still there after the build.
                let from = routes::sent_dir(&identity::home()).join(&m.id);
                for who in &targets {
                    for l in lan::hand_over(&from, who)? {
                        println!("{l}");
                    }
                }
            }
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
                lan: false,
                agent, model,
            });
            let _ = std::fs::remove_dir_all(&tmp);
            r?;
        }
        Cmd::Inspect { dir } => {
            // Without this, inspecting a post-retirement arrival before any
            // other command had looked reported ARRIVAL UNRECORDED instead of
            // recording the arrival and rejecting it: a downgrade.
            observe_or_warn();
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
            // `ctx open <id>` is what the other commands' output invites, so
            // resolve an id to its bundle rather than failing on a path that
            // was never meant to be one.
            let dir = match dir.to_str() {
                Some(s) if !dir.exists() && manifest::id_is_safe(s) => {
                    match routes::find_by_id(&identity::home(), s) {
                        Some(p) => {
                            eprintln!("ctx: {s} -> {}", p.display());
                            p
                        }
                        None => {
                            return Err(format!(
                                "no bundle {s} in this ctx home. `ctx inbox` lists what is here"
                            )
                            .into())
                        }
                    }
                }
                _ => dir,
            };
            // A bundle you only ever `ctx open` would otherwise never be
            // witnessed, and would read as ARRIVAL UNRECORDED after a
            // rotation even though it was sitting in your inbox the whole
            // time.
            //
            // And here it is fatal rather than a warning. `open` is the one
            // command that exists to render a trust verdict, and a verdict
            // computed from state that could not be refreshed can be milder
            // than the truth -- "no record either way" in place of a
            // rejection. Refusing to print is the only safe failure.
            routes::observe_inbox().map_err(|e| -> Box<dyn std::error::Error> {
                format!(
                    "refusing to render a trust verdict: could not record what is in your \
                     inbox ({e}). The verdict would be computed from stale state and could \
                     read milder than the truth. Re-run once no other ctx process is \
                     writing."
                )
                .into()
            })?;
            let l = bundle::load(&dir)?;
            print!("{}", open::render(&l, reveal).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?);
            // Read state is set by rendering, not by listing: having seen a
            // subject line in an inbox is not having read the thing. It is
            // also bookkeeping, and bookkeeping must not turn a successful
            // read into a failure after the content has already been printed.
            if let Err(e) = state::LocalState::load().mark_read(&l.manifest.id) {
                eprintln!("ctx: could not record this as read: {e}");
            }
            // Opening is the event that matters most to an auditor, because
            // it is the moment the contents entered an agent's context. Same
            // rule as above: bookkeeping must not turn a successful read into
            // a failure after the content has already been printed.
            if let Err(e) = journal::record(journal::Event::Opened, &l.dir) {
                eprintln!("ctx: could not journal this read: {e}");
            }
            // Non-zero when the content could not be attributed, so a script
            // or agent harness can branch on it instead of parsing prose.
            // `Revoked` is in here and `Retired` is not. A retired key with
            // a bundle that predates its retirement is attributable, so a
            // harness should carry on; a revoked one is not, so it should
            // stop, exactly as it does for a bad signature.
            if !l.tampered.is_empty()
                || matches!(
                    l.trust,
                    trust::Trust::Unverified | trust::Trust::Revoked | trust::Trust::Unwitnessed
                )
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
            observe_or_warn();
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
            routes::restage(&from, &dest)?;
            // After the move, against the new location, and never fatal: a
            // machine that would not accept a bundle because it could not
            // write a log line has turned an audit feature into an outage.
            if let Err(e) = journal::record(journal::Event::Accepted, &dest) {
                eprintln!("ctx: could not journal this acceptance: {e}");
            }
            println!("accepted {id}");
            println!("  ctx open {}", dest.display());
        }
        Cmd::Reject { id } => {
            let p = routes::pending_dir(&identity::home()).join(&id);
            if !p.is_dir() {
                return Err(format!("no pending bundle {id}").into());
            }
            // Before the delete, because the manifest is what the entry is
            // built from and in a moment there will not be one. This is the
            // event that most needs recording: a rejection destroys the
            // bundle, so without a line here the only trace that it ever
            // existed is gone, and deletion becomes indistinguishable from
            // never having arrived.
            if let Err(e) = journal::record(journal::Event::Rejected, &p) {
                eprintln!("ctx: could not journal this rejection: {e}");
            }
            std::fs::remove_dir_all(&p)?;
            println!("rejected {id}, deleted unread");
        }
        Cmd::Relay { bind, store, max_mailbox_mb, max_mailbox_msgs, max_store_mb, rate_per_min } => {
            let root = store.unwrap_or_else(|| identity::home().join("relaystore"));
            // Said once, loudly, because the difference between a tailnet
            // relay and a public one is the whole of its threat model and
            // the bind address is where that decision is actually made.
            if !bind.starts_with("127.") && !bind.starts_with("100.") && !bind.starts_with("[::1]")
            {
                eprintln!(
                    "ctx relay: binding {bind}, which may be reachable beyond your own \
                     network.\n  Anyone who can reach it may push to any REGISTERED \
                     mailbox -- that is deliberate, so a stranger can send you a first \
                     message -- within the limits below. It still cannot read anything."
                );
            }
            relay::serve_with(
                &bind,
                root,
                relay::Limits {
                    mailbox_bytes: max_mailbox_mb * 1024 * 1024,
                    mailbox_msgs: max_mailbox_msgs,
                    store_bytes: max_store_mb * 1024 * 1024,
                    per_min: rate_per_min,
                },
            )?;
        }
        Cmd::Join { addr } => {
            let id = identity::Identity::load()?;
            let body = serde_json::json!({
                "sign_key": id.public_b64(), "box_key": id.box_public_b64() })
                .to_string();
            register_with_proof(&addr, &id, &body)?;
            remote::set_relay(&addr)?;
            println!("registered with {addr} and saved it as your relay");
            println!("  proved the mailbox is yours by opening a sealed nonce, so nobody");
            println!("  can claim it by quoting your public key");
            println!("  the relay holds sealed envelopes; it cannot read them");
        }
        Cmd::Push { dir, to, yes, lan } => {
            let addr = if lan {
                "this network".to_string()
            } else {
                remote::relay_addr().ok_or("no relay set; ctx join <addr> first")?
            };
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
            if lan {
                for l in lan::hand_over(&dir, &to)? {
                    println!("{l}");
                }
                return Ok(ExitCode::SUCCESS);
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
                let flag = if t.others.len() > 1 {
                    format!("  !! {} correspondents", t.others.len())
                } else if !t.unverified.is_empty() {
                    "  !! unverified thread claim".to_string()
                } else {
                    String::new()
                };
                println!(
                    "{}  {}  [{}]{flag}",
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
            // A message id is what every other command hands you, so accept
            // one here rather than rejecting it: `ctx threads` prints the
            // thread id, but nothing else does, and "no thread <id>" for an
            // id the tool can plainly resolve is a dead end. Dogfood, 15 Oct.
            let found = ts
                .iter()
                .find(|t| t.id == id || t.id.starts_with(&id))
                .or_else(|| ts.iter().find(|t| t.messages.iter().any(|m| m.id == id)));
            let Some(t) = found else {
                return Err(format!(
                    "no thread or message {id}. `ctx threads` lists what is here"
                )
                .into());
            };
            println!("{}  [{}]\n", t.subject, t.state.label());
            // Said before the messages, because it changes how they should be
            // read. A thread with two correspondents is either a group or
            // somebody posting into a conversation they were not part of, and
            // the reader is the only one who can tell which.
            if t.others.len() > 1 {
                let who: Vec<String> = t
                    .others
                    .iter()
                    .map(|k| match contacts.name_any(k) {
                        Some(n) => n.to_string(),
                        None => format!("unlisted {}…", k.chars().take(10).collect::<String>()),
                    })
                    .collect();
                println!("!! {} correspondents here: {}", t.others.len(), who.join(", "));
                println!("   a reply must name a message, not this thread\n");
            }
            if !t.unverified.is_empty() {
                println!(
                    "!! {} message(s) claim this thread while answering something you do",
                    t.unverified.len()
                );
                println!("   not hold: {}\n", t.unverified.join(", "));
            }
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
                let claim = if t.unverified.contains(&m.id) { "  [thread claim unverified]" } else { "" };
                println!("{mark} {}  {:<14} {}  {}{claim}", m.created, m.msg_type.label(), who, m.id);
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
        Cmd::Watch { every, once, quiet, on_arrival, hook_timeout, auto_accept } => {
            // The interval is a trade: shorter means you hear sooner, and it
            // also tells the relay operator more precisely when you are
            // active, since fetch timing is metadata they can see. Two
            // minutes is slow enough not to be a presence feed.
            let every = every.max(10);
            // Latched for the life of the process, not reset each poll: a
            // journal that cannot be written is not a transient condition to
            // retry against, and retrying is what would make it unbounded.
            let mut journal_broken = false;
            loop {
                // Pull before counting, so arrivals are collected and then
                // announced once, rather than announced and collected later.
                if remote::relay_addr().is_some() {
                    if let Err(e) = pull_inner(false, true) {
                        eprintln!("ctx watch: pull failed: {e}");
                    }
                }
                // Date the arrivals before anything acts on them. Without
                // this, a watcher that auto-accepts wrote an `accepted`
                // entry with no `observed` entry before it -- the unattended
                // path, which is the one the journal exists for, was the one
                // leaving the thinnest record. `ctx inbox` has always done
                // this; `watch` never did, because until now it only looked.
                if let Err(e) = routes::observe_inbox() {
                    eprintln!("ctx watch: could not record arrivals: {e}");
                }
                let arrivals = notify::new_arrivals();
                if !arrivals.is_empty() {
                    let (title, body) = notify::summarise(&arrivals);
                    let urgent = arrivals.iter().any(|a| a.expects_reply);
                    if quiet || !notify::desktop(&title, &body, urgent) {
                        println!("{title}\n{body}");
                    }
                    // Announced first, then hooks. A hook that crashes the
                    // watcher must not leave the arrival un-announced, or the
                    // next run re-fires it against the same broken command.
                    let ids: Vec<String> = arrivals.iter().map(|a| a.id.clone()).collect();
                    notify::mark_announced(&ids);
                    // Before the hook, and after the announcement. After,
                    // because a human hears about an unattended acceptance
                    // either way; before, because a hook written for an
                    // unattended loop wants to find the bundle accepted
                    // rather than race the watcher for it.
                    let mut accepted: std::collections::BTreeSet<String> =
                        std::collections::BTreeSet::new();
                    if auto_accept && !journal_broken {
                        let home = identity::home();
                        let contacts = trust::Contacts::load();
                        let auth = authority::Authority::load();
                        for a in &arrivals {
                            let dir = routes::pending_dir(&home).join(&a.id);
                            let Ok(l) = bundle::load(&dir) else { continue };
                            let d = autoaccept::consider(&home, &contacts, &auth, &l);
                            let short = &a.id[..8.min(a.id.len())];
                            match autoaccept::perform(&home, &a.id, &d) {
                                Ok(_) => {
                                    accepted.insert(a.id.clone());
                                    println!("  {short}: {}", d.explain());
                                }
                                Err(_) if !matches!(d, autoaccept::Decision::Yes { .. }) => {
                                    // Not an error: `perform` refuses
                                    // anything but `Yes`, which is how most
                                    // arrivals leave this loop.
                                    println!("  {short}: {}", d.explain());
                                }
                                Err(e) => {
                                    // The entry IS the budget, so a failure
                                    // to record stops the feature for the
                                    // rest of this run rather than being
                                    // printed and passed over.
                                    //
                                    // A reviewer caught the gap: `perform`'s
                                    // comment claimed the caller "stops
                                    // auto-accepting for this run", and the
                                    // caller only printed. A full disk would
                                    // have become an unbounded uncounted
                                    // accept path for as long as it lasted --
                                    // in exactly the unattended mode this
                                    // feature exists to bound.
                                    eprintln!("  {short}: could not auto-accept: {e}");
                                    eprintln!(
                                        "ctx watch: auto-accept is off for the rest of this \
                                         run. Nothing can be accepted unattended while the \
                                         journal cannot be written, because the journal is \
                                         what counts the budget. Arrivals stay pending."
                                    );
                                    journal_broken = true;
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(cmd) = &on_arrival {
                        for a in &arrivals {
                            // No grant, no hook. The notification above already
                            // told the human; this is the line that keeps the
                            // unattended path narrower than the visible one.
                            let Some(g) = &a.grant else {
                                println!(
                                    "  {} from {}: no grant covers it, so --on-arrival did not run",
                                    &a.id[..8.min(a.id.len())],
                                    a.from
                                );
                                continue;
                            };
                            println!(
                                "  running --on-arrival for {} ({g})",
                                &a.id[..8.min(a.id.len())]
                            );
                            if let Err(e) =
                                notify::run_hook(cmd, a, hook_timeout, accepted.contains(&a.id))
                            {
                                eprintln!("  --on-arrival: {e}");
                            }
                        }
                    }
                } else if once {
                    println!("nothing new");
                }
                if once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(every));
            }
        }
        Cmd::Journal { bundle, json, last, verify } => {
            if verify {
                let r = journal::verify();
                if !r.problems.is_empty() {
                    eprintln!(
                        "{} problem(s) in {}:",
                        r.problems.len(),
                        journal::path().display()
                    );
                    for p in &r.problems {
                        eprintln!("  line {}: {}", p.line, p.what);
                    }
                    return Err("the journal does not verify".into());
                }
                let unchained = r.total - r.chained;
                if r.chained == 0 {
                    println!("{} entries, none of them chained", r.total);
                } else {
                    println!("{} of {} entries are chained, and all of them check out",
                             r.chained, r.total);
                }
                if r.chained == 0 {
                    // Not a pass. Saying "intact" over a file nothing has
                    // verified would be the most misleading thing this
                    // command could print.
                    println!();
                    println!("  Nothing here is chained yet, so this check verified NOTHING.");
                    println!("  These entries predate chaining. The next one written starts");
                    println!("  the chain and freezes everything above it as it stands.");
                } else if unchained > 0 {
                    println!();
                    println!("  The {unchained} entries above the chain predate it. They are");
                    println!("  frozen as they stood when chaining began -- which is not the");
                    println!("  same as being trustworthy, since whoever started the chain");
                    println!("  could have edited them first.");
                }
                if r.chained > 0 {
                    println!();
                    println!("  A clean pass means no chained line has been changed, removed");
                    println!("  or reordered -- unless whoever did it also recomputed every");
                    println!("  following link, which anything running as you can do. It is");
                    println!("  evidence against a script dropping one inconvenient line, not");
                    println!("  proof against a process that rewrites the file. No local log");
                    println!("  can be that.");
                }
                return Ok(ExitCode::SUCCESS);
            }
            let all = journal::read();
            let rows: Vec<_> = all
                .iter()
                .filter(|e| bundle.as_deref().is_none_or(|b| e.bundle.starts_with(b)))
                .collect();
            let shown = rows.len().saturating_sub(last);
            if json {
                for e in &rows[shown..] {
                    println!("{}", serde_json::to_string(e)?);
                }
            } else if rows.is_empty() {
                println!("nothing recorded yet.");
                println!("  {} is written as bundles arrive, are accepted,", journal::path().display());
                println!("  rejected or opened. It holds hashes and verdicts, never contents.");
            } else {
                for e in &rows[shown..] {
                    println!(
                        "{}\t{:<8}\t{}\t{}",
                        e.at,
                        e.event.label(),
                        &e.bundle[..8.min(e.bundle.len())],
                        e.verdict
                    );
                    // The verdict is the frozen one, so say which key it was
                    // about: a later entry for the same bundle may carry a
                    // different verdict, and that difference is the record of
                    // a key having changed underneath.
                    println!(
                        "  seq {}  from {}…{}",
                        e.seq,
                        &e.from_key[..12.min(e.from_key.len())],
                        e.author_key
                            .as_ref()
                            .map(|a| format!("  authored by {}…", &a[..12.min(a.len())]))
                            .unwrap_or_default()
                    );
                }
                println!();
                println!("{} entr{}", rows.len(), if rows.len() == 1 { "y" } else { "ies" });
                println!("  hashes and verdicts only -- never a subject, a filename or a payload,");
                println!("  because a field a sender can fill is an injection against whatever");
                println!("  reads this next. Append-only by convention, not tamper-proof: a");
                println!("  process running as you can rewrite it.");
            }
        }
        Cmd::Ui { port } => {
            ui::serve(port)?;
        }
        Cmd::Lan { port } => {
            lan::run(port)?;
        }
        Cmd::Nearby { announce, r#for } => {
            let id = identity::Identity::load().ok();
            let secs = announce.unwrap_or(r#for).max(r#for);
            if let Some(n) = announce {
                let id = id.as_ref().ok_or("ctx init first -- announcing needs a key to sign with")?;
                println!("announcing for {n}s, then stopping. What leaves this machine:");
                println!("  handle \"{}\"  (a string you chose; nobody should trust it)", id.handle);
                println!("  signing key {}", id.public_b64());
                println!("  encryption key {}", id.box_public_b64());
                println!("  port {}", lan::LISTEN_PORT);
                println!("  to every host on this network. Anything listening learns all of it.");
                // Printed because the failure mode is silence. If the other
                // machine sees nothing, this line is the first thing worth
                // looking at -- a destination that is not your actual subnet
                // means the guess was wrong, and CTX_LAN_BCAST overrides it.
                println!("  sending to: {}", lan::bcast_targets().join(", "));
            } else {
                println!("listening for {secs}s. Not announcing -- pass --announce to be seen.");
            }
            let seen = lan::nearby(id.as_ref(), lan::LISTEN_PORT, secs, announce.is_some())?;
            if seen.is_empty() {
                println!();
                println!("nobody announcing. The other machine needs `ctx nearby --announce`.");
                return Ok(ExitCode::SUCCESS);
            }
            let c = trust::Contacts::load();
            println!();
            for s in &seen {
                let known = match c.name_for(&s.sign) {
                    Some(n) => format!("on your list as {n}"),
                    None => "NOT on your list -- ctx pair <name> to add it".to_string(),
                };
                println!("  \"{}\" at {}  ({known})", s.handle, s.addr.ip());
                println!("      says : {}", words::fingerprint(&s.sign));
            }
            println!();
            println!("the handle is decoration. The words are the key, and the only thing");
            println!("worth comparing with the person sitting at the other machine.");
        }
        Cmd::Pair { name, r#as, confirm, r#for } => {
            let id = identity::Identity::load()?;
            // If `ctx lan` is running it has already written down who is
            // here, so pairing needs no second announce window and no timing
            // between two machines. Falling back to listening keeps `ctx
            // pair` working on its own.
            let live: Vec<lan::Seen> = lan::read_nearby()
                .into_iter()
                .filter(|e| lan::now().saturating_sub(e.at) <= 60)
                .filter_map(|e| {
                    let addr: std::net::SocketAddr = e.addr.parse().ok()?;
                    Some(lan::Seen {
                        handle: e.handle,
                        sign: e.sign,
                        boxpub: e.boxpub,
                        addr,
                        port: addr.port(),
                    })
                })
                .collect();
            let seen = if live.is_empty() {
                println!("listening for {}s. The other machine wants `ctx lan`.", r#for);
                lan::nearby(Some(&id), lan::LISTEN_PORT, r#for, false)?
            } else {
                live
            };
            let c = trust::Contacts::load();
            let fresh: Vec<_> = seen.iter().filter(|s| !c.knows(&s.sign)).collect();
            let cand = match fresh.len() {
                0 if seen.is_empty() => {
                    return Err("nobody announcing on this network".into())
                }
                0 => return Err("everyone announcing is already on your list".into()),
                1 => fresh[0],
                // No numbered menu, on purpose: picking "2" from a list is
                // exactly the step where a person stops reading, and the
                // whole value of this command is that they read. Narrow it
                // down by having one machine announce at a time.
                // More than one, so the NAME has to say which. `ctx pair
                // laptop simple-dahlia` -- still no numbered menu, because
                // picking "2" from a list is exactly where a person stops
                // reading, and reading is the whole value of this command.
                n => {
                    let want = r#as
                        .as_deref()
                        .map(|w| w.trim().to_ascii_lowercase().replace('-', " "));
                    let pick: Vec<_> = match &want {
                        Some(w) => fresh
                            .iter()
                            .filter(|s| words::label(&s.sign).starts_with(w.as_str()))
                            .collect(),
                        None => Vec::new(),
                    };
                    if pick.len() == 1 {
                        pick[0]
                    } else {
                        for s in &fresh {
                            println!("  {}  at {}  {}", words::label(&s.sign), s.addr.ip(), words::fingerprint(&s.sign));
                        }
                        return Err(format!(
                            "{n} unpaired machines are here. Say which, by the word-pair \
                             above: ctx pair {name} <word-pair>"
                        )
                        .into());
                    }
                }
            };
            let fp = words::fingerprint(&cand.sign);
            println!();
            println!("  \"{}\" at {}", cand.handle, cand.addr.ip());
            println!("  says : {fp}");
            println!();
            match &confirm {
                Some(given) => {
                    // Compared on the words, whitespace-insensitive, so a
                    // value read off a screen and typed with a double space
                    // still matches -- but a single different word does not.
                    let norm = |x: &str| {
                        x.split_whitespace()
                            .filter(|t| *t != "·")
                            .map(|t| t.to_ascii_lowercase())
                            .collect::<Vec<_>>()
                    };
                    if norm(given) != norm(&fp) {
                        return Err(format!(
                            "those are not the same words.\n  you gave : {given}\n  \
                             it says  : {fp}\nNothing was added. Either you mistyped, or \
                             the machine announcing is not the one you are looking at."
                        )
                        .into());
                    }
                    println!("  matches what you read off the other screen.");
                }
                None => {
                    print!("Does the other machine show EXACTLY those words? [y/N] ");
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut ans = String::new();
                    std::io::stdin().read_line(&mut ans)?;
                    if !matches!(ans.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                        return Err("not paired. Nothing was added.".into());
                    }
                }
            }
            for l in trust::add_contact(&name, &cand.token())? {
                println!("{l}");
            }
            println!();
            println!("paired. With `ctx lan` running on both: ctx send --to {name} --file <path> --lan");
        }
        Cmd::Listen { bind, port } => {
            lan::listen(&bind, port)?;
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
