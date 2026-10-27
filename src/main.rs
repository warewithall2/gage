//! gage -- hand context between agents, with a trust boundary.
//!
//! Transport-agnostic on purpose. A bundle is a directory, so it moves over
//! anything you already have: a shared folder for two agents on one machine,
//! git, email, a file drop. No server is required, and none is included,
//! because agents are invoked rather than online -- presence is the part of
//! the instant-messenger model that does not transfer.

mod anchor;
mod agentcfg;
mod authority;
mod autoaccept;
mod backup;
mod bundle;
mod collect;
mod identity;
mod invite;
mod journal;
mod lan;
mod manifest;
mod mcp;
mod notify;
mod open;
mod outbound;
mod quickstart;
mod relay;
mod remote;
mod rotate;
mod routes;
mod runfile;
mod scrub;
mod seal;
mod sig;
mod state;
mod trust;
mod ui;
mod words;

use clap::{Parser, Subcommand};
use manifest::{one_line, shell_word};
use outbound::{SendArgs, all_manifests, resolve_reply, send_bundle};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "gage",
    about = "Hand context between agents, with provenance",
    // The version carries the build's commit, because "which gage is this"
    // is the first question when two machines disagree -- and with the
    // journal freezing verdicts, "a gage upgrade changed what a verdict
    // means" is an explanation an auditor has to be able to rule out.
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CTX_BUILD_REV"), ")")
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Send this machine's journal head to a contact, so they hold a copy
    Send {
        #[arg(long)]
        to: String,
    },
    /// Read anchors out of bundles you have accepted, and store them
    Record,
    /// What is held, and anything in it that contradicts itself
    List,
    /// Check an index and digest somebody holds for YOU against this journal
    ///
    /// The other half of anchoring. They read you an anchor they hold; this
    /// says whether this machine's journal still says the same thing there.
    Check { n: u64, digest: String },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// What agent identities exist here, and the words each key says
    List,
    /// Give an agent its own identity and introduce it to yours
    New { name: String },
    /// Take an agent out of service and delete its identity
    ///
    /// Retires its key rather than forgetting it, so anything it already
    /// sent keeps the verdict it was judged with.
    Remove {
        name: String,
        /// Go ahead without asking. This deletes an identity key.
        #[arg(long)]
        yes: bool,
    },
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
        #[arg(long)]
        compromised: bool,
    },
    /// Serve the Model Context Protocol on stdin/stdout, so an agent can call
    /// gage as tools
    ///
    /// stdio only: no port, no listener, no network surface. Point an MCP host
    /// at it -- `claude mcp add gage -- gage mcp`. See docs/mcp.md. Nothing is
    /// printed except protocol messages, because stdout IS the protocol.
    Mcp,
    /// Nothing to a first verified handoff, one step at a time
    ///
    /// Makes an identity if you have none, shows your word-pairs and the line
    /// you send a colleague, then offers to add their key and send one bundle.
    /// Every step is skippable and nothing here does anything the individual
    /// commands do not.
    Quickstart,
    /// Your key history: what is current, what is retired
    Keys,
    /// Write your identity to a passphrase-encrypted file you keep yourself
    ///
    /// Opt-in, and a real trade: it turns "lose the key, lose everything" into
    /// "your security is your passphrase's strength". Keep the file somewhere
    /// other than the machine it came from.
    ExportIdentity {
        /// Where to write it. Refuses to overwrite an existing file
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore an identity from a passphrase-encrypted backup
    ///
    /// Into a home with no identity. Shows the word-pair fingerprint of what
    /// the backup holds before writing anything, so you can check it is the
    /// identity you meant.
    RestoreIdentity {
        file: PathBuf,
        /// Replace an identity that is already here. Asks you to type `replace`
        /// as well, and moves the existing key aside rather than deleting it
        #[arg(long)]
        replace: bool,
    },
    /// Check a contact's rotation notice, and apply it only if told to
    Keychange {
        file: PathBuf,
        /// Actually move the contact onto the new key
        #[arg(long)]
        accept: bool,
    },
    /// Take a contact's key out of service without a replacement
    Retire {
        name: String,
        /// Their key was stolen, so even their old bundles stop counting
        #[arg(long)]
        compromised: bool,
        /// Also condemn every earlier key you held for them. For when you
        /// learn they were compromised long before you found out.
        #[arg(long)]
        all: bool,
    },
    /// Add someone's key to your buddy list (the signpub.boxpub token)
    Add {
        name: String,
        key: String,
        /// Put back a key you retired, or add one you refused
        ///
        /// Both are decisions somebody took to narrow this list, and `add`
        /// will not quietly undo either. It used to, with a `note:` line in
        /// the output -- so anything that could add a contact could reverse a
        /// revocation and leave no record anybody had to read.
        #[arg(long)]
        reinstate: bool,
        /// This machine generated the key, so there is nothing to compare
        ///
        /// For `gage agent new`, which makes a second identity beside this
        /// one: both keys come out of a keygen this machine just ran, there
        /// is no other party and no channel for anybody to sit on. Never use
        /// it for a key that came from anywhere else -- it records a
        /// confirmation that nobody performed.
        #[arg(long)]
        same_machine: bool,
    },
    /// Record that you compared a contact's word-pairs out of band
    ///
    /// The one thing that writes a confirmation, and the only reason a
    /// bundle ever reads SENDER VERIFIED. Every other way a key gets onto
    /// your list -- `add` from a chat window, `quickstart` from a pasted
    /// token, an agent calling the MCP server -- records that something put
    /// a key there, which is exactly as strong as the channel it came over.
    ///
    /// Type the four pairs as the OTHER machine shows them. Typing them is
    /// the point: it is the part that shows you read them off something that
    /// is not this screen.
    Confirm {
        /// The contact, as they appear in `gage contacts`
        name: String,
        /// The four word-pairs, as their machine shows them
        ///
        /// Separators and case do not matter; the words do. Leave it off to
        /// be asked for them.
        words: Vec<String>,
    },
    /// Agent identities on this machine: one key each, so a grant can name one
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Publish your journal's head to contacts, and hold theirs
    ///
    /// A local chain cannot catch a process that rewrites the whole file and
    /// re-links it. A head somebody else is holding can.
    #[command(subcommand)]
    Anchor(AnchorCmd),
    /// Get set up and get the one line you send to the other person.
    ///
    /// Does the three steps that have no decisions in them -- make an
    /// identity, register a mailbox on a relay, work out what to share --
    /// and then stops at the one step that does: confirming the other
    /// party's word-pairs with them, out loud, over a channel that is not
    /// this one. That step is not automated here because automating it
    /// would be removing the only thing gage actually does
    Connect {
        /// The relay to register with, e.g. https://relay.example.com.
        /// Omit it to see where you stand and get your share line again
        relay: Option<String>,
        /// What to call yourself. Only used if you have no identity yet;
        /// with no name, one is derived from your own key
        #[arg(long)]
        name: Option<String>,
    },
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
        /// Show the words for the SIGNING key alone.
        ///
        /// The normal form covers both halves of an identity, because
        /// confirming only the signing key lets an attacker substitute the
        /// encryption key and still pass the comparison. But a bundle does
        /// not carry its sender's encryption key, so someone confirming a
        /// connection request has only the signing half to compare -- and
        /// must compare it against this
        #[arg(long)]
        signing_only: bool,
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
        #[arg(long)]
        to: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt an envelope back into a bundle directory
    Unseal {
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// List your contacts and groups
    Contacts,
    /// Build a bundle
    Send {
        #[arg(long)]
        to: Vec<String>,
        #[arg(long)]
        subject: String,
        /// Where to write it. Omit when --to is a routed local handle.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        file: Vec<PathBuf>,
        #[arg(long)]
        prompt: Vec<PathBuf>,
        #[arg(long)]
        decision: Vec<PathBuf>,
        /// An agent's persistent memory (CLAUDE.md, AGENTS.md, memory/*.md).
        /// Fenced hardest on receipt: it outlives the session that accepts it.
        #[arg(long)]
        memory: Vec<PathBuf>,
        /// A whole directory, structure preserved, build dirs and
        /// secret-looking files skipped
        #[arg(long)]
        dir: Vec<PathBuf>,
        /// Include files that look like secrets (.env, *.pem, *.key). Off by
        /// default, and you should have a reason.
        #[arg(long)]
        allow_secrets: bool,
        /// Bundle id this one answers. Inherits that bundle's thread.
        #[arg(long)]
        reply_to: Option<String>,
        /// share | question | answer | review-request | ack
        #[arg(long, default_value = "share")]
        r#type: String,
        /// Proceed despite findings from the outbound content scan. Prints
        /// what it is overriding.
        #[arg(long)]
        allow_findings: bool,
        /// Hand it straight to a machine on this network once it is built,
        /// so sending is one command rather than a build and then a push.
        /// --to may be a word-pair from the `gage lan` list.
        #[arg(long)]
        lan: bool,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        model: Option<String>,
    },
    /// Answer a thread without typing its id or working out the recipient
    Reply {
        /// Thread or message id. A unique prefix is enough.
        id: String,
        /// The reply itself, as text. Scanned on the way out like any file.
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        file: Vec<PathBuf>,
        #[arg(long)]
        prompt: Vec<PathBuf>,
        #[arg(long)]
        decision: Vec<PathBuf>,
        #[arg(long)]
        memory: Vec<PathBuf>,
        #[arg(long)]
        dir: Vec<PathBuf>,
        /// Override the inferred type (answer for a question, otherwise share)
        #[arg(long)]
        r#type: Option<String>,
        /// Override the inferred subject
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        allow_secrets: bool,
        #[arg(long)]
        allow_findings: bool,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Summarise a bundle without putting its contents in context
    Inspect { dir: PathBuf },
    /// Render a bundle for an agent to read, inside a trust frame
    Open {
        dir: PathBuf,
        /// Show contents even when the signature does not verify
        #[arg(long)]
        reveal: bool,
    },
    /// Map a handle to a local gage home, so --to delivers with no --out
    Route { handle: String, home: PathBuf },
    /// Conversations, grouped, newest activity first
    Threads {
        /// only threads where the ball is in your court
        #[arg(long)]
        mine: bool,
    },
    /// Every message in one thread, oldest first
    Thread { id: String },
    /// Mark a thread settled regardless of what the messages imply
    Close { thread: String },
    /// What is waiting for you
    Inbox {
        /// machine-readable, for an agent harness
        #[arg(long)]
        json: bool,
        /// include already-accepted bundles
        #[arg(long)]
        all: bool,
        /// only what you have not opened
        #[arg(long)]
        unread: bool,
    },
    /// Move a pending bundle to accepted. Arrival is not consent.
    Accept { id: String },
    /// Delete a pending bundle without reading it
    Reject { id: String },
    /// Run a relay (on the box that will hold mail)
    Relay {
        /// Bind address. Default is the tailnet-only loopback-equivalent:
        /// pass the tailnet IP explicitly rather than 0.0.0.0.
        #[arg(long, default_value = "127.0.0.1:7788")]
        bind: String,
        #[arg(long)]
        store: Option<PathBuf>,
        /// megabytes one mailbox may hold before it stops accepting
        #[arg(long, default_value = "64")]
        max_mailbox_mb: u64,
        /// envelopes one mailbox may hold -- a thousand small ones flood as
        /// well as one big one, and cost the recipient more
        #[arg(long, default_value = "500")]
        max_mailbox_msgs: usize,
        /// megabytes the whole store may hold
        #[arg(long, default_value = "4096")]
        max_store_mb: u64,
        /// requests per minute from one address
        #[arg(long, default_value = "120")]
        rate_per_min: u32,
        /// mailboxes that may exist on this relay at all. Registration needs
        /// no authentication beyond proving you hold the key you are
        /// registering, which stops squatting and not manufacturing
        #[arg(long, default_value = "2000")]
        max_mailboxes: usize,
    },
    /// Point this identity at a relay and register your mailbox
    Join { addr: String },
    /// Push a sealed envelope to the relay for a contact
    Push {
        dir: PathBuf,
        #[arg(long)]
        to: String,
        /// Hand it to them over this network instead of the relay. Finds
        /// their address by a signed query, which only they can answer.
        #[arg(long)]
        lan: bool,
        /// Skip the confirmation. Required for a non-interactive push, so an
        /// agent has to state that it meant to send this off the machine.
        #[arg(long)]
        yes: bool,
    },
    /// Collect anything waiting for you on the relay into inbox/pending
    Pull {
        /// leave envelopes on the relay instead of deleting them
        #[arg(long)]
        keep: bool,
    },
    /// Poll the relay and notify when something new arrives
    Watch {
        /// seconds between polls
        #[arg(long, default_value = "120")]
        every: u64,
        /// check once and exit, for a systemd timer or a cron entry
        #[arg(long)]
        once: bool,
        /// print instead of firing a desktop notification
        #[arg(long)]
        quiet: bool,
        /// Run this command when an arrival is covered by a grant in your
        /// authority file. It is given CTX_BUNDLE_ID, CTX_FROM, CTX_FROM_KEY,
        /// CTX_TYPE, CTX_SUBJECT, CTX_EXPECTS_REPLY, CTX_GRANT and
        /// CTX_AUTO_ACCEPTED in its environment -- never the bundle's
        /// contents. The hook itself accepts nothing; but with --auto-accept
        /// also given, acceptance happens FIRST, so the bundle may already be
        /// accepted when the hook runs and CTX_AUTO_ACCEPTED says whether it
        /// was. This help used to say only "it does not accept the bundle",
        /// which read as a promise about the watcher and was one about the
        /// hook. Arrivals with no grant notify as usual and run nothing
        #[arg(long)]
        on_arrival: Option<String>,
        /// seconds before a hook that has not finished is killed
        #[arg(long, default_value = "300")]
        hook_timeout: u64,
        /// Accept arrivals that a grant says may be accepted unattended,
        /// within that grant's max-exchanges for the thread. Only grants
        /// written `auto-accept` qualify, and only replies to something this
        /// machine sent. Every such acceptance records which grant allowed
        /// it. Acceptance itself moves the bundle and reads nothing -- but it
        /// runs BEFORE --on-arrival, so with both flags a granted arrival is
        /// accepted and then your hook runs with CTX_AUTO_ACCEPTED=1. Nothing
        /// here opens a payload; the hook can, and that is your command's
        /// choice, not this flag's
        #[arg(long)]
        auto_accept: bool,
    },
    /// What this machine did with what arrived: one line per event
    Journal {
        /// only this bundle
        #[arg(long)]
        bundle: Option<String>,
        /// the raw JSONL, for a tool rather than a person
        #[arg(long)]
        json: bool,
        /// how many of the most recent entries to show
        #[arg(long, default_value = "40")]
        last: usize,
        /// Walk the hash chain and report every break. A clean pass means no
        /// line has been changed, removed or reordered since chaining began
        /// -- unless whoever did it also recomputed every following link,
        /// which anything running as you can do. Evidence against a script
        /// quietly dropping the line that incriminates it; not proof against
        /// a determined local process
        #[arg(long)]
        verify: bool,
    },
    /// What this machine has SENT: one line per bundle, and to whom.
    ///
    /// The send journal. It prevents nothing -- see
    /// docs/adr-send-side-restraint.md -- it makes what left answerable
    /// afterwards, which is the only honest thing a local log can do about a
    /// local action
    Sent {
        /// only sends newer than this: a duration like 24h, 7d, 30m
        #[arg(long)]
        since: Option<String>,
        /// only bundles addressed to this handle or key
        #[arg(long)]
        to: Option<String>,
        /// the raw JSONL, for a tool rather than a person
        #[arg(long)]
        json: bool,
        /// how many of the most recent sends to show
        #[arg(long, default_value = "40")]
        last: usize,
    },
    /// Serve the local viewer on 127.0.0.1
    Ui {
        #[arg(long, default_value = "7777")]
        port: u16,
    },
    /// Be on this network: visible, discoverable and reachable, for exactly
    /// as long as this runs. The whole of it in one command -- start it on
    /// both machines and they can see and send to each other. Stop it and
    /// this machine is silent again.
    Lan {
        #[arg(long, default_value_t = lan::LISTEN_PORT)]
        port: u16,
    },
    /// Who is announcing themselves on this network, right now
    Nearby {
        /// Also announce YOURSELF, for this many seconds. Off by default:
        /// gage has never had presence, and a laptop broadcasting its handle
        /// and public key onto every network it joins would change that
        /// quietly. This is the pairing mode, and it stops on its own.
        #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "60")]
        announce: Option<u64>,
        /// How long to listen
        #[arg(long, default_value = "10")]
        r#for: u64,
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
        /// Which machine, by the word-pair `gage lan` shows. Only needed when
        /// more than one unpaired machine is on the network.
        r#as: Option<String>,
        /// The four word-pairs the other machine shows. Given here, they are
        /// compared for you and the pairing fails on any difference -- which
        /// is stricter than a person squinting at a y/n prompt. Omit it to
        /// be shown the words and asked.
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long, default_value = "20")]
        r#for: u64,
    },
    /// Be reachable on this network: answer address queries from keys on your
    /// list, and accept a sealed bundle straight from them. No announcing.
    Listen {
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(long, default_value_t = lan::LISTEN_PORT)]
        port: u16,
    },
    /// Re-sign a bundle for someone else, appending to its chain
    Forward {
        dir: PathBuf,
        #[arg(long)]
        to: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
}

/// Observe the inbox, and say so loudly if it could not be done.
///
/// Every caller is about to print a trust verdict, and the verdict depends on
/// this having run. Swallowing the error would silently downgrade a rejected
/// bundle to "no record either way", which is the milder label.
/// Turn `24h`, `7d`, `30m` into the UTC timestamp that far in the past.
///
/// Formatted by `bundle::rfc3339`, the same function that writes `at`, so the
/// comparison in `gage sent --since` is between two strings produced the same
/// way. RFC3339 in UTC with fixed width sorts lexically, which is why a string
/// compare is sound here and would not be if either side were formatted
/// differently.
fn parse_since(w: &str) -> Result<String, Box<dyn std::error::Error>> {
    let w = w.trim();
    let (n, unit) = w.split_at(w.len().saturating_sub(1));
    let n: i64 = n.parse().map_err(|_| {
        format!("--since wants a duration like 24h, 7d or 30m, not {:?}", manifest::one_line(w))
    })?;
    if n < 0 {
        return Err("--since cannot be negative; it looks backwards from now".into());
    }
    let secs = match unit {
        "m" => n * 60,
        "h" => n * 3_600,
        "d" => n * 86_400,
        "w" => n * 604_800,
        _ => {
            return Err(format!(
                "unknown unit {:?} in --since; use m, h, d or w",
                manifest::one_line(unit)
            )
            .into());
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(bundle::rfc3339(now - secs))
}

fn observe_or_warn() {
    if let Err(e) = routes::observe_inbox() {
        eprintln!(
            "gage: WARNING -- could not record what is in your inbox ({e}). A retired-key \
             verdict below may read as ARRIVAL UNRECORDED when it should be a rejection. \
             Re-run once no other gage process is writing."
        );
    }
}

/// Both legs of registration: claim a mailbox, then prove it by opening a
/// nonce the relay sealed to it.
///
/// Naming a box key proves nothing -- it is in every `gage whoami` line -- so
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
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
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

/// Restore the default SIGPIPE disposition. The declaration lives in `sig`,
/// which is the only place in this crate that declares `signal(2)`.
#[cfg(unix)]
unsafe fn libc_signal_default() {
    sig::restore_default(sig::SIGPIPE);
}

/// Collect anything waiting on the relay into inbox/pending.
///
/// Shared by `pull` and `watch` rather than duplicated: a watcher that
/// collected differently from a manual pull would announce bundles the user
/// could then not find.
fn pull_once(keep: bool) -> Result<(), Box<dyn std::error::Error>> {
    pull_inner(keep, false, None)
}

/// `gage_pull`, for the MCP server: the same pull, with its two stdout lines
/// collected instead of printed. On a stdio transport stdout is the JSON-RPC
/// channel, so printing there would corrupt the session. `fetch_mailbox`
/// writes only to stderr, which is free.
pub fn pull_for_mcp(say: &mut Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    pull_inner(false, true, Some(say))
}

/// `gage_push`, for the MCP server. Shares `push_core` with `gage push`, so
/// the sealing and the relay call cannot drift between the two front doors.
pub fn push_for_mcp(
    dir: &std::path::Path,
    to: &str,
    say: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = remote::relay_addr().ok_or(
        "no relay is set for this identity, so there is nowhere to push to.          Set one with `gage join <address>`, or hand the bundle directory over          yourself -- it is signed, and the transport is not trusted with anything.",
    )?;
    push_core(dir, to, &addr, say)
}

/// Seal a built bundle to a contact and hand it to the relay.
fn push_core(
    dir: &std::path::Path,
    to: &str,
    addr: &str,
    say: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = trust::Contacts::load();
    let sign = match c.key_for_name(to) {
        Some(k) => k,
        None => {
            return Err(match c.retired_by_name(to) {
                Some((_, r)) => format!(
                    "{to}'s key was retired on {}; add their current key before \
                     pushing to them",
                    r.retired_at
                ),
                None => format!("no contact named {to}"),
            }
            .into());
        }
    };
    let boxpub = c
        .box_keys
        .get(&sign)
        .ok_or(format!("{to} has no encryption key on file; re-add them"))?;
    // Scan the thing being pushed. `outbound::send_bundle` scans what it is
    // about to build and `outbound.rs` opens with "There is one way out of
    // this program" -- which was not true: push takes a directory somebody
    // else assembled, and `gage_push` let an agent hand over a bundle it had
    // built by hand with nothing looking at the contents. A reviewer pushed
    // AWS keys and an OpenSSH private key through this path and decrypted
    // them on the far side.
    //
    // No --allow-findings here, deliberately. On the send path that flag is a
    // person saying "I looked, they are false positives" about files they
    // chose moments ago. Here the bundle predates the command and may not
    // have been assembled by a human at all.
    let findings = scrub::scan_built(dir);
    if !findings.is_empty() {
        return Err(scrub::refusal_lines(&findings).join("\n").into());
    }
    let env = seal::seal_dir(dir, boxpub)?;
    let body = serde_json::json!({
        "to_box": boxpub, "envelope": serde_json::to_string(&env)? })
    .to_string();
    let resp = remote::post(addr, "/send", &body)?;
    say.push(format!("pushed to {to} via {addr}"));
    say.push(format!("  {}", resp.trim()));
    Ok(())
}

/// `quiet` suppresses the nothing-to-do line. A watcher polls on an interval,
/// and a line per poll turns its journal into noise that hides the one entry
/// that mattered.
fn pull_inner(
    keep: bool,
    quiet: bool,
    mut say: Option<&mut Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut emit = |s: String| match say.as_deref_mut() {
        Some(v) => v.push(s),
        None => println!("{s}"),
    };
    let addr = remote::relay_addr().ok_or(
        "no relay is set for this identity, so there is nowhere to collect from.\n  \
         If you have one:        gage join <address>\n  \
         No relay? You do not need one -- hand the bundle directory over yourself \
         and the other side runs `gage open <dir>`, or use `gage lan` if you are \
         both on this network.",
    )?;
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
            boxes.push((
                r.box_pub.clone(),
                format!(" (retired key, {})", r.retired_at),
            ));
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
        emit(format!("nothing waiting on {addr}"));
    }
    if total > 0 {
        emit(format!(
            "\n{total} bundle(s) in inbox/pending -- gage inbox, then accept or reject"
        ));
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
    // Naming a key is not proof: anyone who has seen a `gage whoami`
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
    let items = v
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default();
    let pending = routes::pending_dir(&identity::home());
    std::fs::create_dir_all(&pending)?;
    let mut n = 0;
    for it in &items {
        let Some(raw) = it.get("envelope").and_then(|e| e.as_str()) else {
            continue;
        };
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
        // join. A signed manifest carrying `id: "../../../../tmp/gage-pwn"`
        // would otherwise have written a bundle outside the inbox entirely.
        if !manifest::id_is_safe(&loaded.manifest.id) {
            eprintln!(
                "  refused: a bundle whose id is not an id ({}) -- it would have become \
                 a path",
                // The ONE place in this file where the id has to be escaped,
                // and the one place it was not: every print below this point
                // has passed `id_is_safe`, which is 16 lowercase hex digits
                // and cannot carry a newline. This arm runs precisely because
                // it did not pass, so the value here is arbitrary
                // sender-chosen bytes landing on stdout that an agent reads.
                // `{:?}` escapes a newline but not a frame marker, and it is
                // not what the rest of the program uses.
                manifest::safe_display(&loaded.manifest.id, 40)
            );
            let _ = std::fs::remove_dir_all(&tmp);
            continue;
        }
        // And a bundle that does not verify never enters the inbox from the
        // relay. Local delivery is written by the sender and cannot be gated
        // here, which is what the trust verdict on read is for -- but mail
        // the relay handed us is ours to refuse.
        if !loaded.tampered.is_empty() {
            eprintln!(
                "  refused {}: {}",
                loaded.manifest.id,
                loaded.tampered.join(", ")
            );
            let _ = std::fs::remove_dir_all(&tmp);
            continue;
        }
        let dest = pending.join(&loaded.manifest.id);
        // Has this machine seen this EXACT manifest before?
        //
        // `dest.exists()` below only asks about `pending`, so once a bundle
        // was accepted that path was gone and the identical envelope was
        // staged again as a fresh arrival -- for ever, on demand. The
        // content is genuine, which is what makes it dangerous: a replayed
        // instruction is a real instruction that was already carried out.
        // Anyone who can reach the relay, including the relay, can do this.
        //
        // The witness is the answer and was already being recorded: it is
        // `sha256(from.key || 0x1f || manifest bytes)`, so it identifies
        // this manifest and not merely this id. A sender resending in good
        // faith produces a new manifest -- different `created` at minimum --
        // and is unaffected.
        // Fails CLOSED. The first version was a chain of `.ok()` and
        // `.and_then`, so an unreadable manifest or an unloadable state file
        // collapsed to "never seen" and staged the replay -- a reviewer put
        // it exactly: the protection that matters most on a damaged machine
        // was the one that silently disabled itself. If this machine cannot
        // tell whether it has seen a bundle, it does not accept it.
        let seen_before = match std::fs::read(tmp.join("manifest.json")) {
            Ok(bytes) => {
                let w = bundle::witness_of(&loaded.manifest.from.key, &bytes);
                state::LocalState::load().witnessed(&w).is_some()
            }
            Err(e) => {
                eprintln!(
                    "  refused {}: cannot read its manifest back to check for a replay ({e})",
                    loaded.manifest.id
                );
                let _ = std::fs::remove_dir_all(&tmp);
                continue;
            }
        };
        if seen_before && !dest.exists() {
            println!(
                "  refused {} -- this machine has already seen this exact message.",
                loaded.manifest.id
            );
            println!("    A replayed message is a real one that was already handled.");
            println!("    If they meant to send it again, ask them to send it again:");
            println!("    a new message has a new id and arrives normally.");
            // Recorded against the temp copy, because in a moment there will
            // not be one -- the same reason `reject` journals before it
            // deletes.
            if let Err(e) = journal::record(journal::Event::Duplicate, &tmp) {
                eprintln!("  (could not journal that refusal: {e})");
            }
            let _ = std::fs::remove_dir_all(&tmp);
            continue;
        }
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
                loaded.manifest.id,
                // Sender-chosen, and this line is the collect summary an
                // agent reads after `gage pull`. The id above it is safe by
                // `id_is_safe`; the subject has never been checked at all.
                manifest::safe_display(&loaded.manifest.subject, 160),
                verdict,
                label
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

/// Say so when a run record claims this home is already serving `service`.
///
/// **This warns; it does not refuse.** The first version refused, and a
/// cross-family audit was right that refusing is unsafe. A run record holds
/// a pid, and a pid is not an identity: a container restarted on the same
/// volume comes back as pid 1 with the same argv and matches its own stale
/// record, and nothing in `running_in` compares start time, namespace or
/// home. Refusing on that evidence makes gage unstartable with no way out
/// but deleting a file nobody has been told about. It also refused
/// `gage ui --port 8080` alongside a server on 7777, which would have bound
/// perfectly well, because the check knows nothing about ports.
///
/// Warning keeps what the check was for. A genuine duplicate still fails on
/// bind, but now with the sentence that explains it printed first instead of
/// an "address already in use" that sends the reader to look at the network.
/// A false positive costs one line of output.
///
/// The record's own pid is excluded: a process cannot be the thing that is
/// already running instead of itself.
fn note_if_already_serving(service: &str) {
    if !runfile::running(service) {
        return;
    }
    // Named explicitly, because "stop the other one" is useless advice when
    // there is no other one. The record is the thing to delete.
    let record = runfile::path_for(service);
    eprintln!(
        "gage: a run record says `gage {service}` is already serving this home \
         ({}).",
        record.display()
    );
    eprintln!(
        "  If that is wrong -- a stale record from a process that was killed, \
         or a reused pid -- delete that file."
    );
    eprintln!("  Starting anyway.");
}

fn main() -> ExitCode {
    // Rust sets SIGPIPE to ignore, so writing to a closed pipe returns an
    // error that `println!` turns into a panic. `gage threads | head` then
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
            eprintln!("gage: {e}");
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
            eprintln!(
                "  this key says : {}",
                words::fingerprint_of(&id.public_b64(), Some(&id.box_public_b64()))
            );
            // Labelled for what it covers. These two lines sat adjacent with
            // the shorter one reading "shown as", which invited the reading
            // that it is the first of the four pairs above -- and that is
            // true only for a key with no encryption half. This one has one,
            // so the two values come from two different hashes. README and
            // spec.md both printed this example WITH the label repeated as
            // the fingerprint's first pair, which cannot happen.
            eprintln!(
                "  device label  : {}   (from the signing key alone, so NOT the first",
                words::label(&id.public_b64())
            );
            eprintln!("                    pair above -- it is how others tell machines apart)");
            eprintln!();
            eprintln!("  Those words come from the key, so nobody picks their own.");
            eprintln!("  When you pair with another machine, both screens must show");
            eprintln!("  the same four pairs. The short label is only for telling");
            eprintln!("  devices apart in a list -- never confirm against it alone.");
        }
        Cmd::Mcp => {
            mcp::run()?;
        }
        Cmd::Quickstart => {
            quickstart::run().map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Cmd::ExportIdentity { out } => {
            backup::export(&out).map_err(std::io::Error::other)?;
        }
        Cmd::RestoreIdentity { file, replace } => {
            backup::restore(&file, replace).map_err(std::io::Error::other)?;
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
                println!("  still be collected. gage pull drains both mailboxes.");
            }
            println!("\nnotice written to {}", np.display());
            println!("  send it to each contact; they run: gage keychange <file>");
            if remote::relay_addr().is_some() {
                let addr = remote::relay_addr().unwrap();
                let body = serde_json::json!({
                    "sign_key": id.public_b64(), "box_key": id.box_public_b64() })
                .to_string();
                match register_with_proof(&addr, &id, &body) {
                    Ok(_) => println!("\nregistered the new mailbox with {addr}"),
                    Err(e) => println!(
                        "\ncould not register with {addr}: {e}\n  run gage join {addr} once it is reachable"
                    ),
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
                    if r.can_collect() {
                        ""
                    } else {
                        " (secrets destroyed)"
                    }
                );
            }
        }
        Cmd::Fingerprint { name, signing_only } => {
            // The encryption key is carried alongside, because the value a
            // person confirms has to cover BOTH halves of the identity --
            // otherwise an attacker substitutes the half nobody checks. See
            // `words::fingerprint_of`.
            let (who, key, boxpub) = match &name {
                None => {
                    let id = identity::Identity::load()?;
                    (
                        id.handle.clone(),
                        id.public_b64(),
                        Some(id.box_public_b64()),
                    )
                }
                Some(n) => {
                    let c = trust::Contacts::load();
                    match c.key_for_name(n) {
                        Some(k) => {
                            let b = c.box_keys.get(&k).cloned();
                            if b.is_none() {
                                // Said out loud rather than quietly showing
                                // a narrower value as though it were the
                                // same one -- and on STDERR, which is the
                                // other half of the rule the comment below
                                // states and this block used to break:
                                // `gage fingerprint x | cut -f2` saw four
                                // lines of prose before the value.
                                eprintln!(
                                    "note: {n} has no encryption key on file, so these words"
                                );
                                eprintln!("  cover the signing key only. You can verify them and");
                                eprintln!("  not seal to them; re-add them from a full token to");
                                eprintln!("  get both.");
                            }
                            (n.clone(), k, b)
                        }
                        None => match c.retired_by_name(n) {
                            Some((k, r)) => {
                                eprintln!("note: {n} is a key you retired on {}", r.retired_at);
                                // A retired contact's encryption key is not
                                // kept, so these words cover the signing key
                                // only -- which is honest for a key that can
                                // no longer be sealed to anyway.
                                (n.clone(), k.to_string(), c.box_keys.get(k).cloned())
                            }
                            None => return Err(format!("no contact named {n}").into()),
                        },
                    }
                }
            };
            // One line on stdout, and the short form on stderr. The same
            // shape as `whoami`, for the same reason: `gage fingerprint x |
            // cut -f2` is the obvious thing to write, and `cut` passes a
            // second line straight through, so two lines here turn one value
            // into two. Found by writing exactly that in the LAN test.
            let boxpub = if signing_only { None } else { boxpub };
            if signing_only {
                eprintln!("  signing key only -- use this ONLY to confirm a connection");
                eprintln!("  request, where the other side has no encryption key for you.");
                eprintln!("  For a full pairing, compare the normal words, which cover both.");
            }
            println!("{who}\t{}", words::fingerprint_of(&key, boxpub.as_deref()));
            eprintln!(
                "{who}\t{}\t(the device label: signing key only, NOT a prefix of the \
                 words above, and never a thing to confirm against)",
                words::label(&key)
            );
            // Whether anybody ever compared these words, for the contact
            // case. Printed here because this is the command a person runs
            // while wondering exactly that.
            if name.is_some() {
                let c = trust::Contacts::load();
                if c.is_confirmed(&key) {
                    eprintln!("  confirmed; bundles from this key read SENDER VERIFIED");
                } else if c.stale_confirmation(&key).is_some() {
                    eprintln!("  a confirmation exists but no longer covers this key --");
                    eprintln!("  compare these words again, then: gage confirm {who}");
                } else if c.knows(&key) {
                    eprintln!("  NOT confirmed. Once you have compared these with them:");
                    eprintln!("    gage confirm {who}");
                }
            }
        }
        Cmd::Authority => {
            let a = authority::Authority::load();
            let p = authority::path();
            if !a.present {
                println!("no authority file at {}", p.display());
                println!("nothing is pre-authorised; every request gets reported to you");
            } else if let Some(e) = &a.error {
                println!("{}", e);
                println!(
                    "the file grants NOTHING while it does not parse, which is the safe direction"
                );
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
                                None => format!(
                                    "contact {n} -- NO SUCH CONTACT, so this grants nothing"
                                ),
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
            let v = rotate::verify_notice(&n)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let mut c = trust::Contacts::load();
            let known = c.name_for(&v.old_sign).map(|s| s.to_string());
            println!("rotation notice");
            println!(
                "  claims handle : {} (their own text, not identity)",
                v.claim.handle
            );
            println!(
                "  old key       : {}…",
                v.old_sign.chars().take(16).collect::<String>()
            );
            println!(
                "  new key       : {}…",
                v.new_sign.chars().take(16).collect::<String>()
            );
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
                            with them directly and run: gage add <name> <newkey>"
                    .into());
            };
            let q = shell_word(&name);
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
                     gage retire {q} {}\n  gage add {q} {}",
                    if v.claim.reason == "compromised" {
                        "--compromised"
                    } else {
                        ""
                    },
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
            // it gets the checks `gage add` already applies to a key a person
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
                // `gage add` deliberately *removes* a non-compromised retired
                // record when a person re-adds a key by hand. So the
                // contradictory state should not exist at all, and this is
                // the only path that creates it.
                return Err(format!(
                    "NOT APPLIED: this notice rotates onto a key you RETIRED on {}{}. \
                     Applying it would put that key back in service while the \
                     retirement still stands, and bundles you had rejected would \
                     read as verified again. If you really mean to trust that key \
                     again, that is a decision to make by hand and in the open:\n  \
                     gage add {q} {}",
                    r.retired_at,
                    if r.compromised { " as COMPROMISED" } else { "" },
                    v.claim.new_key
                )
                .into());
            }
            if let Some(other) = c.name_for(&v.new_sign)
                && other != name
            {
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
            // No confirmation carries over, and this is the one place where
            // saying why matters most. The notice is signed by the key being
            // retired, so accepting it proves the holder of the OLD key chose
            // the new one -- which is precisely what a thief holding the old
            // key also gets to prove. A rotation is a channel, not a
            // comparison, and the only thing that distinguishes the two cases
            // is a human asking them.
            println!("  NOT confirmed: the notice was signed by the key being retired, so");
            println!("  it shows whoever held that key chose this one -- which is also true");
            println!("  if that key was stolen. Their mail reads SENDER ON YOUR LIST,");
            println!("  UNCONFIRMED until you compare the new words with them:");
            println!("      gage confirm {name}");
            println!("  cutoff recorded at {now}, observation {seq} (this machine's own");
            println!(
                "  record). They state they rotated at {} -- that is their",
                v.claim.at
            );
            println!("  claim, and it is not what the verdict uses.");
            // Said because the consequence is surprising: the same bundle can
            // read as attributable on one machine and not on another.
            println!("  this is recorded for THIS gage home only. Another machine sharing");
            println!("  your identity has its own record and needs its own keychange,");
            println!("  and until then the old key is still live over there.");
            println!("  their old bundles stay verifiable, marked as signed with a retired key");
            println!("  anything NEW signed with the old key is now rejected");
        }
        Cmd::Anchor(sub) => match sub {
            AnchorCmd::Send { to } => {
                let Some(a) = anchor::Anchor::mine() else {
                    return Err("there is nothing to anchor yet: this journal has \
                                no chained entries. Anchoring an unchained file \
                                would publish a digest nothing commits to."
                        .into());
                };
                // Staged inside the gage home, not /tmp. A predictable path
                // in a world-writable directory can be pre-created by
                // somebody else as a symlink, and this would then write
                // through it. The content is only a public digest, so the
                // stake is low -- but the home is already created 0700 and
                // costs nothing to use, and "low stake" is how the habit of
                // writing through /tmp gets established.
                let dir = crate::identity::home().join(format!(".anchor-{}", std::process::id()));
                std::fs::create_dir_all(&dir)?;
                let f = dir.join(anchor::ITEM);
                std::fs::write(&f, a.to_json())?;
                let mut say = Vec::new();
                let r = send_bundle(
                    SendArgs {
                        to: vec![to.clone()],
                        subject: format!("journal head {}", a.n),
                        out: None,
                        file: vec![f],
                        prompt: Vec::new(),
                        decision: Vec::new(),
                        memory: Vec::new(),
                        dir: Vec::new(),
                        // A sha256 is 64 hex characters, which is also the
                        // shape of plenty of real secrets. The scanner is
                        // right to look twice and wrong here, and this is
                        // the one call site where the content is known to be
                        // a digest this machine just computed.
                        allow_secrets: true,
                        reply_to: None,
                        msg_type: "share".into(),
                        allow_findings: false,
                        lan: false,
                        agent: None,
                        model: None,
                        // The one send that is NOT journalled. See `record_send`.
                        record_send: false,
                    },
                    &mut say,
                );
                let _ = std::fs::remove_dir_all(&dir);
                for l in say {
                    println!("{l}");
                }
                r?;
                println!("anchored entry {} with {to}", a.n);
                println!("  digest : {}", a.digest);
                println!("  Everything after entry {} is still rewritable without", a.n);
                println!("  anybody noticing. Anchor again to move that line.");
            }
            AnchorCmd::Record => {
                let me = identity::home();
                let c = trust::Contacts::load();
                let mut stored = 0usize;
                let mut evidence = 0usize;
                for (_id, b) in routes::list(&routes::accepted_dir(&me)) {
                    let Some(item) = b
                        .manifest
                        .items
                        .iter()
                        .find(|i| i.path == format!("items/{}", anchor::ITEM))
                    else {
                        continue;
                    };
                    // Only from a key on the list. An anchor is a stored
                    // claim, and storing claims from keys nobody confirmed
                    // is how a directory of strangers accumulates.
                    let key = &b.manifest.from.key;
                    if !c.knows(key) {
                        continue;
                    }
                    if !b.tampered.is_empty() {
                        continue;
                    }
                    let Ok(txt) = std::fs::read_to_string(b.dir.join(&item.path)) else {
                        continue;
                    };
                    let Ok(a) = anchor::Anchor::parse(&txt) else {
                        continue;
                    };
                    let name = c.name_for(key).unwrap_or("?").to_string();
                    let outcome = anchor::store(key, &a)?;
                    if outcome.is_evidence() {
                        evidence += 1;
                    }
                    match outcome {
                        anchor::Held::Same => {}
                        anchor::Held::Fresh => {
                            stored += 1;
                            println!("{name}: entry {} recorded", a.n);
                        }
                        anchor::Held::Diverged { was } => {
                            println!("{name}: !! entry {} does NOT match what they published before", a.n);
                            println!("   they said : {was}");
                            println!("   now say   : {}", a.digest);
                            println!("   Their journal changed under an entry they had already");
                            println!("   published. Both copies are kept in your anchors/ directory.");
                        }
                        anchor::Held::WentBackwards { held } => {
                            println!("{name}: !! head went backwards, {held} -> {}", a.n);
                        }
                    }
                }
                if stored == 0 && evidence == 0 {
                    println!("nothing new to record");
                }
            }
            AnchorCmd::Check { n, digest } => {
                let digest = digest.trim().to_ascii_lowercase();
                match journal::digest_at(n) {
                    Some(d) if d == digest => {
                        println!("entry {n} still matches the anchor they hold");
                        println!("  {d}");
                    }
                    Some(d) => {
                        println!("entry {n} DOES NOT MATCH the anchor they hold");
                        println!("  they hold : {digest}");
                        println!("  this file : {d}");
                        println!();
                        println!("This journal changed under an entry already published.");
                        return Err("the journal does not match that anchor".into());
                    }
                    None => {
                        println!("there is no entry {n} in this journal");
                        println!("  An entry that was deleted outright and one that never");
                        println!("  existed look the same from here. Neither is good news if");
                        println!("  somebody holds an anchor for it.");
                        return Err("no such entry".into());
                    }
                }
            }
            AnchorCmd::List => {
                let c = trust::Contacts::load();
                let peers = anchor::peers();
                if peers.is_empty() {
                    println!("no anchors held");
                    println!("  Nobody has sent you a journal head, so there is nothing");
                    println!("  here to check anything against. gage anchor send --to <name>");
                    println!("  publishes yours; they run gage anchor record.");
                }
                for p in peers {
                    // The directory is named by the SHAPED key, so the real
                    // key is found by matching the shape rather than stored
                    // a second time.
                    let real = c
                        .keys
                        .keys()
                        .find(|k| anchor::peer_dirname(k) == p)
                        .cloned();
                    let name = real
                        .as_deref()
                        .and_then(|k| c.name_for(k))
                        .unwrap_or("(not on your list)");
                    let anchors = real.as_deref().map(anchor::held).unwrap_or_default();
                    let bad = real.as_deref().map(anchor::contradictions).unwrap_or_default();
                    println!("{name}\t{} anchor(s)", anchors.len());
                    for a in &anchors {
                        println!("  entry {:<6} {} at {}", a.n, &a.digest[..16], a.at);
                    }
                    // Printed under the list rather than instead of it: the
                    // contradicting anchors are both above, and this says
                    // which pair to look at.
                    for (n, digests) in &bad {
                        println!("  !! entry {n} is held with {} different digests:", digests.len());
                        for d in digests {
                            println!("       {d}");
                        }
                        println!("     Their journal changed under an entry they had published.");
                    }
                }
                // Said every time, because it is the bound that governs what
                // any of this is worth.
                if let Some(h) = journal::head() {
                    println!();
                    println!("your own head is entry {} ({}…)", h.n, &h.digest[..16]);
                }
            }
        },
        Cmd::Agent(sub) => match sub {
            AgentCmd::List => {
                let agents = agentcfg::list();
                if agents.is_empty() {
                    println!("no agent identities yet");
                    println!("  gage agent new <name>   # or the Agents page in gage ui");
                } else {
                    for a in &agents {
                        println!("{}\t{}", a.name, a.key);
                        println!("  this key says : {}", a.fingerprint());
                        println!("  home          : {}", a.home.display());
                    }
                }
            }
            AgentCmd::New { name } => {
                let a = agentcfg::create(&name)?;
                println!("{}\t{}", a.name, a.key);
                println!("  this key says : {}", a.fingerprint());
                println!("  home          : {}", a.home.display());
                println!();
                println!("Point an MCP host at it:");
                println!("  {}", agentcfg::configs(&a)["claude_code"].as_str().unwrap_or(""));
            }
            AgentCmd::Remove { name, yes } => {
                // Deleting an identity key is the one act in gage that cannot
                // be undone, so the default is to ask. `--yes` exists because
                // the viewer and any script need a path that does not read
                // stdin, not because the question is a formality.
                if !yes {
                    print!(
                        "Delete {name}'s identity key and retire it from your list? [y/N] "
                    );
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut ans = String::new();
                    std::io::stdin().read_line(&mut ans)?;
                    if !matches!(ans.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                        return Err("nothing was removed".into());
                    }
                }
                let r = agentcfg::remove(&name)?;
                println!("removed {}", r.name);
                match &r.key {
                    Some(k) => println!("  key retired   : {k}"),
                    None => println!("  key retired   : none found to retire"),
                }
                if r.route_removed {
                    println!("  route removed : {}", r.name);
                }
                println!("  home deleted  : {}", r.home.display());
                println!();
                // gage never writes another application's config, so it has
                // nothing to un-write. Saying the line is the whole of what
                // it can honestly do here.
                println!("If an MCP host still points at it, remove it there too:");
                println!("  claude mcp remove gage");
            }
        },
        Cmd::Retire {
            name,
            compromised,
            all,
        } => {
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
                let keys: Vec<String> = c
                    .retired_keys_for(&name)
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect();
                c.mark_history_compromised(&name, &keys);
                c.save()?;
                println!(
                    "{name} has no key in service; condemned {} retired key(s)",
                    keys.len()
                );
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
            println!("  recorded for THIS gage home only -- another machine on the same");
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
                    println!(
                        "  bundles signed with those still read as attributable. A stolen key"
                    );
                    println!("  is not evidence its predecessor was stolen -- but if you think it");
                    println!("  was, re-run with --compromised --all.");
                }
            }
        }
        Cmd::Add {
            name,
            key,
            reinstate,
            same_machine,
        } => {
            for l in trust::add_contact(
                &name,
                &key,
                trust::AddOpts {
                    // A key off a web page or out of a chat window, which is
                    // what this command is for. Nobody compared anything, so
                    // nothing is recorded as confirmed and the output says
                    // which command to run once somebody has.
                    confirmed: None,
                    reinstate,
                    same_machine,
                    seq: state::LocalState::load().seq,
                },
            )? {
                println!("{l}");
            }
        }
        Cmd::Confirm { name, words } => {
            let mut c = trust::Contacts::load();
            let key = match c.key_for_name(&name) {
                Some(k) => k,
                None => {
                    return Err(match c.retired_by_name(&name) {
                        Some((_, r)) => format!(
                            "you retired the key you held for {name} on {}, so there is \
                             nothing live to confirm",
                            r.retired_at
                        ),
                        None => format!("no contact named {name}. `gage contacts` lists them."),
                    }
                    .into());
                }
            };
            // Printed before the words are asked for, never after: the
            // comparison is worth nothing if this screen shows the answer
            // first. It prints the LABEL, which is one pair and is already
            // in `gage contacts` as the way to tell entries apart.
            println!(
                "confirming {name} ({})",
                words::label(&key)
            );
            if c.box_keys.contains_key(&key) {
                println!("  On their machine:  gage fingerprint");
            } else {
                // No encryption key on file, so the value is over the signing
                // half alone and their machine must be asked for that one.
                // The wrong command here is the failure review found in the
                // viewer: an honest person compares two different values and
                // is told they do not match.
                println!("  On their machine:  gage fingerprint --signing-only");
                println!(
                    "  (you have no encryption key for {name}, so the words cover the \
                     signing key only)"
                );
            }
            let typed = if words.is_empty() {
                print!("  The four pairs they read out: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line
            } else {
                words.join(" ")
            };
            let seq = state::LocalState::load().seq;
            c.confirm(&key, &typed, "word-pairs typed back at a terminal", seq)?;
            c.save()?;
            println!();
            println!("confirmed {name}.");
            println!("  Bundles signed by this key now read SENDER VERIFIED.");
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
                    println!("  gage undecline <key> takes it back.");
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
                    println!("  it is NOT on your list. gage add <name> <key> does that.");
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
                         `gage whoami` token and add it first.",
                        r.retired_at,
                        if r.compromised { " as compromised" } else { "" }
                    ),
                    None => format!("no contact named {to}; gage add {} <key>", shell_word(&to)),
                }
                .into());
            };
            let Some(boxpub) = c.box_keys.get(&sign) else {
                return Err(format!(
                    "{to} has no encryption key on file. Get their current \
                     `gage whoami` token (signpub.boxpub) and re-add them."
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
            println!("  decryption proves nothing about the sender; run gage open to see the");
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
            to,
            subject,
            out,
            file,
            prompt,
            decision,
            memory,
            dir,
            allow_secrets,
            reply_to,
            r#type,
            allow_findings,
            lan,
            agent,
            model,
        } => {
            let targets = to.clone();
            let mut say = Vec::new();
            let m = send_bundle(
                SendArgs {
                    to,
                    subject,
                    out,
                    file,
                    prompt,
                    decision,
                    memory,
                    dir,
                    allow_secrets,
                    reply_to,
                    msg_type: r#type,
                    allow_findings,
                    lan,
                    agent,
                    model,
                    record_send: true,
                },
                &mut say,
            );
            for l in &say {
                println!("{l}");
            }
            let m = m?;
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
            id,
            text,
            file,
            prompt,
            decision,
            memory,
            dir,
            r#type,
            subject,
            allow_secrets,
            allow_findings,
            agent,
            model,
            out,
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
            let mut say = Vec::new();
            let r = send_bundle(
                SendArgs {
                    to: vec![t.to.clone()],
                    subject: subject.unwrap_or(t.subject),
                    out,
                    file,
                    prompt,
                    decision,
                    memory,
                    dir,
                    allow_secrets,
                    reply_to: Some(t.parent),
                    msg_type: r#type.unwrap_or(t.msg_type),
                    allow_findings,
                    lan: false,
                    agent,
                    model,
                    record_send: true,
                },
                &mut say,
            );
            let _ = std::fs::remove_dir_all(&tmp);
            for l in &say {
                println!("{l}");
            }
            r?;
        }
        Cmd::Inspect { dir } => {
            // Without this, inspecting a post-retirement arrival before any
            // other command had looked reported ARRIVAL UNRECORDED instead of
            // recording the arrival and rejecting it: a downgrade.
            observe_or_warn();
            let l = bundle::load(&dir)?;
            let m = &l.manifest;
            println!("id       : {}", one_line(&m.id));
            println!("subject  : {}", one_line(&m.subject));
            println!("trust    : {}", l.trust.label());
            println!(
                "from     : {} ({}…)",
                one_line(&m.from.handle),
                one_line(&m.from.key.chars().take(16).collect::<String>())
            );
            println!("forwarded: {}", if m.is_forwarded() { "yes" } else { "no" });
            println!("to       : {}", one_line(&m.to.join(", ")));
            for it in &m.items {
                println!(
                    "  {:?}\t{}\t{} bytes",
                    it.kind,
                    one_line(&it.path),
                    it.bytes
                );
            }
            if !l.tampered.is_empty() {
                println!("TAMPERED : {}", l.tampered.join(", "));
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Open { dir, reveal } => {
            // `gage open <id>` is what the other commands' output invites, so
            // resolve an id to its bundle rather than failing on a path that
            // was never meant to be one.
            let dir =
                match dir.to_str() {
                    Some(s) if !dir.exists() && manifest::id_is_safe(s) => {
                        match routes::find_by_id(&identity::home(), s) {
                            Some(p) => {
                                eprintln!("gage: {s} -> {}", p.display());
                                p
                            }
                            None => return Err(format!(
                                "no bundle {s} in this gage home. `gage inbox` lists what is here"
                            )
                            .into()),
                        }
                    }
                    _ => dir,
                };
            // A bundle you only ever `gage open` would otherwise never be
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
                     read milder than the truth. Re-run once no other gage process is \
                     writing."
                )
                .into()
            })?;
            let l = bundle::load(&dir)?;
            print!(
                "{}",
                open::render(&l, reveal).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
            );
            // Read state is set by rendering, not by listing: having seen a
            // subject line in an inbox is not having read the thing. It is
            // also bookkeeping, and bookkeeping must not turn a successful
            // read into a failure after the content has already been printed.
            if let Err(e) = state::LocalState::load().mark_read(&l.manifest.id) {
                eprintln!("gage: could not record this as read: {e}");
            }
            // Opening is the event that matters most to an auditor, because
            // it is the moment the contents entered an agent's context. Same
            // rule as above: bookkeeping must not turn a successful read into
            // a failure after the content has already been printed.
            if let Err(e) = journal::record(journal::Event::Opened, &l.dir) {
                eprintln!("gage: could not journal this read: {e}");
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
            let accepted = if all {
                routes::list(&routes::accepted_dir(&me))
            } else {
                vec![]
            };
            if json {
                let rows = routes::inbox_rows(all);
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
                    println!(
                        "\n* = unread.  gage accept <id> to stage it, gage reject <id> to drop it unread"
                    );
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
                eprintln!("gage: could not journal this acceptance: {e}");
            }
            println!("accepted {id}");
            println!("  gage open {}", dest.display());
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
                eprintln!("gage: could not journal this rejection: {e}");
            }
            std::fs::remove_dir_all(&p)?;
            println!("rejected {id}, deleted unread");
        }
        Cmd::Relay {
            bind,
            store,
            max_mailbox_mb,
            max_mailbox_msgs,
            max_store_mb,
            rate_per_min,
            max_mailboxes,
        } => {
            let root = store.unwrap_or_else(|| identity::home().join("relaystore"));
            // Said once, loudly, because the difference between a tailnet
            // relay and a public one is the whole of its threat model and
            // the bind address is where that decision is actually made.
            if !bind.starts_with("127.") && !bind.starts_with("100.") && !bind.starts_with("[::1]")
            {
                eprintln!(
                    "gage relay: binding {bind}, which may be reachable beyond your own \
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
                    mailboxes: max_mailboxes,
                },
            )?;
        }
        Cmd::Connect { relay, name } => {
            // Step 1: an identity, if there is not one. Never replaces an
            // existing one -- `init` refuses that, and so does this: a
            // command whose job is to get you started must not be the one
            // that silently throws away the key everything you have already
            // exchanged was built on.
            let id = match identity::Identity::load() {
                Ok(id) => {
                    println!("you already have an identity, so this kept it.");
                    id
                }
                Err(_) => {
                    let id = identity::Identity::create_named(name.as_deref())?;
                    println!("made you an identity in {}", identity::home().display());
                    id
                }
            };
            println!();

            // Step 2: the relay, if one was named.
            match &relay {
                Some(addr) => {
                    // Warned BEFORE registering, not after. A reviewer
                    // caught that the note came after `register_with_proof`,
                    // so the keys had already gone to an unverified,
                    // impersonable endpoint by the time the person was told
                    // the connection was unverified. "Said at the moment the
                    // choice is made" was said after the choice took effect.
                    if !addr.trim().to_ascii_lowercase().starts_with("https://") {
                        println!("  note: no https, so the connection to the relay is not");
                        println!("  verified. That is fine on a private network, and not");
                        println!("  fine across the internet.");
                    }
                    let body = serde_json::json!({
                        "sign_key": id.public_b64(), "box_key": id.box_public_b64() })
                    .to_string();
                    register_with_proof(addr, &id, &body)?;
                    remote::set_relay(addr)?;
                    println!("registered a mailbox on {addr}");
                    if false {
                        // Said here, not only in the docs, because this is
                        // the moment the choice is made.
                        // One println per output line. A wrapped literal has
                        // now shipped its own source indentation four times;
                        // the rule here is one line of source per line of output.
                        println!("  note: no https, so the connection to the relay is not");
                        println!("  verified. That is fine on a private network, and not");
                        println!("  fine across the internet.");
                    }
                }
                None => match remote::relay_addr() {
                    Some(a) => println!("your relay is {a}"),
                    None => {
                        println!("no relay yet. `gage connect <address>` registers one.");
                        println!("  Until then you can still exchange bundles by file, or");
                        println!("  on your own network with `gage lan`.");
                    }
                },
            }
            println!();

            // Step 3: the line to share, which is literally the command the
            // other person runs. The fingerprint goes with it so they have
            // something to compare against -- NOT so they can skip the
            // comparison, which the wording below has to earn.
            println!("Send this line to the person you want to exchange with:");
            println!();
            println!("    {}", id.add_line());
            println!();
            println!("Ask them for theirs, and run it. Then one thing is left, and it is");
            println!("the only part of this that cannot be done for you:");
            println!();
            println!(
                "    {}",
                words::fingerprint_of(&id.public_b64(), Some(&id.box_public_b64()))
            );
            println!();
            println!("  Those four word-pairs come from your key, so nobody picks their own.");
            println!("  When they add you, their screen shows four pairs for your key.");
            println!("  Read yours to them out loud -- on a call, in person, NOT in the");
            println!("  same place you sent the line above. If one word differs, it is not");
            println!("  your key, and somebody is between you.");
            println!();
            println!("  Doing this is what makes SENDER VERIFIED mean anything later. Skip");
            println!("  it and that verdict only ever says \"this is the key I was handed\".");
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
                remote::relay_addr().ok_or(
                    "no relay is set for this identity, so there is nowhere to push to.\n  \
                     If you have one:        gage join <address>\n  \
                     No relay? You do not need one -- the bundle is already built; \
                     hand that directory over yourself and they run \
                     `gage open <dir>`, or send it with `gage send --lan` if you are \
                     both on this network.",
                )?
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
                println!("  subject : {}", one_line(&loaded.manifest.subject));
                println!("  bundle  : {}", one_line(&loaded.manifest.id));
                for it in &loaded.manifest.items {
                    println!(
                        "  {:?}  {}  ({} bytes)",
                        it.kind,
                        one_line(it.path.strip_prefix("items/").unwrap_or(&it.path)),
                        it.bytes
                    );
                }
                return Err(
                    "not sent. Re-run with --yes once you have read the list above.".into(),
                );
            }
            if lan {
                for l in lan::hand_over(&dir, &to)? {
                    println!("{l}");
                }
                return Ok(ExitCode::SUCCESS);
            }
            let mut say = Vec::new();
            let r = push_core(&dir, &to, &addr, &mut say);
            for l in &say {
                println!("{l}");
            }
            r?;
        }
        Cmd::Pull { keep } => {
            pull_once(keep)?;
        }
        Cmd::Threads { mine } => {
            let st = state::LocalState::load();
            let me = identity::Identity::load()
                .map(|i| i.public_b64())
                .unwrap_or_default();
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
                println!("{}  {}  [{}]{flag}", t.id, t.subject, t.state.label());
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
            let me = identity::Identity::load()
                .map(|i| i.public_b64())
                .unwrap_or_default();
            let contacts = trust::Contacts::load();
            let ts = state::threads(all_manifests(), &st, &me);
            // A message id is what every other command hands you, so accept
            // one here rather than rejecting it: `gage threads` prints the
            // thread id, but nothing else does, and "no thread <id>" for an
            // id the tool can plainly resolve is a dead end. Dogfood, 15 Oct.
            let found = ts
                .iter()
                .find(|t| t.id == id || t.id.starts_with(&id))
                .or_else(|| ts.iter().find(|t| t.messages.iter().any(|m| m.id == id)));
            let Some(t) = found else {
                return Err(format!(
                    "no thread or message {id}. `gage threads` lists what is here"
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
                println!(
                    "!! {} correspondents here: {}",
                    t.others.len(),
                    who.join(", ")
                );
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
                let mark = if mine_msg || st.is_read(&m.id) {
                    " "
                } else {
                    "*"
                };
                let claim = if t.unverified.contains(&m.id) {
                    "  [thread claim unverified]"
                } else {
                    ""
                };
                println!(
                    "{mark} {}  {:<14} {}  {}{claim}",
                    m.created,
                    m.msg_type.label(),
                    who,
                    m.id
                );
                for it in &m.items {
                    println!(
                        "      {:?}  {}",
                        it.kind,
                        one_line(it.path.strip_prefix("items/").unwrap_or(&it.path))
                    );
                }
            }
            println!(
                "\nctx open <path> to read one, gage reply {} --text \"...\" to answer",
                t.id
            );
        }
        Cmd::Close { thread } => {
            let mut st = state::LocalState::load();
            st.close(&thread)?;
            println!("thread {thread} marked closed locally");
            println!("  (your view only -- the other side decides their own)");
        }
        Cmd::Watch {
            every,
            once,
            quiet,
            on_arrival,
            hook_timeout,
            auto_accept,
        } => {
            // The interval is a trade: shorter means you hear sooner, and it
            // also tells the relay operator more precisely when you are
            // active, since fetch timing is metadata they can see. Two
            // minutes is slow enough not to be a presence feed.
            let every = every.max(10);
            // Only the loop claims the home. `--once` is a single poll that
            // exits, not a service, and a record for it would make the app
            // skip starting the watcher it came to start.
            let _run = if once {
                None
            } else {
                note_if_already_serving("watch");
                runfile::RunFile::claim("watch")
            };
            // Latched for the life of the process, not reset each poll: a
            // journal that cannot be written is not a transient condition to
            // retry against, and retrying is what would make it unbounded.
            let mut journal_broken = false;
            loop {
                // Pull before counting, so arrivals are collected and then
                // announced once, rather than announced and collected later.
                if remote::relay_addr().is_some()
                    && let Err(e) = pull_inner(false, true, None)
                {
                    eprintln!("gage watch: pull failed: {e}");
                }
                // Date the arrivals before anything acts on them. Without
                // this, a watcher that auto-accepts wrote an `accepted`
                // entry with no `observed` entry before it -- the unattended
                // path, which is the one the journal exists for, was the one
                // leaving the thinnest record. `gage inbox` has always done
                // this; `watch` never did, because until now it only looked.
                if let Err(e) = routes::observe_inbox() {
                    eprintln!("gage watch: could not record arrivals: {e}");
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
                                        "gage watch: auto-accept is off for the rest of this \
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
        Cmd::Sent {
            since,
            to,
            json,
            last,
        } => {
            let cutoff = match since.as_deref() {
                None => None,
                Some(w) => Some(parse_since(w)?),
            };
            let all = journal::read();
            let rows: Vec<_> = all
                .iter()
                .filter(|e| e.event == journal::Event::Sent)
                .filter(|e| cutoff.as_deref().is_none_or(|c| e.at.as_str() >= c))
                .filter(|e| {
                    // Matches a handle as typed or a key, because after an
                    // incident you may have only one of the two: a name you
                    // remember, or a key from the other machine's inbox.
                    to.as_deref().is_none_or(|want| {
                        e.to.as_deref().unwrap_or(&[]).iter().any(|a| {
                            a.named == want || a.key.as_deref().is_some_and(|k| k.starts_with(want))
                        })
                    })
                })
                .collect();
            let shown = rows.len().saturating_sub(last);
            if json {
                for e in &rows[shown..] {
                    println!("{}", serde_json::to_string(e)?);
                }
                return Ok(ExitCode::SUCCESS);
            }
            if rows.is_empty() {
                println!("nothing sent{}", match &since {
                    Some(w) => format!(" in the last {w}"),
                    None => String::new(),
                });
                // An empty list is the one answer this command cannot give
                // honestly without saying what it covers: a machine that
                // never ran this version wrote no lines, and that looks
                // identical to a machine that sent nothing.
                println!();
                println!("  Sends are recorded from 0.3.2 onwards. Anything sent before");
                println!("  this version was upgraded leaves no line here, and an empty");
                println!("  list is not evidence that nothing was sent.");
                println!("  `gage anchor send` is also not listed -- see `gage sent --help`.");
                return Ok(ExitCode::SUCCESS);
            }
            for e in &rows[shown..] {
                let who: Vec<String> = e
                    .to
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|a| match (&a.key, a.routed) {
                        (Some(k), true) => format!("{} <{}>", a.named, &k[..k.len().min(10)]),
                        (Some(k), false) => {
                            format!("{} <{}> (no route)", a.named, &k[..k.len().min(10)])
                        }
                        (None, _) => format!("{} (not on your list)", a.named),
                    })
                    .collect();
                println!(
                    "{}  {}  {} item(s), {} bytes",
                    e.at,
                    e.bundle,
                    e.items.unwrap_or(0),
                    e.bytes.unwrap_or(0)
                );
                println!("      to {}", who.join(", "));
                println!("      {}", e.verdict);
            }
            println!();
            println!(
                "{} send(s). This is a record, not a control: it is written by the",
                rows.len()
            );
            println!("process that did the sending, into a file that process can rewrite.");
            println!("`gage anchor` is what makes a rewrite detectable -- and anchors");
            println!("themselves are not listed above, because journalling them would");
            println!("move the head they publish and break the comparison they exist for.");
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Journal {
            bundle,
            json,
            last,
            verify,
        } => {
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
                    println!(
                        "{} of {} entries are chained, and all of them check out",
                        r.chained, r.total
                    );
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
                println!(
                    "  {} is written as bundles arrive, are accepted,",
                    journal::path().display()
                );
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
                println!(
                    "{} entr{}",
                    rows.len(),
                    if rows.len() == 1 { "y" } else { "ies" }
                );
                println!("  hashes and verdicts only -- never a subject, a filename or a payload,");
                println!("  because a field a sender can fill is an injection against whatever");
                println!("  reads this next. Append-only by convention, not tamper-proof: a");
                println!("  process running as you can rewrite it.");
            }
        }
        Cmd::Ui { port } => {
            // Held for as long as the service runs, so something outside gage
            // can tell this home is already served. See src/runfile.rs for why
            // the record lives in the home and not in the process table.
            note_if_already_serving("ui");
            let _run = runfile::RunFile::claim("ui");
            ui::serve(port)?;
        }
        Cmd::Lan { port } => {
            note_if_already_serving("lan");
            let _run = runfile::RunFile::claim("lan");
            lan::run(port)?;
        }
        Cmd::Nearby { announce, r#for } => {
            let id = identity::Identity::load().ok();
            let secs = announce.unwrap_or(r#for).max(r#for);
            if let Some(n) = announce {
                let id = id
                    .as_ref()
                    .ok_or("gage init first -- announcing needs a key to sign with")?;
                println!("announcing for {n}s, then stopping. What leaves this machine:");
                println!(
                    "  handle \"{}\"  (a string you chose; nobody should trust it)",
                    id.handle
                );
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
                println!("nobody announcing. The other machine needs `gage nearby --announce`.");
                return Ok(ExitCode::SUCCESS);
            }
            let c = trust::Contacts::load();
            println!();
            for s in &seen {
                let known = match c.name_for(&s.sign) {
                    Some(n) => format!("on your list as {n}"),
                    None => "NOT on your list -- gage pair <name> to add it".to_string(),
                };
                println!("  \"{}\" at {}  ({known})", s.handle, s.addr.ip());
                println!(
                    "      says : {}",
                    words::fingerprint_of(&s.sign, Some(&s.boxpub))
                );
            }
            println!();
            println!("the handle is decoration. The words are the key, and the only thing");
            println!("worth comparing with the person sitting at the other machine.");
        }
        Cmd::Pair {
            name,
            r#as,
            confirm,
            r#for,
        } => {
            let id = identity::Identity::load()?;
            // If `gage lan` is running it has already written down who is
            // here, so pairing needs no second announce window and no timing
            // between two machines. Falling back to listening keeps `gage
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
                println!(
                    "listening for {}s. The other machine wants `gage lan`.",
                    r#for
                );
                lan::nearby(Some(&id), lan::LISTEN_PORT, r#for, false)?
            } else {
                live
            };
            let c = trust::Contacts::load();
            let fresh: Vec<_> = seen.iter().filter(|s| !c.knows(&s.sign)).collect();
            let cand = match fresh.len() {
                0 if seen.is_empty() => return Err("nobody announcing on this network".into()),
                0 => return Err("everyone announcing is already on your list".into()),
                1 => fresh[0],
                // No numbered menu, on purpose: picking "2" from a list is
                // exactly the step where a person stops reading, and the
                // whole value of this command is that they read. Narrow it
                // down by having one machine announce at a time.
                // More than one, so the NAME has to say which. `gage pair
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
                            println!(
                                "  {}  at {}  {}",
                                words::label(&s.sign),
                                s.addr.ip(),
                                words::fingerprint(&s.sign)
                            );
                        }
                        return Err(format!(
                            "{n} unpaired machines are here. Say which, by the word-pair \
                             above: gage pair {name} <word-pair>"
                        )
                        .into());
                    }
                }
            };
            // Both halves: the LAN announcement carries the encryption key
            // too, and confirming only the signing half is what let an
            // attacker substitute the key mail gets sealed to.
            let fp = words::fingerprint_of(&cand.sign, Some(&cand.boxpub));
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
            // Only the typed form records a confirmation. A `y` next to the
            // words printed on this screen is the person's assertion that
            // they compared them, and this machine has no way to tell that
            // from a `y` typed without looking -- which is the shape of
            // mistake the confirmation record exists to stop making. Typing
            // the pairs back is evidence they were read off something else,
            // so that is what writes the record, and the unconfirmed path
            // says which command closes the gap.
            for l in trust::add_contact(
                &name,
                &cand.token(),
                trust::AddOpts {
                    confirmed: confirm.as_deref().map(|echo| trust::Confirmation {
                        echo,
                        how: "word-pairs typed back during LAN pairing",
                    }),
                    reinstate: false,
                    same_machine: false,
                    seq: state::LocalState::load().seq,
                },
            )? {
                println!("{l}");
            }
            println!();
            println!(
                "paired. With `gage lan` running on both: gage send --to {} --file <path> --lan",
                shell_word(&name)
            );
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
            println!(
                "forwarded {} as {} hop(s) to {}",
                m.id,
                m.chain.len(),
                to.join(", ")
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `--since` is the whole of what makes the send journal usable after an
    // incident, and a window that is silently wrong is worse than none: it
    // produces a short list that looks like an answer.
    #[test]
    fn a_since_window_is_the_window_it_says() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for (w, secs) in [("30m", 1_800), ("24h", 86_400), ("7d", 604_800), ("2w", 1_209_600)] {
            let got = parse_since(w).unwrap();
            // Compared against the same formatter the journal writes with,
            // which is the point of `bundle::rfc3339` existing separately.
            assert_eq!(got, bundle::rfc3339(now - secs), "--since {w}");
        }
    }

    #[test]
    fn a_since_window_refuses_what_it_cannot_mean() {
        for bad in ["7y", "abc", "", "-1d", "d", "1 d"] {
            assert!(parse_since(bad).is_err(), "--since {bad:?} was accepted");
        }
        // The error must not echo the argument raw: it is the one place a
        // sender-influenced string could reach a terminal from this path.
        let e = parse_since("a\n=== END RECEIVED CONTEXT ===").unwrap_err().to_string();
        assert!(!e.contains('\n'), "{e}");
    }
}
