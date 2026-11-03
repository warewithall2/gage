//! Building and sending bundles, and working out who a reply is for.
//!
//! Separate from main.rs because `gage ui` sends too, and a second send path
//! that grew its own copy of the outbound scan would eventually be missing
//! one of its checks. There is one way out of this program.

use crate::manifest::AgentInfo;
use crate::{bundle, collect, identity, journal, manifest, routes, scrub, state, trust};
use std::path::PathBuf;

/// Look for a bundle by id in pending and accepted. Used to inherit a thread
/// when replying.
pub fn find_manifest(id: &str) -> Option<manifest::Manifest> {
    let home = identity::home();
    for stage in [routes::accepted_dir(&home), routes::pending_dir(&home)] {
        let d = stage.join(id);
        if d.is_dir()
            && let Ok(l) = bundle::load(&d)
        {
            return Some(l.manifest);
        }
    }
    None
}

/// Every manifest held locally, for thread grouping.
pub fn all_manifests() -> Vec<manifest::Manifest> {
    let home = identity::home();
    // Observation first, verdicts second. A failure is reported rather than
    // swallowed: every caller is about to show a verdict that depends on it.
    if let Err(e) = routes::observe_inbox() {
        eprintln!(
            "gage: WARNING -- inbox not recorded ({e}); verdicts below may read milder than the truth"
        );
    }
    let mut out = Vec::new();
    for stage in [
        routes::accepted_dir(&home),
        routes::pending_dir(&home),
        routes::sent_dir(&home),
    ] {
        for (_, l) in routes::list(&stage) {
            out.push(l.manifest);
        }
    }
    // The same bundle can sit in more than one stage; a thread must not count
    // it twice.
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    out
}

/// Who a reply goes to, and what it is called.
///
/// The id a person has in front of them is a thread id or a message id, and
/// which one it is should not be their problem. The recipient is worked out
/// from the key that signed the message being answered -- not from its
/// `from.handle`, which is text the sender chose, and not from the `to` list,
/// which is also theirs.
pub struct ReplyTarget {
    pub parent: String,
    pub to: String,
    pub msg_type: String,
    pub subject: String,
}

/// Refuse an `--out` that points inside the directories this machine uses to
/// record what ARRIVED and what it sent.
///
/// Checked lexically rather than by canonicalising, because the target
/// usually does not exist yet, and `..` is resolved first so that
/// `inbox/../inbox/accepted` is the same answer as the direct path.
///
/// `why` completes the refusal, because the two callers would be forging
/// different things. `send --out` would manufacture the arrival of a bundle
/// this machine authored. `unseal --out` would manufacture the ACCEPT of one
/// somebody really did send -- milder, since the signature is genuine, but it
/// is still the gate that exists so that crossing it is an act a human
/// performed. Neither has a legitimate use now that `unseal` with no `--out`
/// receives properly.
pub fn refuse_out_in_records(
    out: &std::path::Path,
    why: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = identity::home();
    let abs = if out.is_absolute() {
        out.to_path_buf()
    } else {
        std::env::current_dir()?.join(out)
    };
    let mut norm = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                norm.pop();
            }
            std::path::Component::CurDir => {}
            other => norm.push(other),
        }
    }
    for reserved in ["inbox", "sent", "outbox"] {
        if norm.starts_with(home.join(reserved)) {
            return Err(format!(
                "--out may not write inside {}: that is where this machine records \
                 what ARRIVED and what it sent. {why}",
                home.join(reserved).display()
            )
            .into());
        }
    }
    Ok(())
}

pub fn resolve_reply(id: &str) -> Result<ReplyTarget, Box<dyn std::error::Error>> {
    let me = identity::Identity::load()?.public_b64();
    let st = state::LocalState::load();
    let ts = state::threads(all_manifests(), &st, &me);

    // A message id wins over a thread id: naming one message is the more
    // specific thing to have typed.
    let by_msg: Vec<(&state::Thread, &manifest::Manifest)> = ts
        .iter()
        .flat_map(|t| t.messages.iter().map(move |m| (t, m)))
        .filter(|(_, m)| m.id.starts_with(id))
        .collect();
    let (thread, parent) = if !by_msg.is_empty() {
        if by_msg.len() > 1 {
            // Refuse rather than pick. A prefix matching two messages that
            // silently resolved to one of them would put a reply in the wrong
            // conversation, and nothing in the output would say so.
            let ids: Vec<&str> = by_msg.iter().map(|(_, m)| m.id.as_str()).collect();
            return Err(format!(
                "{id} matches {} messages: {}. Use more characters.",
                ids.len(),
                ids.join(", ")
            )
            .into());
        }
        let (t, m) = by_msg[0];
        (t, m.clone())
    } else {
        let hits: Vec<&state::Thread> = ts.iter().filter(|t| t.id.starts_with(id)).collect();
        let t = match hits.len() {
            0 => return Err(format!("no thread or message starting with {id}").into()),
            1 => hits[0],
            _ => {
                let ids: Vec<&str> = hits.iter().map(|t| t.id.as_str()).collect();
                return Err(
                    format!("{id} matches {} threads: {}", ids.len(), ids.join(", ")).into(),
                );
            }
        };
        // More than one correspondent means naming the thread does not name a
        // recipient. This is the whole fix: with exactly one other party there
        // is no redirect to perform, verified claim or not, and with two there
        // is no way to guess which one the person meant. Picking the newest looks helpful and is how a grafted
        // bundle steals a reply: anyone who has seen one message of a
        // conversation can post into it and become "the newest message that is
        // not yours". So the ambiguity is handed back rather than guessed.
        if t.others.len() > 1 {
            let contacts = trust::Contacts::load();
            let who: Vec<String> = t
                .others
                .iter()
                .map(|k| match contacts.name_any(k) {
                    Some(n) => format!("{n} ({}…)", k.chars().take(10).collect::<String>()),
                    None => format!(
                        "an unlisted key ({}…)",
                        k.chars().take(10).collect::<String>()
                    ),
                })
                .collect();
            let newest: Vec<String> = t
                .messages
                .iter()
                .rev()
                .filter(|m| m.from.key != me)
                .take(2)
                .map(|m| format!("{} from {}", m.id, m.from.handle))
                .collect();
            return Err(format!(
                "thread {} has {} correspondents ({}), so naming the thread does not \
                 name a recipient. Reply to one MESSAGE instead:\n  {}",
                t.id,
                t.others.len(),
                who.join(", "),
                newest.join("\n  ")
            )
            .into());
        }
        // The newest message that is not yours. Replying to your own last
        // message is a follow-up, not a reply, and guessing which it was
        // would get the recipient from a message you wrote.
        let parent = t
            .messages
            .iter()
            .rev()
            .find(|m| m.from.key != me)
            .ok_or_else(|| {
                format!(
                    "every message in thread {} is your own, so there is nobody to reply \
                     to. Name a message id, or use gage send --reply-to.",
                    t.id
                )
            })?
            .clone();
        (t, parent)
    };

    // Checked for BOTH paths. The thread path looks for a message that is not
    // yours; the message path takes the id you typed, and naming your own
    // message used to fall through to the contact lookup and report "that key
    // is not on your list" -- which is true, your own key is not in your own
    // contacts, and completely misleading.
    if parent.from.key == me {
        return Err(format!(
            "{} is your own message, so there is nobody to reply to. Name the \
             message you are answering, or use gage send --reply-to.",
            parent.id
        )
        .into());
    }

    let contacts = trust::Contacts::load();
    let to = match contacts.name_for(&parent.from.key) {
        Some(n) => n.to_string(),
        None => {
            // Both refusals name the key rather than the handle, because the
            // handle is the part that cannot be trusted here.
            let short: String = parent.from.key.chars().take(16).collect();
            return Err(match contacts.retired_record(&parent.from.key) {
                Some(r) => format!(
                    "that message was signed with a key you retired on {} ({short}…). \
                     Get their current key before replying.",
                    r.retired_at
                ),
                None => format!(
                    "the key that signed that message is not on your list ({short}…). It \
                     claims the name {:?}, which proves nothing. Add them first.",
                    parent.from.handle
                ),
            }
            .into());
        }
    };

    // A reply to a question is an answer; a reply to anything else is a
    // share. Overridable, because an answer that raises a new question is a
    // real thing and only the person sending it knows which it is.
    let msg_type = if parent.msg_type.expects_reply() {
        "answer"
    } else {
        "share"
    }
    .to_string();
    let subject = if thread.subject.to_ascii_lowercase().starts_with("re:") {
        thread.subject.clone()
    } else {
        format!("re: {}", thread.subject)
    };
    Ok(ReplyTarget {
        parent: parent.id.clone(),
        to,
        msg_type,
        subject,
    })
}

/// Everything `send` does, as a function, because `reply` does all of it too.
///
/// Duplicating it would have been the obvious move and the wrong one: the
/// outbound scan, the skip reporting and the secret deny list live in here,
/// and a second send path that grew its own copy would eventually be missing
/// one of them. A reply is a send with its recipient and thread worked out.
pub struct SendArgs {
    pub to: Vec<String>,
    pub subject: String,
    pub out: Option<PathBuf>,
    pub file: Vec<PathBuf>,
    pub prompt: Vec<PathBuf>,
    pub decision: Vec<PathBuf>,
    pub memory: Vec<PathBuf>,
    pub dir: Vec<PathBuf>,
    pub allow_secrets: bool,
    pub reply_to: Option<String>,
    pub msg_type: String,
    pub allow_findings: bool,
    /// Delivery is being handled over the local network by the caller, so the
    /// "no local route, move it yourself" advice would be wrong rather than
    /// merely noisy -- it tells a person to do a step that is already done.
    pub lan: bool,
    pub agent: Option<String>,
    pub model: Option<String>,
    /// Write a `Sent` line to the journal. True for everything a person or
    /// an agent sends; false for `gage anchor send`, and only for that.
    ///
    /// The reason is specific and was found by the suite rather than
    /// reasoned out. An anchor publishes the digest of the journal's current
    /// head. Journaling the anchor's own send appends an entry, so the head
    /// moves the instant it is published, and two anchors can never name the
    /// same index again -- which is exactly how `anchor record` detects a
    /// contradiction: the same entry, published twice, with two digests. Four
    /// checks went red and none of them was a flaky test.
    ///
    /// So anchors are excluded, and the exclusion is STATED in `gage sent`
    /// rather than left as a hole where a careful reader would look. What is
    /// being given up is small and bounded: an anchor carries a digest of
    /// this machine's own journal, no user content, and goes only to a
    /// contact already on the list.
    pub record_send: bool,
    /// How long this should stay current, as a duration: `24h`, `7d`, `30m`.
    /// Resolved against this machine's clock at build time, so what ships is
    /// an absolute instant and not a countdown a recipient has to interpret.
    pub ttl: Option<String>,
    /// The expiry as an absolute RFC 3339 timestamp, for a sender who has a
    /// deadline rather than a window. Canonicalised before it is signed.
    pub expires: Option<String>,
    /// The task or run label. Inherited from the thread on a reply unless the
    /// caller passes one.
    pub context: Option<String>,
}

/// Resolve `--ttl` / `--expires` into the one absolute UTC timestamp that
/// goes into the manifest.
///
/// Both forms end up here, and the result is always formatted by
/// `bundle::rfc3339` -- the same function that writes `created`. That is not
/// tidiness: an expiry a sender typed as `+02:00` is a correct RFC 3339
/// timestamp that no 0.3.5 reader will ever see, and canonicalising it at
/// send time means the bytes a recipient compares are in the form this tree
/// produces everywhere else. The parse stays permissive on the way in, so a
/// sender who types an offset is not refused -- they are normalised.
///
/// Giving both is refused rather than resolved by precedence. They are two
/// ways of saying one thing, and a silent winner is how a sender comes to
/// believe they set a deadline they did not set.
pub fn resolve_expiry(
    ttl: Option<&str>,
    expires: Option<&str>,
    now: i64,
) -> Result<Option<String>, String> {
    match (ttl, expires) {
        (Some(_), Some(_)) => Err(
            "--ttl and --expires say the same thing two ways; pass one. \
             --ttl 24h is a window from now, --expires is an instant."
                .into(),
        ),
        (None, None) => Ok(None),
        (Some(t), None) => {
            let secs = parse_duration(t)?;
            // Checked, and then bounded. `--ttl` is a number a sender types,
            // so the only thing standing between `99999999999999w` and a
            // serialized expiry is this line: unchecked, it wrapped in
            // release builds -- signing a deadline that was not the one
            // asked for, possibly already past -- and panicked in debug.
            let at = now
                .checked_add(secs)
                .filter(|at| *at <= MAX_EXPIRY)
                .ok_or_else(|| too_far(t))?;
            Ok(Some(crate::bundle::rfc3339(at)))
        }
        (None, Some(e)) => {
            let at = crate::bundle::parse_rfc3339(e).ok_or_else(|| {
                format!(
                    "--expires wants an RFC 3339 timestamp like 2026-11-09T09:00:00Z, not {:?}. \
                     A zone is required: a bare local time is hours away from where you meant it.",
                    manifest::one_line(e)
                )
            })?;
            // Refused, not warned. A bundle that is expired before it is
            // built cannot be opened by anyone, so building it is never what
            // the sender wanted, and the only place this can be said while
            // it is still fixable is here.
            if at <= now {
                return Err(format!(
                    "--expires {} is already past; the bundle would be built expired and \
                     its recipient could not open it.",
                    manifest::one_line(e)
                ));
            }
            // And bounded, on the normalized instant rather than on the
            // digits the sender typed. The grammar's four-digit year is not
            // the ceiling it looks like: `parse_rfc3339` subtracts the zone
            // offset, so `9999-12-31T23:59:59-23:59` is an in-grammar input
            // whose UTC instant is in the year 10000. `rfc3339` formats the
            // year with a minimum width of four digits, not a maximum, so
            // that instant is written out as `10000-01-01T23:58:59Z` -- a
            // signed expiry this tree's own parser reads back as nothing,
            // which makes a recipient withhold the payload for a bundle
            // whose sender did nothing wrong but pick a zone.
            //
            // So the same ceiling the `--ttl` path bounds against is applied
            // here, after normalization and before formatting.
            if at > MAX_EXPIRY {
                return Err(too_far_expires(e));
            }
            Ok(Some(crate::bundle::rfc3339(at)))
        }
    }
}

/// The last instant `bundle::rfc3339` can write: 9999-12-31T23:59:59Z.
///
/// Not an arbitrary ceiling. `rfc3339` formats the year as four digits and
/// walks the years one at a time from 1970, so a deadline past this point is
/// a timestamp this tree cannot write and would spend a geological age trying
/// to -- a hang rather than a wrong answer, which is why a merely-checked
/// multiplication is not enough on its own here.
const MAX_EXPIRY: i64 = 253_402_300_799;

/// The one refusal both overflow paths reach.
fn too_far(w: &str) -> String {
    format!(
        "--ttl {:?} is too far out; gage cannot write an expiry past \
         9999-12-31T23:59:59Z. Pass a window a recipient could actually be \
         inside, in m, h, d or w.",
        manifest::one_line(w)
    )
}

/// The refusal for an `--expires` whose normalized instant is past the bound.
///
/// Separate from `too_far` because it is reached by a different mistake and
/// has a different fix. A `--ttl` past the bound is a window nobody could be
/// inside; an `--expires` past it is usually a timestamp whose zone offset
/// carried it over, so the sender is told what their input normalizes to
/// rather than being told to pick a shorter window they did not ask for.
fn too_far_expires(w: &str) -> String {
    format!(
        "--expires {:?} is past 9999-12-31T23:59:59Z once its zone offset is \
         applied, and gage cannot write an expiry beyond that. Pass an \
         instant inside that range.",
        manifest::one_line(w)
    )
}

/// `24h`, `7d`, `30m`, `2w` as seconds.
///
/// Deliberately the same four units, the same shape and the same refusals as
/// `--since` in `main.rs`: one duration grammar in this tool, so a person who
/// has learned `7d` once has learned it everywhere. Zero is refused for the
/// same reason a past `--expires` is.
pub fn parse_duration(w: &str) -> Result<i64, String> {
    let w = w.trim();
    let (n, unit) = w.split_at(w.len().saturating_sub(1));
    let n: i64 = n.parse().map_err(|_| {
        format!(
            "--ttl wants a duration like 24h, 7d or 30m, not {:?}",
            manifest::one_line(w)
        )
    })?;
    if n <= 0 {
        return Err(
            "--ttl must be positive; a bundle that expires now or earlier \
             cannot be opened by anybody"
                .into(),
        );
    }
    // Checked: the unit is a multiplier of up to 604_800, so an `n` well
    // inside i64 can leave the type on the way out. The unknown-unit arm
    // comes first in the reading order a sender needs, but the refusal for
    // an in-grammar number that cannot be a duration is just as much a
    // refusal -- never a wrap, and never a debug-build panic.
    let per = match unit {
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => {
            return Err(format!(
                "unknown unit {:?} in --ttl; use m, h, d or w",
                manifest::one_line(unit)
            ));
        }
    };
    n.checked_mul(per)
        .filter(|secs| *secs <= MAX_EXPIRY)
        .ok_or_else(|| too_far(w))
}

/// Build and deliver a bundle.
///
/// Human-facing lines are pushed into `say` rather than printed. Every caller
/// prints them and still does, in the same place, so stdout is unchanged --
/// the point is that `gage mcp` can hand the same lines to an agent as data,
/// because on a stdio transport the server's own stdout IS the JSON-RPC
/// channel and printing to it would corrupt the protocol.
///
/// The sink belongs to the caller, not the return value, because the skip
/// report has to survive a later failure: "all 2 item(s) were skipped (listed
/// above)" is only true if the caller printed the list before the error. A
/// `Result` carrying the lines drops them on exactly the path that needs
/// them most.
pub fn send_bundle(
    a: SendArgs,
    say: &mut Vec<String>,
) -> Result<manifest::Manifest, Box<dyn std::error::Error>> {
    let SendArgs {
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
        msg_type: type_in,
        allow_findings,
        lan,
        agent,
        model,
        record_send,
        ttl,
        expires,
        context,
    } = a;
    let r#type = type_in;

    let id = identity::Identity::load()?;
    let c = collect::collect(&file, &prompt, &decision, &memory, &dir, allow_secrets)?;
    // Skips are printed BEFORE the bundle is built, so a sender sees
    // what is not going out while they can still change their mind.
    if !c.skipped_secret.is_empty() {
        say.push("skipped (look like secrets, --allow-secrets to include):".to_string());
        for f in &c.skipped_secret {
            say.push(format!("  {f}"));
        }
    }
    if !c.skipped_link.is_empty() {
        say.push("skipped (symlinks -- a link's name says nothing about its target):".to_string());
        for f in &c.skipped_link {
            say.push(format!("  {f}"));
        }
    }
    if !c.skipped_big.is_empty() {
        say.push("skipped (over the per-item size limit):".to_string());
        for f in &c.skipped_big {
            say.push(format!("  {f}"));
        }
    }
    if !c.skipped_dir.is_empty() {
        let mut d = c.skipped_dir.clone();
        d.sort();
        d.dedup();
        say.push(format!("skipped build/cache dirs: {}", d.join(", ")));
    }
    let routes = routes::Routes::load();
    let skipped = c.skipped_secret.len() + c.skipped_big.len() + c.skipped_link.len();
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
    // Outbound CONTENT scan. The filename deny list above catches
    // .env; it says nothing about an innocent notes.md that quotes a
    // customer address or still has a bearer token in it. Refuse
    // rather than warn: on an outbound path a warning arrives after
    // the bundle exists, and for a remote recipient after it has
    // gone.
    let findings = scrub::scan(&specs);
    if !findings.is_empty() {
        // The findings go in the ERROR rather than to stdout, so that
        // every caller gets them. The viewer's send button reported a
        // bare "refusing to build this bundle" with the reason
        // printed in a terminal the person was not looking at, which
        // is a refusal they cannot act on.
        let mut lines = vec![format!(
            "outbound scan found {} item(s) that should not leave:",
            findings.len()
        )];
        for f in &findings {
            lines.push(format!(
                "  {}:{}  [{}]  {}",
                f.path, f.line, f.rule, f.preview
            ));
        }
        if !allow_findings {
            // The path is COMPUTED, not written out. This line said
            // `~/.ctx/scrub.json` long after the home moved to `~/.gage`, so
            // the one piece of advice a person needed in order to act on a
            // refusal sent them to a file nothing reads.
            lines.push(format!(
                "refusing to build this bundle. Fix the files, add a rule to {}, \
                 or pass --allow-findings if they are false positives.",
                crate::scrub::policy_path().display()
            ));
            return Err(lines.join("\n").into());
        }
        for l in &lines {
            say.push(l.to_string());
        }
        say.push("  --allow-findings given: sending anyway".to_string());
    }

    let msg_type = manifest::MsgType::parse(&r#type).ok_or_else(|| {
        format!(
            "unknown --type {type_in:?}; use share, question, answer, review-request or ack",
            type_in = r#type
        )
    })?;
    // A reply inherits its parent's thread. Looked up locally rather
    // than walked at read time: over a relay you may hold only part
    // of a thread, and a chain you cannot walk is a thread you cannot
    // group. Falling back to the parent id still groups the pair.
    // The parent is looked up once and used for both the thread and the
    // inherited context. Two lookups would be two chances for them to come
    // from different messages.
    let parent = reply_to.as_ref().and_then(|rid| find_manifest(rid));
    let thread = reply_to.as_ref().map(|rid| match &parent {
        Some(m) => m.thread_id().to_string(),
        None => rid.clone(),
    });
    // A reply inherits the thread's context, derived at the same point and
    // from the same message as the thread id. An exchange about one run is
    // about that run in both directions, and a reply that dropped the label
    // would be a reply the other side could not match against its own run --
    // which is the comparison the field exists for.
    //
    // An explicit `--context` wins, and passing a blank one clears it: a
    // sender who has moved on from the run their correspondent was in has to
    // be able to say so.
    let context = match context {
        Some(c) if c.trim().is_empty() => None,
        Some(c) => Some(c),
        None => parent.as_ref().and_then(|m| m.context.clone()),
    };
    let expires = resolve_expiry(
        ttl.as_deref(),
        expires.as_deref(),
        crate::bundle::now_secs(),
    )?;
    let ag = agent.map(|name| AgentInfo { name, model });
    // Built once into a staging dir, then delivered to each routed
    // recipient. Building per-recipient would give one payload a
    // different content id for every person who received it.
    // `--out` must not name somewhere inside this machine's own inbox.
    //
    // Found by review: `gage_send out=<home>/inbox/accepted/<anything>` wrote
    // a bundle the CALLER authored straight into the accepted inbox, where
    // every reader treats it as mail that arrived, was accepted and crossed
    // the gate. An agent could manufacture its own received context, with its
    // own signature on it, and `gage inbox --all` would list it beside real
    // arrivals. Nothing about the signature is forged; what is forged is the
    // *arrival*, which is a local fact this program is the only witness to.
    //
    // Checked lexically rather than by canonicalising, because the target
    // usually does not exist yet, and `..` is resolved first so that
    // `inbox/../inbox/accepted` is the same answer as the direct path.
    if let Some(p) = &out {
        refuse_out_in_records(
            p,
            "A bundle you built is not an arrival, and putting it there would make it \
             indistinguishable from one. Write it anywhere else and hand it over, or drop \
             --out and let gage deliver it.",
        )?;
    }
    let stage = out
        .clone()
        .unwrap_or_else(|| identity::home().join(format!("outbox/{}", std::process::id())));
    let m = bundle::create(
        &stage, &id, &subject, &to, ag, reply_to, thread, msg_type, expires, context, &specs,
    )?;
    // Keep our own copy before delivering anywhere.
    let sent = routes::sent_dir(&identity::home()).join(&m.id);
    if !sent.exists() {
        if let Some(parent) = sent.parent() {
            std::fs::create_dir_all(parent)?;
        }
        routes::deliver(&stage, &sent)?;
    }
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
    // The send journal. Here rather than in each caller for the same reason
    // the outbound scan is here: a second send path that grew its own copy
    // would eventually be missing it, and a log with a hole in it is worse
    // than no log, because the hole is invisible.
    //
    // It is written AFTER delivery, so a line means the bundle was built,
    // signed and placed -- not merely attempted. The cost of that ordering is
    // the crash window: a process that dies between `deliver` and this append
    // has sent something it did not record. Recording first would invert the
    // lie rather than remove it, and claiming a send that did not happen is
    // the worse of the two for a log whose whole purpose is answering "what
    // left".
    //
    // A failure to write it does NOT fail the send. The bundle has already
    // gone; returning an error here would tell the caller it did not, which
    // is a worse record than a missing line. It is said out loud instead.
    if record_send {
        let contacts = trust::Contacts::load();
        let addressees: Vec<journal::Addressee> = to
            .iter()
            .map(|who| journal::Addressee {
                named: who.clone(),
                key: contacts.key_for_name(who),
                routed: routes.home_of(who).is_some(),
            })
            .collect();
        let manifest_bytes = std::fs::read(sent.join("manifest.json"))
            .or_else(|_| std::fs::read(stage.join("manifest.json")))
            .unwrap_or_default();
        if let Err(e) = journal::record_sent(&m, &manifest_bytes, addressees) {
            say.push(format!(
                "  warning: the bundle went but the send journal did not record it: {e}"
            ));
        }
    }
    say.push(format!(
        "bundle {} [{}] -- {} item(s), {} bytes, signed by {}",
        m.id,
        m.msg_type.label(),
        m.items.len(),
        m.total_bytes(),
        id.handle
    ));
    if m.memory_count() > 0 {
        say.push(format!(
            "  {} MEMORY item(s): these persist in whoever accepts them",
            m.memory_count()
        ));
    }
    // Echoed back because they are the two fields a sender can get wrong in
    // a way nothing else will tell them about: a `--ttl` typed as `7h` when
    // `7d` was meant builds a bundle that works now and is refused on Monday.
    if let Some(e) = &m.expires {
        say.push(format!(
            "  expires {e} -- after that the recipient's gage withholds the payload"
        ));
    }
    if let Some(c) = &m.context {
        say.push(format!(
            "  context {:?} -- shown to the recipient to compare with the run they are in",
            manifest::safe_display(c, 160)
        ));
    }
    for d in &delivered {
        say.push(format!("  delivered {d}"));
    }
    let unrouted: Vec<String> = to
        .iter()
        .filter(|w| routes.home_of(w).is_none())
        .cloned()
        .collect();
    if !unrouted.is_empty() && !lan {
        say.push(format!("  no local route for: {}", unrouted.join(", ")));
        say.push(format!(
            "  bundle is at {} -- move it yourself, or",
            stage.display()
        ));
        say.push("  gage route <handle> <their-gage-home> to deliver automatically".to_string());
    }

    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ttl_becomes_an_absolute_instant_in_the_form_this_tree_writes() {
        // The window is resolved at build time rather than shipped as a
        // countdown, because a countdown would have to be interpreted
        // against the RECIPIENT's clock -- and then "7d" means a different
        // instant for every reader, including a relay that held it a while.
        let now = 1_793_000_000;
        let out = resolve_expiry(Some("7d"), None, now).unwrap().unwrap();
        assert_eq!(out, crate::bundle::rfc3339(now + 7 * 86_400));
        // And it round-trips through the parser the receiver uses.
        assert_eq!(
            crate::bundle::parse_rfc3339(&out),
            Some(now + 7 * 86_400),
            "{out}"
        );
        for (w, secs) in [("30m", 1_800), ("24h", 86_400), ("2w", 1_209_600)] {
            assert_eq!(parse_duration(w), Ok(secs), "{w}");
        }
    }

    #[test]
    fn an_absolute_expiry_is_canonicalised_rather_than_passed_through() {
        // A sender may legitimately type an offset. What a recipient compares
        // is then in the same form everything else in this tree writes, so a
        // reader eyeballing the manifest is not comparing two notations.
        let now = 1_793_000_000;
        let at = crate::bundle::rfc3339(now + 3_600);
        let typed = at.replace('Z', "+00:00");
        assert_eq!(
            resolve_expiry(None, Some(&typed), now).unwrap(),
            Some(at.clone())
        );
        assert_eq!(resolve_expiry(None, Some(&at), now).unwrap(), Some(at));
    }

    #[test]
    fn the_ways_of_getting_an_expiry_wrong_are_refused_at_send_time() {
        let now = 1_793_000_000;
        // Both at once. Two ways of saying one thing, and a silent winner is
        // how a sender comes to believe they set a deadline they did not set.
        assert!(resolve_expiry(Some("7d"), Some("2026-11-09T09:00:00Z"), now).is_err());
        // Already past: the bundle would be built unopenable, and this is
        // the last moment anybody can be told while it is still fixable.
        assert!(resolve_expiry(None, Some(&crate::bundle::rfc3339(now - 1)), now).is_err());
        assert!(resolve_expiry(None, Some(&crate::bundle::rfc3339(now)), now).is_err());
        // Not a timestamp, no zone, not a duration, zero, negative, bad unit.
        assert!(resolve_expiry(None, Some("next tuesday"), now).is_err());
        assert!(resolve_expiry(None, Some("2026-11-09T09:00:00"), now).is_err());
        for bad in ["7y", "abc", "", "0d", "-1d", "d", "1 d"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be refused");
        }
        // Nothing asked for is still nothing: no default TTL, ever. A
        // default would silently expire mail that store-and-forward is
        // entitled to hold.
        assert_eq!(resolve_expiry(None, None, now), Ok(None));
    }

    #[test]
    fn a_ttl_too_large_to_mean_anything_is_refused_rather_than_wrapped() {
        let now = 1_793_000_000;
        // In the grammar, parses as an i64, and is not a duration. Unchecked,
        // the multiply wrapped in release builds -- signing a deadline that
        // was not the one asked for, and for some inputs one already past --
        // and panicked in debug. Every unit, because each has its own
        // multiplier and a fix applied to one arm is a fix applied to one
        // arm.
        for w in [
            "9223372036854775807m",
            "9223372036854775807h",
            "9223372036854775807d",
            "9223372036854775807w",
            "153722867280912930w",
            "99999999999999w",
            "1000000000000000000d",
        ] {
            let e = parse_duration(w).unwrap_err();
            assert!(e.contains("too far out"), "{w}: {e}");
            // And the refusal reaches the CLI through the path `gage send`
            // actually takes, not only through the helper.
            let r = resolve_expiry(Some(w), None, now);
            assert!(r.is_err(), "{w} resolved to {r:?}");
        }
        // The far side of the same boundary: the largest instant this tree
        // can WRITE is accepted and round-trips, and one second past it is
        // refused rather than formatted into a year rfc3339 cannot print.
        let edge = MAX_EXPIRY - now;
        let out = resolve_expiry(Some(&format!("{edge}m")), None, now);
        assert!(out.is_err(), "a window {edge} minutes long is not writable");
        assert!(parse_duration(&format!("{MAX_EXPIRY}m")).is_err());
        // Ordinary TTLs are untouched by any of this.
        for (w, secs) in [
            ("1m", 60),
            ("30m", 1_800),
            ("24h", 86_400),
            ("7d", 604_800),
            ("52w", 31_449_600),
        ] {
            assert_eq!(parse_duration(w), Ok(secs), "{w}");
            assert_eq!(
                resolve_expiry(Some(w), None, now),
                Ok(Some(crate::bundle::rfc3339(now + secs))),
                "{w}"
            );
        }
    }

    #[test]
    fn the_absolute_expiry_path_is_bounded_on_the_normalized_utc_instant() {
        // The earlier version of this test asserted that `--expires` needed
        // no bound, on the reasoning that `parse_rfc3339` reads the year
        // from four ASCII digits and so cannot return an instant past
        // 9999-12-31. That reasoning was wrong, and wrong in the one place
        // it mattered: the parser SUBTRACTS the zone offset after reading
        // the digits, so an in-grammar input can normalize past the bound.
        // The property pinned here is that the refusal is decided on the
        // normalized UTC instant, never on the local fields.
        let now = 1_793_000_000;

        // Just inside the bound, written two ways, and the output is a
        // timestamp this tree reads back as the same instant.
        for w in ["9999-12-31T23:59:59Z", "9999-12-31T23:59:59+00:00"] {
            let out = resolve_expiry(None, Some(w), now)
                .unwrap_or_else(|e| panic!("{w} refused: {e}"))
                .unwrap();
            assert_eq!(out, "9999-12-31T23:59:59Z", "{w}");
            assert_eq!(crate::bundle::parse_rfc3339(&out), Some(MAX_EXPIRY), "{w}");
        }
        assert_eq!(
            crate::bundle::parse_rfc3339("9999-12-31T23:59:59Z"),
            Some(MAX_EXPIRY)
        );

        // A negative offset pushing an in-grammar input over the bound. This
        // is the case the old assertion accepted: it normalizes to the year
        // 10000, which `rfc3339` prints with five year digits and
        // `parse_rfc3339` then refuses, so the recipient of such a bundle
        // withholds the payload. Refused at send time instead.
        let e = resolve_expiry(None, Some("9999-12-31T23:59:59-23:59"), now).unwrap_err();
        assert!(e.contains("9999-12-31T23:59:59Z"), "{e}");
        // Stated as the round-trip property, so this cannot regress into an
        // `is_some()` again: nothing this function returns is unreadable.
        for w in [
            "9999-12-31T23:59:59-23:59",
            "9999-12-31T23:59:59-00:01",
            "9999-12-31T23:59:60Z",
            "9999-12-31T00:00:00-23:59",
        ] {
            if let Ok(Some(out)) = resolve_expiry(None, Some(w), now) {
                let back = crate::bundle::parse_rfc3339(&out)
                    .unwrap_or_else(|| panic!("{w} produced an unreadable {out}"));
                assert!(back <= MAX_EXPIRY, "{w} -> {out}");
            }
        }

        // A plain year-10000 input, and a five-digit year generally, is not
        // in the grammar: refused as "not a timestamp" before any bound.
        for w in ["10000-01-01T00:00:00Z", "99999-01-01T00:00:00Z"] {
            let e = resolve_expiry(None, Some(w), now).unwrap_err();
            assert!(e.contains("RFC 3339 timestamp"), "{w}: {e}");
        }

        // The lower bound needs no separate check: `rfc3339` cannot write a
        // pre-1970 instant either, and the already-past refusal above covers
        // every negative second for any `now` at or after the epoch.
        let e = resolve_expiry(None, Some("1969-07-20T20:17:00Z"), now).unwrap_err();
        assert!(e.contains("already past"), "{e}");
    }

    #[test]
    fn the_expiry_bound_is_decided_on_the_instant_not_on_the_typed_fields() {
        let now = 1_793_000_000;
        // The other direction, and the reason the check cannot be done on
        // the typed fields: a POSITIVE offset makes the local fields read
        // later than the instant they denote. `10000-01-01T00:30:00+23:59`
        // is inside the bound as an instant, but this tree's parser refuses
        // five-digit local years up front (`parse_rfc3339` wants exactly
        // four digits before the `-`), so that input never reaches the
        // bound at all.
        assert_eq!(
            crate::bundle::parse_rfc3339("10000-01-01T00:30:00+23:59"),
            None
        );
        // So the inside-bound positive-offset case is taken at the largest
        // four-digit local year instead. Its local fields are the maximum
        // the grammar allows; its UTC instant is EARLIER, hence inside, and
        // it is accepted -- a bound applied to the local fields would have
        // refused it.
        let out = resolve_expiry(None, Some("9999-12-31T23:59:59+23:59"), now)
            .unwrap()
            .unwrap();
        assert_eq!(out, "9999-12-31T00:00:59Z");
        assert_eq!(
            crate::bundle::parse_rfc3339(&out),
            Some(MAX_EXPIRY - 86_340)
        );
    }

    #[test]
    fn the_resolved_expiry_is_always_one_this_tree_can_write_and_read_back() {
        // The property the bound exists for, stated as a property: whatever
        // comes out of `resolve_expiry` is a timestamp `parse_rfc3339` reads
        // back as the same instant, so a receiver's freshness check is
        // deciding on the deadline the sender asked for.
        let now = 1_793_000_000;
        for w in ["1m", "90m", "36h", "365d", "4000w", "100000d"] {
            let out = resolve_expiry(Some(w), None, now).unwrap().unwrap();
            let back = crate::bundle::parse_rfc3339(&out)
                .unwrap_or_else(|| panic!("{w} produced an unreadable {out}"));
            assert_eq!(back, now + parse_duration(w).unwrap(), "{w} -> {out}");
            assert!(back > now, "{w} -> {out} is not in the future");
        }
    }
}
