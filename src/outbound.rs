//! Building and sending bundles, and working out who a reply is for.
//!
//! Separate from main.rs because `gage ui` sends too, and a second send path
//! that grew its own copy of the outbound scan would eventually be missing
//! one of its checks. There is one way out of this program.

use crate::manifest::AgentInfo;
use crate::{bundle, collect, identity, manifest, routes, scrub, state, trust};
use std::path::PathBuf;

/// Look for a bundle by id in pending and accepted. Used to inherit a thread
/// when replying.
pub fn find_manifest(id: &str) -> Option<manifest::Manifest> {
    let home = identity::home();
    for stage in [routes::accepted_dir(&home), routes::pending_dir(&home)] {
        let d = stage.join(id);
        if d.is_dir() {
            if let Ok(l) = bundle::load(&d) {
                return Some(l.manifest);
            }
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
        eprintln!("ctx: WARNING -- inbox not recorded ({e}); verdicts below may read milder than the truth");
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
                return Err(format!("{id} matches {} threads: {}", ids.len(), ids.join(", ")).into());
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
                    None => format!("an unlisted key ({}…)", k.chars().take(10).collect::<String>()),
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
    let msg_type = if parent.msg_type.expects_reply() { "answer" } else { "share" }.to_string();
    let subject = if thread.subject.to_ascii_lowercase().starts_with("re:") {
        thread.subject.clone()
    } else {
        format!("re: {}", thread.subject)
    };
    Ok(ReplyTarget { parent: parent.id.clone(), to, msg_type, subject })
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
}

pub fn send_bundle(a: SendArgs) -> Result<manifest::Manifest, Box<dyn std::error::Error>> {
    let SendArgs {
        to, subject, out, file, prompt, decision, memory, dir,
        allow_secrets, reply_to, msg_type: type_in, allow_findings, lan, agent, model,
    } = a;
    let r#type = type_in;

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
            if !c.skipped_link.is_empty() {
                println!("skipped (symlinks -- a link's name says nothing about its target):");
                for f in &c.skipped_link {
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
                    lines.push(format!("  {}:{}  [{}]  {}", f.path, f.line, f.rule, f.preview));
                }
                if !allow_findings {
                    lines.push(
                        "refusing to build this bundle. Fix the files, add a rule to \
                         ~/.ctx/scrub.json, or pass --allow-findings if they are false \
                         positives."
                            .to_string(),
                    );
                    return Err(lines.join("\n").into());
                }
                for l in &lines {
                    println!("{l}");
                }
                println!("  --allow-findings given: sending anyway");
            }

            let msg_type = manifest::MsgType::parse(&r#type).ok_or_else(|| {
                format!("unknown --type {type_in:?}; use share, question, answer, review-request or ack",
                        type_in = r#type)
            })?;
            // A reply inherits its parent's thread. Looked up locally rather
            // than walked at read time: over a relay you may hold only part
            // of a thread, and a chain you cannot walk is a thread you cannot
            // group. Falling back to the parent id still groups the pair.
            let thread = reply_to.as_ref().map(|rid| {
                find_manifest(rid)
                    .map(|m| m.thread_id().to_string())
                    .unwrap_or_else(|| rid.clone())
            });
            let ag = agent.map(|name| AgentInfo { name, model });
            // Built once into a staging dir, then delivered to each routed
            // recipient. Building per-recipient would give one payload a
            // different content id for every person who received it.
            let stage = out.clone().unwrap_or_else(|| {
                identity::home().join(format!("outbox/{}", std::process::id()))
            });
            let m = bundle::create(&stage, &id, &subject, &to, ag, reply_to, thread, msg_type, &specs)?;
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
            println!(
                "bundle {} [{}] -- {} item(s), {} bytes, signed by {}",
                m.id, m.msg_type.label(), m.items.len(), m.total_bytes(), id.handle
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
            if !unrouted.is_empty() && !lan {
                println!("  no local route for: {}", unrouted.join(", "));
                println!("  bundle is at {} -- move it yourself, or", stage.display());
                println!("  gage route <handle> <their-ctx-home> to deliver automatically");
            }
        
    Ok(m)
}

