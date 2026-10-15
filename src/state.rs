//! Local state: what you have read, and what you consider settled.
//!
//! None of this lives in a bundle, and that is the point. A sender must not be
//! able to mark their own message read in your inbox, or declare a thread
//! answered because they would like it to be. It is the same rule that keeps
//! trust out of the manifest: anything the sender controls is a claim, and
//! claims do not get to be your state.
//!
//! Thread state is derived, not stored, wherever it can be: a thread is open
//! if its newest message expects a reply and nothing later answered it. Stored
//! state is only the overrides a person makes by hand, so the common case
//! stays correct without anyone maintaining it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LocalState {
    /// Bundle ids that have been rendered by `ctx open`.
    #[serde(default)]
    pub read: BTreeSet<String>,
    /// thread id -> an explicit override, when someone closes a thread by
    /// hand. Absent means "work it out from the messages".
    #[serde(default)]
    pub closed: BTreeMap<String, String>,
    /// A monotonic counter, bumped once per observation batch.
    ///
    /// Ordering by COUNT rather than by clock, because every timestamp-based
    /// version of this was wrong in a different way. `created` is the signer's
    /// field. A local wall clock has one-second resolution here, so a witness
    /// written in the same second as a retirement fails a strict `<`. And a
    /// string compare over RFC3339 accepted `""`, `"...00.9Z"` and
    /// `"...T01:00:00-14:00"` as earlier than noon. A counter has none of
    /// those properties: it only ever increases, and "before the retirement"
    /// is a total order with no parsing in it.
    #[serde(default)]
    pub seq: u64,
    /// witness -> the `seq` at which this machine first observed it.
    ///
    /// The witness is `sha256(from.key || manifest bytes)`, NOT the bundle id.
    /// `bundle::load` never recomputes the id, so the signer picks it: keying
    /// on the id let a holder of a retired key reuse an id this machine had
    /// already stamped, attach a different payload, and inherit the witness.
    /// The manifest bytes are what the signature covers, and the key is in
    /// there for domain separation.
    #[serde(default)]
    pub witness: BTreeMap<String, u64>,
}

/// An advisory lock around `state.json`.
///
/// Both halves of read-modify-write used to happen on a value loaded earlier,
/// and the whole file was written back whole. The viewer polls every 2.5
/// seconds while the CLI writes, so two processes could each load the old
/// state and overwrite the other's changes -- silently losing a witness,
/// which is the one record that must not be lost. Mutations now run under
/// this lock, against a fresh read, and land by rename.
struct Lock(PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn take_lock(target: &Path) -> io::Result<Lock> {
    let lp = target.with_extension("json.lock");
    if let Some(d) = lp.parent() {
        fs::create_dir_all(d)?;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match fs::OpenOptions::new().write(true).create_new(true).open(&lp) {
            Ok(_) => return Ok(Lock(lp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // A crash between create and remove would otherwise wedge
                // every later run, so a lock nobody has touched for a while
                // is treated as abandoned rather than honoured forever.
                let stale = fs::metadata(&lp)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d > Duration::from_secs(30))
                    .unwrap_or(false);
                if stale {
                    let _ = fs::remove_file(&lp);
                    continue;
                }
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{} stayed locked; another ctx process may be stuck", lp.display()),
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
}

impl LocalState {
    fn path() -> std::path::PathBuf {
        crate::identity::home().join("state.json")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Apply a change under the lock, against what is on disk right now.
    ///
    /// The closure returns whether anything changed, so a no-op does not
    /// rewrite the file. Callers hold a `LocalState` for reading and come
    /// through here to write, which is why there is no public `save`: a
    /// whole-file save from a stale value is exactly the lost-update bug.
    pub fn mutate<F>(f: F) -> std::io::Result<Self>
    where
        F: FnOnce(&mut Self) -> bool,
    {
        let p = Self::path();
        let _guard = take_lock(&p)?;
        let mut cur = Self::load();
        if f(&mut cur) {
            let tmp = p.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&cur)?)?;
            std::fs::rename(&tmp, &p)?;
        }
        Ok(cur)
    }

    pub fn is_read(&self, id: &str) -> bool {
        self.read.contains(id)
    }

    pub fn mark_read(&mut self, id: &str) -> std::io::Result<()> {
        let owned = id.to_string();
        Self::mutate(move |s| s.read.insert(owned))?;
        self.read.insert(id.to_string());
        Ok(())
    }

    /// The sequence at which a bundle was first observed here, if ever.
    pub fn witnessed(&self, witness: &str) -> Option<u64> {
        self.witness.get(witness).copied()
    }

    /// Record observations and return the state as it now stands on disk.
    ///
    /// One batch, one `seq`. Bundles observed in the same batch are not
    /// ordered against each other, which is correct: nothing distinguishes
    /// them, and inventing an order would be a claim this machine cannot
    /// support.
    pub fn observe(witnesses: &[String]) -> std::io::Result<Self> {
        Self::mutate(|s| {
            let next = s.seq + 1;
            let mut added = false;
            for w in witnesses {
                if !s.witness.contains_key(w) {
                    s.witness.insert(w.clone(), next);
                    added = true;
                }
            }
            if added {
                s.seq = next;
            }
            added
        })
    }

    /// Bump the counter and return the value that separates "before" from
    /// "after". Used when a retirement is recorded: everything already
    /// witnessed is below this, everything observed later is above it.
    pub fn cut(&mut self) -> std::io::Result<u64> {
        let st = Self::mutate(|s| {
            s.seq += 1;
            true
        })?;
        self.seq = st.seq;
        Ok(st.seq)
    }

    pub fn close(&mut self, thread: &str) -> std::io::Result<()> {
        let owned = thread.to_string();
        Self::mutate(move |s| s.closed.insert(owned, "closed".into()).is_none())?;
        self.closed.insert(thread.to_string(), "closed".into());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Newest message expects a reply and none has come.
    AwaitingYou,
    /// You asked; nothing has come back.
    AwaitingThem,
    /// Nothing outstanding.
    Settled,
    /// Closed by hand.
    Closed,
}

impl ThreadState {
    pub fn label(&self) -> &'static str {
        match self {
            ThreadState::AwaitingYou => "awaiting YOU",
            ThreadState::AwaitingThem => "awaiting them",
            ThreadState::Settled => "settled",
            ThreadState::Closed => "closed",
        }
    }
}

pub struct Thread {
    pub id: String,
    pub subject: String,
    pub messages: Vec<crate::manifest::Manifest>,
    pub unread: usize,
    pub state: ThreadState,
    /// Distinct sender keys other than yours, in first-seen order. More than
    /// one means a reply has more than one possible destination.
    pub others: Vec<String>,
    /// Message ids whose claim to belong to this thread could not be checked
    /// against anything held locally.
    pub unverified: Vec<String>,
}

/// Can this message's claim to belong to a thread be checked locally?
///
/// `thread` is a field the SENDER writes, and the grouper used to honour it
/// outright. That let anyone who had seen one message of a conversation graft
/// a bundle onto it: group by the claim, and `ctx reply` -- which picks the
/// newest message that is not yours -- would then resolve the recipient to
/// the grafter instead of the person you were talking to. A sender-controlled
/// field decided who your reply went to, in a codebase whose rule is that
/// trust is computed by the receiver and never carried.
///
/// So the claim is checked against what is held locally:
///
/// * no claim, or a claim to be its own root: nothing to forge.
/// * a parent that is held, and really is in the claimed thread: verified.
/// * a parent that is held and is in a DIFFERENT thread: the chain
///   contradicts the claim, so the claim loses and the message starts its own.
/// * a parent that is not held: honoured, because over a relay you may hold
///   only part of a thread, but marked unverified. `resolve_reply` refuses to
///   take a recipient from one of these, and the viewer says so.
fn thread_claim(
    m: &crate::manifest::Manifest,
    held: &BTreeMap<String, String>,
) -> (String, bool) {
    let Some(claim) = m.thread.as_deref() else { return (m.id.clone(), true) };
    if claim == m.id {
        return (m.id.clone(), true);
    }
    let Some(parent) = m.in_reply_to.as_deref() else {
        // Claims a thread while answering nothing. There is no chain to check,
        // so it does not get to join.
        return (m.id.clone(), false);
    };
    match held.get(parent) {
        Some(pt) if pt == claim => (claim.to_string(), true),
        Some(_) => (m.id.clone(), false),
        None => (claim.to_string(), false),
    }
}

/// Group every bundle you hold into threads, newest activity first.
///
/// `mine` is your own signing key, which is how an outstanding question is
/// told from one you are waiting on: the direction of the newest message.
pub fn threads(
    manifests: Vec<crate::manifest::Manifest>,
    st: &LocalState,
    mine: &str,
) -> Vec<Thread> {
    // First pass: what each held message says its thread is, so a claim can be
    // checked against a parent. Built from the raw claims on purpose -- the
    // check only needs to know whether the parent is in the SAME thread, and
    // a one-level comparison cannot be walked into a loop.
    let held: BTreeMap<String, String> = manifests
        .iter()
        .map(|m| (m.id.clone(), m.thread_id().to_string()))
        .collect();

    let mut by: BTreeMap<String, Vec<crate::manifest::Manifest>> = BTreeMap::new();
    let mut unverified: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in manifests {
        let (tid, ok) = thread_claim(&m, &held);
        if !ok {
            unverified.entry(tid.clone()).or_default().push(m.id.clone());
        }
        by.entry(tid).or_default().push(m);
    }
    let mut out: Vec<Thread> = by
        .into_iter()
        .map(|(id, mut msgs)| {
                // Root first, then by time, then by id so the order is total and
            // stable rather than dependent on directory iteration.
            msgs.sort_by(|a, b| {
                (a.id != id, &a.created, &a.id).cmp(&(b.id != id, &b.created, &b.id))
            });
            // Your own messages are never unread. Counting them makes every
            // thread you started look like it needs attention.
            let unread = msgs
                .iter()
                .filter(|m| m.from.key != mine && !st.is_read(&m.id))
                .count();
            // The root is the message whose own id IS the thread id, not
            // whichever sorted first. `created` has one-second resolution, so
            // a question and its reply sent in the same second can invert and
            // the thread ends up named after the reply ("re: ...").
            let subject = msgs
                .iter()
                .find(|m| m.id == id)
                .or_else(|| msgs.first())
                .map(|m| m.subject.clone())
                .unwrap_or_else(|| "(no subject)".into());
            let state = if st.closed.contains_key(&id) {
                ThreadState::Closed
            } else {
                match msgs.last() {
                    Some(last) if last.msg_type.expects_reply() => {
                        if last.from.key == mine {
                            ThreadState::AwaitingThem
                        } else {
                            ThreadState::AwaitingYou
                        }
                    }
                    _ => ThreadState::Settled,
                }
            };
            // Who a reply could go to. Order is oldest first, which makes the
            // original correspondent first and a late graft last.
            let mut others: Vec<String> = Vec::new();
            for m in &msgs {
                if m.from.key != mine && !others.contains(&m.from.key) {
                    others.push(m.from.key.clone());
                }
            }
            let unverified = unverified.remove(&id).unwrap_or_default();
            Thread { id, subject, messages: msgs, unread, state, others, unverified }
        })
        .collect();
    out.sort_by(|a, b| {
        let an = a.messages.last().map(|m| m.created.clone()).unwrap_or_default();
        let bn = b.messages.last().map(|m| m.created.clone()).unwrap_or_default();
        bn.cmp(&an)
    });
    out
}
