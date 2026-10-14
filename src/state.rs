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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LocalState {
    /// Bundle ids that have been rendered by `ctx open`.
    #[serde(default)]
    pub read: BTreeSet<String>,
    /// thread id -> an explicit override, when someone closes a thread by
    /// hand. Absent means "work it out from the messages".
    #[serde(default)]
    pub closed: BTreeMap<String, String>,
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

    pub fn save(&self) -> std::io::Result<()> {
        let p = Self::path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(p, serde_json::to_vec_pretty(self)?)
    }

    pub fn is_read(&self, id: &str) -> bool {
        self.read.contains(id)
    }

    pub fn mark_read(&mut self, id: &str) -> std::io::Result<()> {
        if self.read.insert(id.to_string()) {
            self.save()?;
        }
        Ok(())
    }

    pub fn close(&mut self, thread: &str) -> std::io::Result<()> {
        self.closed.insert(thread.to_string(), "closed".into());
        self.save()
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
    let mut by: BTreeMap<String, Vec<crate::manifest::Manifest>> = BTreeMap::new();
    for m in manifests {
        by.entry(m.thread_id().to_string()).or_default().push(m);
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
            Thread { id, subject, messages: msgs, unread, state }
        })
        .collect();
    out.sort_by(|a, b| {
        let an = a.messages.last().map(|m| m.created.clone()).unwrap_or_default();
        let bn = b.messages.last().map(|m| m.created.clone()).unwrap_or_default();
        bn.cmp(&an)
    });
    out
}
