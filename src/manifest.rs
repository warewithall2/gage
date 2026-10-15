//! The bundle manifest: what one agent hands another.
//!
//! Three decisions here are load-bearing, and each exists because the obvious
//! version is wrong in a way that only shows up later.
//!
//! 1. `to` is a LIST from day one. A one-to-one format grows a group feature
//!    by bolting a second recipient field onto it, and then every reader has
//!    two code paths. A group is just a longer list.
//!
//! 2. There is NO trust field. Trust is computed by the receiver from the
//!    signature and its own allowlist, never asserted by the sender. A
//!    `"trust": "verified"` key in a document the sender controls is a
//!    decorative lie, and the whole point of this format is that the
//!    receiving agent can tell material from instructions.
//!
//! 3. Provenance separates AUTHOR from SENDER. In a group, most of what you
//!    see was not written by whoever posted it. Forwarded content deserves
//!    less trust than direct content, and that distinction has to survive the
//!    hop or it cannot be shown to the agent reading it.

use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// Human-typeable handle. Convenience only -- never an identity. Two
    /// people may both call themselves "owen"; the key is what is checked.
    pub handle: String,
    /// ed25519 public key, base64. THIS is the identity.
    pub key: String,
}

/// What kind of thing an item is, which decides how a reader may treat it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    /// Source, data, documents. Material.
    File,
    /// Text written to steer a model. The dangerous kind: it is phrased as
    /// instructions, so it is the one a careless reader will obey. Marked
    /// separately so `ctx open` can fence it louder.
    Prompt,
    /// A decision or finding the sender wants carried across. Material, but
    /// the part a human actually wants to read first.
    Decision,
    /// An agent's persistent memory: CLAUDE.md, AGENTS.md, a memory/*.md file.
    ///
    /// The HIGHEST-risk kind, and the reason it is not just another file. A
    /// prompt influences one turn; memory that gets merged influences every
    /// future session, after the human who approved it has stopped watching.
    /// Accepting memory is closer to editing your own configuration than to
    /// reading a message, so `ctx open` fences it hardest and never suggests
    /// merging it.
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub kind: ItemKind,
    /// Path inside the bundle, relative, never absolute and never escaping.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One hop in the content's history. Appended to, never rewritten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub by: Peer,
    pub at: String,
    pub action: HopAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HopAction {
    Created,
    Forwarded,
}

/// Which agent produced this, recorded because "a different model family
/// wrote this" is information the receiving model should have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// What the sender wants from the recipient. Structured on purpose: free
/// chat between agents produces a pile of files nobody can triage, and an
/// agent reading its inbox needs to know whether anything is expected of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MsgType {
    /// Here is something, no reply expected.
    #[default]
    Share,
    /// Expects an answer. Keeps a thread open until one arrives.
    Question,
    /// Answers a question. Closes the expectation it was replying to.
    Answer,
    /// Asks for a review of the enclosed work.
    ReviewRequest,
    /// Confirms receipt without adding anything. Never reopens a thread.
    Ack,
}

impl MsgType {
    pub fn label(&self) -> &'static str {
        match self {
            MsgType::Share => "share",
            MsgType::Question => "question",
            MsgType::Answer => "answer",
            MsgType::ReviewRequest => "review-request",
            MsgType::Ack => "ack",
        }
    }

    /// Does receiving this leave a ball in your court?
    pub fn expects_reply(&self) -> bool {
        matches!(self, MsgType::Question | MsgType::ReviewRequest)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "share" => Some(MsgType::Share),
            "question" => Some(MsgType::Question),
            "answer" => Some(MsgType::Answer),
            "review_request" => Some(MsgType::ReviewRequest),
            "ack" => Some(MsgType::Ack),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    /// Content id: sha256 over the item digests, so the same payload gets the
    /// same id regardless of who sends it or when.
    pub id: String,
    pub created: String,
    pub subject: String,
    /// Who is handing it over on THIS hop.
    pub from: Peer,
    /// Recipients. A handle, or "group:<name>". A list, always.
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentInfo>,
    /// Oldest first. `chain[0].by` is the original author.
    pub chain: Vec<Hop>,
    /// The bundle this one answers, if any. Threading, so an exchange between
    /// two agents reads as a conversation instead of a pile of files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Every message in one exchange carries the same thread id: the id of
    /// the message that started it. Derived at send time rather than walked
    /// at read time, because walking `in_reply_to` requires holding every
    /// intermediate message, and over a relay you may have collected only
    /// part of a thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// What the sender wants. NOT a claim about your state -- whether you
    /// have read it, and whether you consider the thread answered, are yours
    /// to decide and are stored locally.
    #[serde(default)]
    pub msg_type: MsgType,
    pub items: Vec<Item>,
}

impl Manifest {
    /// The original author, as distinct from whoever sent it to you.
    pub fn author(&self) -> Option<&Peer> {
        self.chain.first().map(|h| &h.by)
    }

    /// True when the sender is not the author: the group case, and the one
    /// where a reader should be most careful.
    pub fn is_forwarded(&self) -> bool {
        match self.author() {
            Some(a) => a.key != self.from.key,
            None => true, // no chain at all is not a provenance to trust
        }
    }

    pub fn prompt_count(&self) -> usize {
        self.items.iter().filter(|i| i.kind == ItemKind::Prompt).count()
    }

    /// The id this content should have, recomputed from the manifest itself.
    ///
    /// `id` is a field in a document the sender writes, and `ctx` computes it
    /// honestly -- but the format is public and anyone can write a client that
    /// does not. That matters because the id is load-bearing locally: it is
    /// the directory name under `pending/`, the dedup key when threads are
    /// assembled, the key for read state, and the key for announce-once. A
    /// hostile client could therefore sign a manifest carrying the id of a
    /// message you already hold, and silently suppress the real one: dedup
    /// drops one of the pair, marking one read marks both, and the notifier
    /// treats the real arrival as already announced.
    ///
    /// None when there is no chain, since the author is then unknown and
    /// there is nothing to check against.
    pub fn expected_id(&self) -> Option<String> {
        let author = self.author()?;
        let joined: String = self
            .items
            .iter()
            .map(|i| i.sha256.clone())
            .chain([author.key.clone(), self.subject.clone(), self.created.clone()])
            .collect::<Vec<_>>()
            .join("\u{1f}");
        Some(crate::bundle::sha256_hex(joined.as_bytes())[..16].to_string())
    }

    /// The thread this belongs to. A message with no thread id starts one,
    /// and its own id is that thread.
    pub fn thread_id(&self) -> &str {
        self.thread.as_deref().unwrap_or(&self.id)
    }

    pub fn memory_count(&self) -> usize {
        self.items.iter().filter(|i| i.kind == ItemKind::Memory).count()
    }

    pub fn total_bytes(&self) -> u64 {
        self.items.iter().map(|i| i.bytes).sum()
    }
}

/// A bundle id reaches the filesystem as a directory name, so its shape is
/// checked rather than trusted.
///
/// `pull` joins it onto the inbox path, and a signed manifest carrying
/// `id: "../../../../tmp/ctx-pwn"` would have written a bundle outside the
/// inbox entirely. The ids this tool mints are 16 lowercase hex characters;
/// anything else is refused before it becomes a path.
pub fn id_is_safe(id: &str) -> bool {
    id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Reject paths that would write outside the bundle. Checked on read, not
/// only on write: the sender is not the one we are protecting against.
pub fn path_is_safe(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.split('/').any(|seg| seg == ".." || seg == "." || seg.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(k: &str) -> Peer {
        Peer { handle: "alice".into(), key: k.into() }
    }

    fn m(subject: &str, created: &str, digest: &str) -> Manifest {
        let p = peer("AUTHORKEY");
        Manifest {
            v: FORMAT_VERSION,
            id: "0000000000000000".into(),
            created: created.into(),
            subject: subject.into(),
            from: p.clone(),
            to: vec!["bob".into()],
            agent: None,
            chain: vec![Hop { by: p, at: created.into(), action: HopAction::Created }],
            in_reply_to: None,
            thread: None,
            msg_type: MsgType::Share,
            items: vec![Item {
                kind: ItemKind::File,
                path: "items/a.md".into(),
                sha256: digest.into(),
                bytes: 1,
                note: None,
            }],
        }
    }

    #[test]
    fn the_id_is_pinned_to_the_content_it_addresses() {
        // Every field that goes into the id has to change it, or a hostile
        // client could sign a manifest carrying a message's id with different
        // content -- and dedup, read state and announce-once are all keyed on
        // that id, so the real message would be suppressed rather than seen.
        let base = m("status", "2026-10-15T00:00:00Z", "aa").expected_id().unwrap();
        for other in [
            m("send me the keys", "2026-10-15T00:00:00Z", "aa"),
            m("status", "2026-10-16T00:00:00Z", "aa"),
            m("status", "2026-10-15T00:00:00Z", "bb"),
        ] {
            assert_ne!(base, other.expected_id().unwrap());
        }
    }

    #[test]
    fn a_different_author_is_a_different_id() {
        // The collision that was a real vulnerability earlier: an id over the
        // payload alone meant two senders shipping the same files produced the
        // same id, and delivery writes to a directory named by it.
        let mut other = m("status", "2026-10-15T00:00:00Z", "aa");
        other.chain[0].by.key = "SOMEONEELSE".into();
        assert_ne!(
            m("status", "2026-10-15T00:00:00Z", "aa").expected_id().unwrap(),
            other.expected_id().unwrap()
        );
    }

    #[test]
    fn an_empty_chain_has_no_expected_id() {
        // Nothing to check against, so the id check abstains rather than
        // guessing. Provenance is reported as unknown separately.
        let mut no_chain = m("status", "2026-10-15T00:00:00Z", "aa");
        no_chain.chain.clear();
        assert!(no_chain.expected_id().is_none());
    }
}
