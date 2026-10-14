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

    pub fn memory_count(&self) -> usize {
        self.items.iter().filter(|i| i.kind == ItemKind::Memory).count()
    }

    pub fn total_bytes(&self) -> u64 {
        self.items.iter().map(|i| i.bytes).sum()
    }
}

/// Reject paths that would write outside the bundle. Checked on read, not
/// only on write: the sender is not the one we are protecting against.
pub fn path_is_safe(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.split('/').any(|seg| seg == ".." || seg == "." || seg.is_empty())
}
