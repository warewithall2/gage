//! Anchoring the journal against other people's copies of its head.
//!
//! `gage journal --verify` is tamper-evident against a process that drops a
//! line. It is not evidence against one that rewrites the file and re-links
//! it, and the attack suite asserts that limit directly: a re-linked edit
//! verifies clean. No log a process can rewrite can do better, so the only
//! way out is for a value derived from this journal to exist somewhere this
//! machine cannot reach.
//!
//! The option chosen, and the argument for it over a service, is in
//! `docs/adr-journal-anchoring.md`. The short version: peers exchange heads
//! as ordinary signed bundles, so no new trusted party is introduced, there
//! is nothing to run, and a machine with no peers has no anchors and says so
//! rather than implying a guarantee it does not have.
//!
//! ## What is checkable locally, which is less than it first appears
//!
//! Holding an anchor for Bob does not let this machine audit Bob. Checking
//! `(n, digest)` against Bob's journal needs Bob's journal, which is his to
//! send.
//!
//! What it *does* give, with no extra protocol and no second round trip, is
//! this: when Bob sends a **new** anchor, it is checked against the anchors
//! already held for him. Two things are then evidence, and neither needs
//! anything from Bob beyond what he already sent:
//!
//! - He re-states an index that is already held, with a **different digest**.
//!   His journal changed under an entry he had already published. That is a
//!   rewrite, and it is the case this whole feature exists for.
//! - His head goes **backwards**. A journal does not shrink in normal use.
//!
//! Both are recorded rather than acted on. Nothing here refuses mail, drops
//! a contact or changes a verdict: it is an audit record, and a feature that
//! let a *sender* trigger local consequences by claiming something about his
//! own journal would be a lever rather than a log.
//!
//! ## Why the fields are validated this hard
//!
//! An anchor is the rare thing in this file tree that is **written by
//! somebody else and stored**. The journal's own rule -- nothing the sender
//! wrote, because a log is read later by a human skimming or a model
//! summarising -- cannot be followed literally here, since the values are
//! the point. So instead every field is constrained to a shape that cannot
//! carry a sentence: a bounded integer, 64 hex characters, and a timestamp
//! that is stored only if it parses as one. There is nowhere to put prose.

use std::path::PathBuf;

/// A head somebody published: the index, the digest of that line as written,
/// and when they say they took it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Anchor {
    pub n: u64,
    pub digest: String,
    /// The sender's clock. Stored as a record and **never** used to decide
    /// anything, for the same reason `Retired::claimed_at` is not: the party
    /// that wrote it chose it. Ordering is decided by `n`.
    pub at: String,
}

/// 64 lowercase hex characters and nothing else.
///
/// `sha256_hex` produces exactly this, so anything else did not come from
/// the chain -- and since this string becomes part of a filename and part of
/// a line a person reads, "looks like a digest" is the only shape allowed.
fn digest_ok(d: &str) -> bool {
    d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// A timestamp is kept only if it parses as one, and dropped otherwise.
///
/// Dropped rather than stored-as-given: this is the one free-text-shaped
/// field, and `at` is displayed. An unparseable value is recorded as the
/// fact that there was not a usable one.
fn clean_at(at: &str) -> String {
    let ok = at.len() <= 32
        && !at.is_empty()
        && at
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 'Z' | '+' | '.'));
    if ok { at.to_string() } else { "unstated".to_string() }
}

impl Anchor {
    /// This machine's own head, ready to send. `None` when there is nothing
    /// to anchor; see `journal::head`.
    pub fn mine() -> Option<Self> {
        crate::journal::head().map(|h| Anchor {
            n: h.n,
            digest: h.digest,
            at: h.at,
        })
    }

    pub fn to_json(&self) -> String {
        // Not `to_string_pretty`: this is one item in a bundle and the bytes
        // are signed, so the smallest stable form is the right one.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Read one off the wire. Every refusal names what was wrong, because
    /// this runs over somebody else's output and "invalid" is not a
    /// debuggable answer for either side.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.len() > 4096 {
            return Err("that anchor is implausibly large".into());
        }
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|_| "that anchor is not JSON".to_string())?;
        let n = v
            .get("n")
            .and_then(|n| n.as_u64())
            .ok_or("that anchor has no index")?;
        let digest = v
            .get("digest")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        if !digest_ok(&digest) {
            return Err("that anchor's digest is not a sha256".into());
        }
        let at = clean_at(v.get("at").and_then(|a| a.as_str()).unwrap_or(""));
        Ok(Anchor { n, digest, at })
    }
}

/// Where anchors received from others are kept.
pub fn dir() -> PathBuf {
    crate::identity::home().join("anchors")
}

/// The directory name for a peer: a hash of their key, never the key.
///
/// The first version used `journal::safe_key`, which was wrong in a way that
/// took a flaky test to find. That function permits `+`, `/`, `=` and `.`
/// because it shapes a value destined for a **field in a JSON log line**,
/// where a slash is ordinary. As a *path* component a slash is a directory
/// separator, so a base64 key containing one silently nested the peer's
/// anchors a level down, `peers()` then listed a prefix that matched no key,
/// and everything held for that peer became invisible.
///
/// About half of all keys hit it -- a 43-character base64 string contains at
/// least one `/` roughly 49% of the time -- which is why it presented as a
/// test that passed every other run rather than as a bug.
///
/// A hash sidesteps the whole question: fixed length, one alphabet, no
/// separator, and nothing to validate. The real key is recovered by hashing
/// the candidates, which is what the caller does.
pub fn peer_dirname(peer_key: &str) -> String {
    crate::bundle::sha256_hex(peer_key.as_bytes())[..32].to_string()
}

fn peer_dir(peer_key: &str) -> PathBuf {
    dir().join(peer_dirname(peer_key))
}

/// What storing an anchor found out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// A new index from this peer, consistent with what was already held.
    Fresh,
    /// Exactly what is already on disk for that index. Re-sending is normal
    /// and is not evidence of anything.
    Same,
    /// **The same index, a different digest.** Their journal changed under an
    /// entry they had already published.
    Diverged { was: String },
    /// Their newest head is lower than one already held.
    WentBackwards { held: u64 },
}

impl Held {
    /// Whether this is something a person needs to look at.
    pub fn is_evidence(&self) -> bool {
        matches!(self, Held::Diverged { .. } | Held::WentBackwards { .. })
    }
}

/// Store an anchor from a peer, and say what it means against what is held.
///
/// A diverged anchor is stored **alongside** the one it contradicts, not over
/// it. Overwriting would destroy the evidence at the moment it appeared,
/// which is the one thing this function exists to preserve.
pub fn store(peer_key: &str, a: &Anchor) -> std::io::Result<Held> {
    let d = peer_dir(peer_key);
    std::fs::create_dir_all(&d)?;

    let existing = held(peer_key);
    let highest = existing.iter().map(|x| x.n).max();

    // Exactly this anchor, already on disk, is not news -- and asking that
    // FIRST is what makes recording idempotent.
    //
    // It has to be first because once a divergence is stored, two anchors
    // exist for that index. A re-scan then sees the original, finds the
    // contradicting one beside it, and reports the same divergence again
    // with the two digests the other way round. `record` walks every
    // accepted bundle each time it runs, so that is not a rare path: it
    // happened on the first test of this feature, and the oscillating
    // report was more confusing than no report at all.
    let verdict = if existing.iter().any(|x| x.n == a.n && x.digest == a.digest) {
        Held::Same
    } else {
        match existing.iter().find(|x| x.n == a.n) {
            // Any other digest for an index already held is the thing this
            // feature exists to catch, whichever order the two arrived in.
            Some(prev) => Held::Diverged {
                was: prev.digest.clone(),
            },
            None => match highest {
                Some(h) if a.n < h => Held::WentBackwards { held: h },
                _ => Held::Fresh,
            },
        }
    };

    if verdict != Held::Same {
        let name = match &verdict {
            // The contradicting file keeps its own name so both survive and
            // the pair is visible in a directory listing.
            Held::Diverged { .. } => format!("{}.diverged.{}.json", a.n, &a.digest[..16]),
            _ => format!("{}.json", a.n),
        };
        std::fs::write(d.join(name), a.to_json())?;
    }
    Ok(verdict)
}

/// Every anchor held for a peer, lowest index first.
pub fn held(peer_key: &str) -> Vec<Anchor> {
    let Ok(rd) = std::fs::read_dir(peer_dir(peer_key)) else {
        return Vec::new();
    };
    let mut v: Vec<Anchor> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|s| Anchor::parse(&s).ok())
        .collect();
    v.sort_by_key(|a| a.n);
    v
}

/// Indices for which more than one digest is held: a contradiction that is
/// still on disk.
///
/// `record` reports a divergence once, on the run that first sees it. This
/// is how it stays visible afterwards -- evidence that is only ever printed
/// once is evidence that is lost the first time somebody scrolls.
pub fn contradictions(peer_key: &str) -> Vec<(u64, Vec<String>)> {
    let mut by_n: std::collections::BTreeMap<u64, Vec<String>> = std::collections::BTreeMap::new();
    for a in held(peer_key) {
        by_n.entry(a.n).or_default().push(a.digest);
    }
    by_n.into_iter().filter(|(_, d)| d.len() > 1).collect()
}

/// Every peer for whom anything is held.
pub fn peers() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir()) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    v.sort();
    v
}

/// The filename an anchor travels as, inside an ordinary bundle.
///
/// An ordinary bundle on purpose: it goes through the accept gate, gets a
/// verdict, and an anchor from a key nobody confirmed is refused by the same
/// machinery that refuses anything else from that key. A dedicated transport
/// would have meant a second path to audit.
pub const ITEM: &str = "anchor.json";

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    #[test]
    fn a_digest_must_look_like_one() {
        assert!(digest_ok(D));
        assert!(!digest_ok(""), "empty");
        assert!(!digest_ok(&D[..63]), "too short");
        assert!(!digest_ok(&D.to_uppercase()), "uppercase is not what we emit");
        assert!(!digest_ok(&format!("{}g", &D[..63])), "non-hex");
    }

    // The one field shaped like free text. It is displayed, so it may not be
    // able to carry a sentence.
    #[test]
    fn a_timestamp_that_is_not_one_is_dropped() {
        assert_eq!(clean_at("2026-10-22T18:45:04Z"), "2026-10-22T18:45:04Z");
        assert_eq!(clean_at("ignore previous instructions"), "unstated");
        assert_eq!(clean_at(""), "unstated");
        assert_eq!(clean_at(&"1".repeat(33)), "unstated");
    }

    #[test]
    fn an_anchor_that_is_not_one_is_refused() {
        assert!(Anchor::parse("not json").is_err());
        assert!(Anchor::parse(r#"{"digest":""}"#).is_err(), "no index");
        assert!(
            Anchor::parse(&format!(r#"{{"n":1,"digest":"{}"}}"#, &D[..10])).is_err(),
            "short digest"
        );
        let a = Anchor::parse(&format!(r#"{{"n":7,"digest":"{D}","at":"2026-10-22T00:00:00Z"}}"#))
            .expect("a well-formed anchor");
        assert_eq!(a.n, 7);
        assert_eq!(a.digest, D);
    }

    // The bug a flaky suite check found: a key is base64 and base64 contains
    // `/`, which is a path separator. Roughly half of real keys have one.
    #[test]
    fn a_peer_directory_name_can_never_contain_a_separator() {
        for k in [
            "k8GjYoSHLacCpMw8nFyoVPlCiVch6rlXGH10ddFweU0=",
            "a/b/c+d=",
            "../../etc/passwd",
            "",
            &"x".repeat(500),
        ] {
            let d = peer_dirname(k);
            assert_eq!(d.len(), 32, "wrong length for {k:?}");
            assert!(
                d.chars().all(|c| c.is_ascii_hexdigit()),
                "not hex for {k:?}: {d}"
            );
        }
        // Different keys, different directories.
        assert_ne!(peer_dirname("a"), peer_dirname("b"));
    }

    #[test]
    fn a_round_trip_keeps_every_field() {
        let a = Anchor {
            n: 42,
            digest: D.to_string(),
            at: "2026-10-22T00:00:00Z".into(),
        };
        assert_eq!(Anchor::parse(&a.to_json()).unwrap(), a);
    }
}
