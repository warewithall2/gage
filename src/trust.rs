//! The buddy list, which is the entire access-control model.
//!
//! AIM had this right in 1997: you accept people, and anyone else cannot
//! reach you. Here it does double duty -- it stops unsolicited bundles, and
//! it is what turns a signature into a *meaning*. A valid signature only
//! proves the sender holds a key; the allowlist is what says you have ever
//! agreed to hear from that key.
//!
//! Keyed by public key, not by handle. A handle is a label anybody can claim.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signature valid and the key is on the allowlist.
    Known,
    /// Signature valid, key not on the allowlist. Real sender, stranger.
    Unknown,
    /// Signature absent, malformed, or does not match the manifest bytes.
    /// Nothing about the sender can be believed.
    Unverified,
    /// Signature valid under a key you have RETIRED, and the bundle is older
    /// than the retirement. Attributable, with a caveat worth stating.
    Retired,
    /// Signature valid under a retired key, but the bundle claims to be newer
    /// than the retirement -- or the key was retired as compromised, in which
    /// case no date saves it. This is the case that makes rotation mean
    /// anything: if a retired key kept working for new mail, retiring it
    /// would buy nothing at all.
    Revoked,
}

impl Trust {
    /// Labels are deliberately NOT substrings of one another. The first
    /// version used "KNOWN SENDER" and "UNKNOWN SENDER", and a test that
    /// asserted the absence of the former matched the latter -- so any reader
    /// grepping for trust, an agent included, could read "unknown" as
    /// "known". A safety label that fails a substring check is not a label.
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Known => "SENDER VERIFIED (signature valid, key is on your list)",
            Trust::Unknown => "SENDER NOT ON YOUR LIST (signature valid, you have never accepted this key)",
            Trust::Unverified => "SENDER UNVERIFIABLE (signature missing or invalid)",
            Trust::Retired => "SENDER KEY RETIRED (signature valid; the key was later retired and this bundle predates that)",
            Trust::Revoked => "SENDER KEY REJECTED (signature valid, but you retired this key and this bundle is not covered by it)",
        }
    }
}

/// A contact key you have taken out of service.
///
/// Kept rather than deleted, because deleting it is what turns every bundle
/// that key ever signed into `SENDER UNVERIFIABLE` -- a whole thread history
/// going unattributable the day someone rotates is a bug, not security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retired {
    /// Your name for them at the time, so an old bundle still shows a person.
    pub name: String,
    pub retired_at: String,
    /// The signing key that took over, when this was a rotation rather than
    /// an ending.
    #[serde(default)]
    pub replaced_by: Option<String>,
    /// What the rotation notice said the time was, when one was applied. Kept
    /// as a record and never used to decide a verdict: the party that wrote
    /// it chose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<String>,
    /// Retired because it was STOLEN. Then even old bundles are worthless:
    /// `created` is a field the signer writes, so a thief backdates it. The
    /// honest-rotation case leans on that timestamp; this case cannot.
    #[serde(default)]
    pub compromised: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    /// pubkey -> handle you chose for them. Your label, not their claim.
    #[serde(default)]
    pub keys: BTreeMap<String, String>,
    /// group name -> member pubkeys. A group is a list of keys you trust in
    /// that context, so leaving a group cannot be done by the group.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// signing pubkey -> X25519 pubkey, for sealing to them. Separate map so
    /// contacts added before encryption existed keep working: they can be
    /// verified, just not sealed to.
    #[serde(default)]
    pub box_keys: BTreeMap<String, String>,
    /// retired signing pubkey -> what it was and what replaced it.
    #[serde(default)]
    pub retired: BTreeMap<String, Retired>,
}

impl Contacts {
    pub fn load() -> Self {
        let p = crate::identity::home().join("contacts.json");
        fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = crate::identity::home();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("contacts.json"), serde_json::to_vec_pretty(self)?)
    }

    pub fn knows(&self, pubkey: &str) -> bool {
        self.keys.contains_key(pubkey)
    }

    pub fn name_for(&self, pubkey: &str) -> Option<&str> {
        self.keys.get(pubkey).map(|s| s.as_str())
    }

    /// The name for a key whether it is live or retired. `name_for` stays
    /// live-only, because it is what `open` uses to decide whether a sender
    /// is on your list at all.
    pub fn name_any(&self, pubkey: &str) -> Option<&str> {
        self.name_for(pubkey)
            .or_else(|| self.retired.get(pubkey).map(|r| r.name.as_str()))
    }

    pub fn retired_record(&self, pubkey: &str) -> Option<&Retired> {
        self.retired.get(pubkey)
    }

    /// Trust for a key whose signature already checked out.
    ///
    /// `when` is this machine's record of when the bundle arrived, falling
    /// back to the manifest's own `created` for a bundle that has never been
    /// in this inbox. The distinction is the point: `created` is the signer's
    /// field, so a thief holding an ordinarily-retired key could date a new
    /// bundle before the cutoff and be read as attributable. A compromised
    /// key consults no date at all.
    pub fn verdict(&self, pubkey: &str, when: &str) -> Trust {
        if self.knows(pubkey) {
            return Trust::Known;
        }
        match self.retired.get(pubkey) {
            Some(r) if r.compromised => Trust::Revoked,
            // String comparison is the right one here: RFC3339 UTC with
            // fixed-width fields sorts lexicographically, which is the whole
            // reason this codebase writes timestamps that way.
            Some(r) if when < r.retired_at.as_str() => Trust::Retired,
            Some(_) => Trust::Revoked,
            None => Trust::Unknown,
        }
    }

    /// Every retired key you have held under this name, oldest entry first.
    pub fn retired_keys_for(&self, name: &str) -> Vec<(String, &Retired)> {
        self.retired
            .iter()
            .filter(|(_, r)| r.name == name)
            .map(|(k, r)| (k.clone(), r))
            .collect()
    }

    /// Mark keys already retired under this name as compromised too.
    ///
    /// Retiring the live key says nothing about the ones before it: a stolen
    /// key is not evidence that its predecessor was stolen. But the case
    /// where you learn a machine was owned for months is real, and then
    /// nothing that person ever signed should count. That is this -- a
    /// separate, louder act, because it discards history.
    pub fn mark_history_compromised(&mut self, name: &str, keys: &[String]) {
        for k in keys {
            if let Some(r) = self.retired.get_mut(k) {
                if r.name == name {
                    r.compromised = true;
                }
            }
        }
    }

    /// Take a key out of service. Returns false if it was not a live contact.
    pub fn retire(&mut self, pubkey: &str, at: &str, compromised: bool,
                  replaced_by: Option<String>) -> bool {
        let Some(name) = self.keys.remove(pubkey) else { return false };
        self.box_keys.remove(pubkey);
        self.retired.insert(
            pubkey.to_string(),
            Retired { name, retired_at: at.to_string(), claimed_at: None, replaced_by, compromised },
        );
        true
    }

    /// A retired key you once held under this name. Used to turn "no contact
    /// named bob" into something true, when bob is someone you retired.
    pub fn retired_by_name(&self, name: &str) -> Option<(&str, &Retired)> {
        self.retired
            .iter()
            .find(|(_, r)| r.name == name)
            .map(|(k, r)| (k.as_str(), r))
    }

    pub fn key_for_name(&self, name: &str) -> Option<String> {
        self.keys
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(k, _)| k.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_retired(compromised: bool) -> Contacts {
        let mut c = Contacts::default();
        c.keys.insert("OLD".into(), "bob".into());
        c.retire("OLD", "2026-10-14T12:00:00Z", compromised, Some("NEW".into()));
        c.keys.insert("NEW".into(), "bob".into());
        c
    }

    #[test]
    fn retired_key_covers_only_what_predates_it() {
        let c = with_retired(false);
        assert_eq!(c.verdict("OLD", "2026-10-13T00:00:00Z"), Trust::Retired);
        // The case that gives rotation its meaning. If this returned Retired,
        // a key could be rotated away from and keep sending.
        assert_eq!(c.verdict("OLD", "2026-10-15T00:00:00Z"), Trust::Revoked);
        assert_eq!(c.verdict("NEW", "2026-10-15T00:00:00Z"), Trust::Known);
    }

    #[test]
    fn the_boundary_second_itself_goes_against_the_old_key() {
        // Timestamps have one-second resolution, so "created exactly at the
        // retirement" is genuinely ambiguous. It is resolved against the old
        // key because the two mistakes are not symmetric: a wrongly-rejected
        // honest bundle shows a warning and can be read with --reveal, while
        // a wrongly-accepted one renders a thief's content as attributable.
        // The attacker can aim at this second, too -- the time is in the
        // notice they sent.
        let c = with_retired(false);
        assert_eq!(c.verdict("OLD", "2026-10-14T12:00:00Z"), Trust::Revoked);
    }

    #[test]
    fn a_backdated_bundle_does_not_get_in_on_the_senders_word() {
        // The sequence the codex reviewer found. A key is stolen; the owner
        // rotates for ordinary reasons before anyone knows, so the recipient
        // records the old key as retired-not-compromised. The thief then signs
        // a new bundle with `created` set before the cutoff. What the verdict
        // is given is the recipient's own record of when the bundle arrived,
        // which is after the retirement, so the backdating buys nothing.
        let c = with_retired(false);
        let created_by_thief = "2026-10-01T00:00:00Z";
        let when_it_actually_arrived = "2026-10-20T00:00:00Z";
        assert_eq!(c.verdict("OLD", created_by_thief), Trust::Retired,
                   "the sender's own date is the weak case, kept only for bundles \
                    that were never in this inbox");
        assert_eq!(c.verdict("OLD", when_it_actually_arrived), Trust::Revoked);
    }

    #[test]
    fn a_compromised_key_is_rejected_even_for_old_bundles() {
        // A thief writes the `created` field, so "it is dated before the
        // theft" is not a fact about the bundle.
        let c = with_retired(true);
        assert_eq!(c.verdict("OLD", "2020-01-01T00:00:00Z"), Trust::Revoked);
    }

    #[test]
    fn retiring_removes_the_sealing_key_too() {
        let mut c = Contacts::default();
        c.keys.insert("OLD".into(), "bob".into());
        c.box_keys.insert("OLD".into(), "OLDBOX".into());
        assert!(c.retire("OLD", "2026-10-14T12:00:00Z", false, None));
        // Leaving it would let a later `ctx seal --to bob` encrypt to a key
        // bob has stopped using -- mail that silently goes nowhere.
        assert!(!c.box_keys.contains_key("OLD"));
        assert!(!c.knows("OLD"));
        assert_eq!(c.name_any("OLD"), Some("bob"));
    }

    #[test]
    fn no_verdict_label_is_a_substring_of_another() {
        let all = [
            Trust::Known, Trust::Unknown, Trust::Unverified,
            Trust::Retired, Trust::Revoked,
        ];
        for a in &all {
            for b in &all {
                if a != b {
                    assert!(
                        !a.label().contains(b.label()),
                        "{:?} contains {:?}", a, b
                    );
                }
            }
        }
    }
}
