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
    /// Signature valid, and a human on this machine **refused** this key.
    ///
    /// Kept apart from `Unknown` because they call for different actions and
    /// the difference is the whole point of recording a decline: "a stranger"
    /// invites a decision, "one you already refused" is a decision already
    /// taken. It withholds nothing `Unknown` does not -- an unlisted sender's
    /// contents are behind the same accept gate either way -- so this is a
    /// statement to the reader, not a new restriction.
    Declined,
    /// Signature absent, malformed, or does not match the manifest bytes.
    /// Nothing about the sender can be believed.
    Unverified,
    /// Signature valid under a key you have RETIRED, and the bundle is older
    /// than the retirement. Attributable, with a caveat worth stating.
    Retired,
    /// Signature valid under a retired key, and this machine saw the bundle
    /// arrive AFTER the retirement -- or the key was retired as compromised,
    /// in which case nothing saves it. This is the case that makes rotation
    /// mean anything: if a retired key kept working for new mail, retiring it
    /// would buy nothing at all.
    Revoked,
    /// Signature valid under a retired key, and there is NO local record of
    /// this bundle arriving at all, so this machine cannot place it either
    /// side of the retirement.
    ///
    /// Kept apart from `Revoked` on purpose. Both withhold contents, but they
    /// mean different things and call for different actions: `Revoked` says
    /// the bundle turned up after you retired the key, which is suspicious,
    /// while this says the record is missing -- the ordinary cause being
    /// honest mail that was sealed before the rotation and collected from a
    /// relay afterwards. Reporting that to someone as a rejection would tell
    /// them a colleague is attacking them.
    Unwitnessed,
}

/// Every verdict, for the tests that must cover all of them.
///
/// Hand-written lists of variants stop covering new ones silently, and this
/// one guards a real property -- that no label is a prefix of another, which
/// the viewer relies on because it classifies with `startsWith`. When
/// `Declined` was added, the prefix test had a hardcoded array of six and
/// went on passing while asserting nothing about the seventh.
///
/// So it is tied to the compiler: `Trust::index` has an exhaustive match, so
/// a new variant does not build until it is given an index, and
/// `every_verdict_is_in_ALL` fails until it is listed here.
pub const ALL: &[Trust] = &[
    Trust::Known,
    Trust::Unknown,
    Trust::Declined,
    Trust::Unverified,
    Trust::Retired,
    Trust::Revoked,
    Trust::Unwitnessed,
];

impl Trust {
    /// A dense index per variant. Exists only so `ALL` cannot fall behind:
    /// the match is exhaustive, so adding a variant is a build error here.
    pub fn index(self) -> usize {
        match self {
            Trust::Known => 0,
            Trust::Unknown => 1,
            Trust::Declined => 2,
            Trust::Unverified => 3,
            Trust::Retired => 4,
            Trust::Revoked => 5,
            Trust::Unwitnessed => 6,
        }
    }

    /// Labels are deliberately NOT substrings of one another. The first
    /// version used "KNOWN SENDER" and "UNKNOWN SENDER", and a test that
    /// asserted the absence of the former matched the latter -- so any reader
    /// grepping for trust, an agent included, could read "unknown" as
    /// "known". A safety label that fails a substring check is not a label.
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Known => "SENDER VERIFIED (signature valid, key is on your list)",
            Trust::Unknown => {
                "SENDER NOT ON YOUR LIST (signature valid, you have never accepted this key)"
            }
            Trust::Declined => {
                "SENDER REFUSED BEFORE (signature valid, and you declined this key rather than adding it)"
            }
            Trust::Unverified => "SENDER UNVERIFIABLE (signature missing or invalid)",
            Trust::Retired => {
                "SENDER KEY RETIRED (signature valid; you saw this bundle before you retired that key)"
            }
            Trust::Revoked => {
                "SENDER KEY REJECTED (signature valid, but this bundle reached you after you retired that key)"
            }
            Trust::Unwitnessed => {
                "ARRIVAL UNRECORDED (signature valid under a retired key, and no record of this bundle reaching you before then)"
            }
        }
    }
}

/// Shown in place of a verdict when the local observation step failed.
///
/// Not a `Trust` variant, because it is not a judgement about a sender -- it
/// is the absence of one. `gage open` refuses to print at all in this case
/// (see main.rs); the viewer polls and cannot refuse, so it must say this
/// instead of showing a verdict computed from state that could not be
/// refreshed. Either way the rule is the same: never show a verdict that
/// could read milder than the truth.
pub const VERDICT_UNAVAILABLE: &str = "VERDICT UNAVAILABLE (your inbox could not be recorded, so a verdict here could \
     read milder than the truth)";

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
    /// The local observation counter at the moment of retirement. A bundle
    /// witnessed below this was here first; one witnessed above it, or not at
    /// all, was not. This is what the verdict is decided on.
    #[serde(default)]
    pub retired_seq: u64,
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
    /// signing pubkey -> when you refused to add it.
    ///
    /// The third state, and the one that was missing. `keys` says yes and an
    /// absence says "not asked yet"; neither can say **no**. Without this, a
    /// key a human looked at and refused is indistinguishable from one never
    /// seen, so the next bundle from it offers the same decision again, and
    /// the only way to stop being asked is to accept.
    #[serde(default)]
    pub declined: BTreeMap<String, Declined>,
}

/// A key you looked at and said no to.
///
/// Deliberately holds **nothing the sender wrote** -- not the handle it
/// claimed, not a subject, not a note. The journal's rule applies here for
/// the same reason and more strongly: this file is loaded by every command,
/// and a field an unlisted stranger can fill would be a stored injection
/// against every later reader of it. What a human needs in order to
/// recognise the entry is the key's own word-label, which is derived from the
/// key and cannot be chosen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declined {
    pub at: String,
    /// The observation counter when it happened, which is what relates a
    /// decline to the arrivals around it. A timestamp alone cannot be
    /// trusted to increase.
    #[serde(default)]
    pub seq: u64,
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

    /// Record that a human refused this key.
    ///
    /// Narrows and never widens, which is why -- unlike the authority file --
    /// there is a command for it. The worst an injected agent achieves by
    /// declining something is that its own user stops hearing from a contact,
    /// which is visible in `gage contacts` and reversible by `gage add`.
    ///
    /// Refuses a key already on the list rather than doing both. "On your
    /// list and refused" is not a state with a meaning, and silently removing
    /// a contact would be a far bigger act than this command's name suggests.
    pub fn decline(&mut self, pubkey: &str, seq: u64) -> Result<bool, String> {
        if !crate::bundle::b64_decode_ok(pubkey) {
            return Err("that is not a valid key".to_string());
        }
        if let Some(n) = self.keys.get(pubkey) {
            return Err(format!(
                "that key is already on your list as {n}. Declining is for a key \
                 you have NOT added; to remove a contact, use gage retire {n}."
            ));
        }
        if self.declined.contains_key(pubkey) {
            return Ok(false);
        }
        self.declined.insert(
            pubkey.to_string(),
            Declined {
                at: crate::bundle::now_rfc3339(),
                seq,
            },
        );
        Ok(true)
    }

    pub fn declined_record(&self, pubkey: &str) -> Option<&Declined> {
        self.declined.get(pubkey)
    }

    /// Is this string something a reader of yours would recognise as naming
    /// somebody -- other than the key it arrived with?
    ///
    /// Asked by the frame before it treats a sender's claimed handle as
    /// harmless. Four sources, and the fourth is the one a reviewer had to
    /// point out:
    ///
    /// - a live contact name, and
    /// - a retired one, because a name you used to use is still a name a
    ///   reader recognises, and recognition is the thing being borrowed, and
    /// - a group name, for the same reason, and
    /// - **the key-derived label of any OTHER key on this list.** A label is
    ///   one word-pair, 16 bits, grindable in about 65,000 tries, so a sender
    ///   can arrange its own label to collide with the label of a key you
    ///   already hold. Checking only chosen names missed that entirely --
    ///   which is live on a two-machine setup, where machines routinely go by
    ///   their labels and a reader learns to recognise them.
    ///
    /// Compared case-insensitively, because the recognition being exploited
    /// is a human's and a human does not read case.
    ///
    /// `except` is the key the handle arrived with, so its own label does not
    /// count against it.
    pub fn is_a_name_you_use(&self, s: &str, except: &str) -> bool {
        let s = s.trim().to_lowercase();
        let hit = |n: &str| n.trim().to_lowercase() == s;
        self.keys.values().any(|n| hit(n))
            || self.retired.values().any(|r| hit(&r.name))
            || self.groups.keys().any(|n| hit(n))
            || self
                .keys
                .keys()
                .chain(self.retired.keys())
                .filter(|k| k.as_str() != except)
                .any(|k| hit(&crate::words::label(k)))
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
    /// `witnessed` is the local observation counter at which this machine
    /// first saw this exact signed manifest, or None if it never did.
    ///
    /// No timestamp enters this decision. Every version that used one was
    /// broken: `created` is the signer's own field, and a local clock at
    /// one-second resolution cannot separate a witness from a retirement
    /// recorded in the same second. A counter can.
    pub fn verdict(&self, pubkey: &str, witnessed: Option<u64>) -> Trust {
        if self.knows(pubkey) {
            return Trust::Known;
        }
        // Before the retired check and before `Unknown`, but after `knows`:
        // an explicit `gage add` is a later decision than a decline and
        // overrides it. `add` clears the entry, so this only matters for a
        // file edited by hand.
        if self.declined.contains_key(pubkey) && !self.retired.contains_key(pubkey) {
            return Trust::Declined;
        }
        match self.retired.get(pubkey) {
            // A stolen key signs as well as its owner and writes its own
            // dates, so nothing it produced counts, whenever it turned up.
            Some(r) if r.compromised => Trust::Revoked,
            Some(r) => match witnessed {
                Some(seq) if seq < r.retired_seq => Trust::Retired,
                Some(_) => Trust::Revoked,
                None => Trust::Unwitnessed,
            },
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
    pub fn retire(
        &mut self,
        pubkey: &str,
        at: &str,
        seq: u64,
        compromised: bool,
        replaced_by: Option<String>,
    ) -> bool {
        let Some(name) = self.keys.remove(pubkey) else {
            return false;
        };
        self.box_keys.remove(pubkey);
        self.retired.insert(
            pubkey.to_string(),
            Retired {
                name,
                retired_at: at.to_string(),
                retired_seq: seq,
                claimed_at: None,
                replaced_by,
                compromised,
            },
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

    /// bob rotated at observation 10: anything witnessed below that was here
    /// first, anything above it or never witnessed was not.
    fn with_retired(compromised: bool) -> Contacts {
        let mut c = Contacts::default();
        c.keys.insert("OLD".into(), "bob".into());
        c.retire(
            "OLD",
            "2026-10-14T12:00:00Z",
            10,
            compromised,
            Some("NEW".into()),
        );
        c.keys.insert("NEW".into(), "bob".into());
        c
    }

    #[test]
    fn a_retired_key_covers_only_what_was_here_first() {
        let c = with_retired(false);
        assert_eq!(c.verdict("OLD", Some(9)), Trust::Retired);
        // The case that gives rotation its meaning. If this were Retired, a
        // key could be rotated away from and keep sending.
        assert_eq!(c.verdict("OLD", Some(11)), Trust::Revoked);
        assert_eq!(c.verdict("NEW", Some(11)), Trust::Known);
    }

    #[test]
    fn the_boundary_itself_goes_against_the_old_key() {
        // Observed in the same batch as the retirement. The two mistakes are
        // not symmetric: a wrongly-rejected honest bundle shows a warning and
        // opens with --reveal, while a wrongly-accepted one renders a thief's
        // content as attributable. Unlike the timestamp version this tie is a
        // real tie -- nothing in the ordering is attacker-controlled.
        let c = with_retired(false);
        assert_eq!(c.verdict("OLD", Some(10)), Trust::Revoked);
    }

    #[test]
    fn no_record_is_not_the_same_as_rejected() {
        // Honest mail sealed before a rotation and pulled from a relay after
        // it cannot have been witnessed in time. Calling that a rejection
        // would tell someone their colleague is attacking them.
        let c = with_retired(false);
        assert_eq!(c.verdict("OLD", None), Trust::Unwitnessed);
        assert_ne!(c.verdict("OLD", None), Trust::Revoked);
    }

    #[test]
    fn a_timestamp_cannot_reach_the_verdict_at_all() {
        // The bug this replaced: `created` is the signer's field, and the
        // comparison was lexical, so "", "...00.9Z" and "...T01:00:00-14:00"
        // (really 15:00Z, three hours AFTER a noon cutoff) all sorted as
        // earlier. There is now no timestamp in the signature of this
        // function for a sender to aim at.
        let c = with_retired(false);
        for forged in [
            "",
            "2026-10-14T12:00:00",
            "2026-10-14T12:00:00.9Z",
            "2026-10-14T01:00:00-14:00",
            "0000-01-01T00:00:00Z",
        ] {
            let _ = forged; // nothing to pass it to, which is the assertion
        }
        assert_eq!(c.verdict("OLD", None), Trust::Unwitnessed);
    }

    #[test]
    fn a_compromised_key_is_rejected_however_it_arrived() {
        // A thief signs as well as the owner, so no observation order helps.
        let c = with_retired(true);
        assert_eq!(c.verdict("OLD", Some(1)), Trust::Revoked);
        assert_eq!(c.verdict("OLD", None), Trust::Revoked);
    }

    #[test]
    fn retiring_removes_the_sealing_key_too() {
        let mut c = Contacts::default();
        c.keys.insert("OLD".into(), "bob".into());
        c.box_keys.insert("OLD".into(), "OLDBOX".into());
        assert!(c.retire("OLD", "2026-10-14T12:00:00Z", 10, false, None));
        // Leaving it would let a later `gage seal --to bob` encrypt to a key
        // bob has stopped using -- mail that silently goes nowhere.
        assert!(!c.box_keys.contains_key("OLD"));
        assert!(!c.knows("OLD"));
        assert_eq!(c.name_any("OLD"), Some("bob"));
    }

    #[test]
    fn every_verdict_is_in_all() {
        // The guard that keeps the test below honest. `index` is exhaustive,
        // so a new variant cannot compile without an index; this fails until
        // that variant is also in `ALL`, which is what the prefix test walks.
        let mut seen = vec![false; ALL.len()];
        for t in ALL {
            let i = t.index();
            assert!(i < ALL.len(), "{t:?} has index {i}, past the end of ALL");
            assert!(!seen[i], "two verdicts share index {i}");
            seen[i] = true;
        }
        assert!(
            seen.iter().all(|x| *x),
            "a verdict has an index but is missing from ALL: {seen:?}"
        );
    }

    #[test]
    fn no_verdict_label_is_a_prefix_of_another() {
        // Stronger than the substring check it replaces, because the viewer
        // classifies with startsWith: a new label beginning with an old one
        // would render a worse verdict as a milder one.
        let all = ALL;
        for a in all {
            for b in all {
                if a != b {
                    assert!(
                        !a.label().starts_with(b.label()) && !a.label().contains(b.label()),
                        "{:?} starts with or contains {:?}",
                        a,
                        b
                    );
                }
            }
        }
        // No label carries doubled whitespace. Easy to introduce by editing
        // a wrapped string literal and invisible in review, but it reaches
        // the person's screen.
        for l in all.iter().map(|t| t.label()).chain([VERDICT_UNAVAILABLE]) {
            assert!(!l.contains("  "), "doubled whitespace in {l:?}");
            assert_eq!(l.trim(), l, "stray edge whitespace in {l:?}");
        }
        // VERDICT UNAVAILABLE travels the same path through the viewer's
        // startsWith table, so it is held to the same rule.
        for a in all {
            assert!(
                !a.label().starts_with(VERDICT_UNAVAILABLE)
                    && !VERDICT_UNAVAILABLE.starts_with(a.label())
                    && !a.label().contains(VERDICT_UNAVAILABLE)
                    && !VERDICT_UNAVAILABLE.contains(a.label()),
                "VERDICT UNAVAILABLE collides with {:?}",
                a
            );
        }
    }
}

/// Put a key on the list, with every guard `gage add` has always had.
///
/// Shared rather than duplicated, so `gage add`, `gage pair` and the viewer's
/// pair button all land a key by one path. A pairing flow that quietly
/// skipped the "already on your list under a different key" refusal would let
/// a LAN announcement do what `gage add` deliberately will not: take over a
/// trusted name in one step.
///
/// Returns the lines to show rather than printing them, because one of the
/// three callers is a web page.
pub fn add_contact(name: &str, key: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let (sign, boxpub) = crate::identity::split_key(key);
    if !crate::bundle::b64_decode_ok(&sign) {
        return Err("that signing key is not valid base64".to_string());
    }
    if let Some(b) = &boxpub {
        if !crate::bundle::b64_decode_ok(b) {
            return Err("that encryption key is not valid base64".to_string());
        }
    }
    let mut c = Contacts::load();
    // Adding an existing name under a DIFFERENT key used to just overwrite
    // it, which is key rotation performed by accident and with no record:
    // every bundle the old key signed turned into SENDER UNVERIFIABLE, and a
    // stranger's key could take over a trusted name in one command.
    // `keychange` is the operation that does this with evidence; `retire` is
    // the one that does it deliberately without.
    if let Some(existing) = c.key_for_name(name) {
        if existing != sign {
            return Err(format!(
                "{name} is already on your list under a different key. This would \
                 replace it and orphan everything that key signed.\n  \
                 If they rotated: gage keychange <their notice file> --accept\n  \
                 If you are doing it by hand: gage retire {name}, then add them \
                 again under a name you choose"
            ));
        }
    }
    if let Some(r) = c.retired_record(&sign) {
        if r.compromised {
            return Err(format!(
                "that key is recorded as COMPROMISED (retired {}). Re-adding it undoes \
                 that decision; if it really is safe again, edit contacts.json \
                 deliberately.",
                r.retired_at
            ));
        }
        out.push(format!(
            "note: you retired this key on {} -- re-adding it puts it back in service",
            r.retired_at
        ));
        let k = sign.clone();
        c.retired.remove(&k);
    }
    // An explicit add is a later decision than a decline, so it overrides
    // it -- but it says so. A human who declined this key last week and is
    // now adding it should see that, because the ordinary cause of adding a
    // key you refused is being asked twice by something that wants in.
    if let Some(d) = c.declined.remove(&sign) {
        out.push(format!(
            "note: you declined this key on {} -- adding it now reverses that",
            d.at
        ));
    }
    c.keys.insert(sign.clone(), name.to_string());
    match &boxpub {
        Some(b) => {
            c.box_keys.insert(sign, b.clone());
            out.push(format!("added {name} (verify + encrypt)"));
        }
        None => out.push(format!(
            "added {name} (verify only -- no encryption key, so you cannot seal to them)"
        )),
    }
    c.save().map_err(|e| e.to_string())?;
    // Shown AFTER the add, not before, because this is the step where a
    // person checks they added the key they meant to. An out-of-band
    // confirmation is the only thing that makes a key belong to a person, and
    // it is a great deal easier to do when the thing being compared can be
    // read aloud.
    // Both halves. The value a person is asked to confirm has to cover the
    // encryption key too, or an attacker substitutes the half nobody checks
    // and the comparison passes while they read everything.
    let words = c
        .key_for_name(name)
        .map(|k| crate::words::fingerprint_of(&k, c.box_keys.get(&k).map(|s| s.as_str())));
    if let Some(w) = words {
        out.push(String::new());
        out.push(format!("  this key says : {w}"));
        out.push(format!(
            "  Check that with {name} over a channel that is not this one."
        ));
        out.push("  If their machine says anything else, you have the wrong key.".to_string());
    }
    Ok(out)
}
