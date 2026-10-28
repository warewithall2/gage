//! The buddy list, which is the entire access-control model.
//!
//! AIM had this right in 1997: you accept people, and everyone else lands in
//! a queue you decide about. Here the list does double duty -- it decides
//! what reaches your inbox unasked, and it is what turns a signature into a
//! *meaning*. A valid signature only proves the sender holds a key; the
//! allowlist is what says you have ever agreed to hear from that key.
//!
//! Said precisely, because the first version of this note said strangers
//! "cannot reach you" and that was not true: a bundle handed over as a file,
//! or unsealed from a mailbox, is read by `gage open` whoever signed it. What
//! the list controls is the VERDICT and the accept gate, not whether bytes
//! can arrive. Someone who can hand you a file can always hand you a file.
//!
//! ## Being on the list is not the same as having been confirmed
//!
//! A key gets onto this list by several routes, and only one of them involves
//! a human comparing anything: `gage add` takes a key off a web page or out
//! of a chat window, the MCP server adds one on an agent's say-so, and
//! `quickstart` adds one from a token pasted into a prompt. None of those is
//! a confirmation -- they record that something put a key here, which is
//! exactly as strong as the channel it came over.
//!
//! So `confirmed` is a separate map, and the verdict distinguishes them.
//! Before it existed, `SENDER VERIFIED` meant "this key is on the list" while
//! every document described it as meaning "a human compared this key's
//! word-pairs out of band" -- and an agent that could call `gage add` could
//! manufacture the stronger reading. A claim nothing records is not a claim.
//!
//! Keyed by public key, not by handle. A handle is a label anybody can claim.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signature valid, the key is on the allowlist, and a human recorded
    /// confirming its word-pairs over a channel neither machine controls.
    ///
    /// The only verdict that means what the documents say `SENDER VERIFIED`
    /// means, and the only one `authority` will honour a grant under.
    Known,
    /// Signature valid and the key is on the allowlist, but **nothing on this
    /// machine records a human ever confirming it** -- or what was confirmed
    /// no longer covers the key on file, because an encryption key was
    /// attached after the fact.
    ///
    /// Attributable: the signature is good, and a key that signs two bundles
    /// ties them to the same holder. What is missing is any evidence that the
    /// holder is the person whose name is beside it, which is the claim the
    /// word-pair ceremony exists to make and the one `gage add` cannot make
    /// on its own. Contents are NOT withheld -- you put this key on your list
    /// deliberately, and withholding would make the honest ordinary case
    /// useless -- but the verdict stops borrowing a word it has not earned.
    Unconfirmed,
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
// Kept deliberately: with `index` below it, adding a Trust variant becomes a
// build error rather than a silently short list.
#[allow(dead_code)]
pub const ALL: &[Trust] = &[
    Trust::Known,
    Trust::Unconfirmed,
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
    // Unused by design -- its only job is to make the match below exhaustive,
    // so a new variant cannot slip past `ALL`.
    #[allow(dead_code)]
    pub fn index(self) -> usize {
        match self {
            Trust::Known => 0,
            Trust::Unknown => 1,
            Trust::Declined => 2,
            Trust::Unverified => 3,
            Trust::Retired => 4,
            Trust::Revoked => 5,
            Trust::Unwitnessed => 6,
            Trust::Unconfirmed => 7,
        }
    }

    /// Labels are deliberately NOT substrings of one another. The first
    /// version used "KNOWN SENDER" and "UNKNOWN SENDER", and a test that
    /// asserted the absence of the former matched the latter -- so any reader
    /// grepping for trust, an agent included, could read "unknown" as
    /// "known". A safety label that fails a substring check is not a label.
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Known => {
                "SENDER VERIFIED (signature valid, key is on your list, word-pairs confirmed)"
            }
            Trust::Unconfirmed => {
                "SENDER ON YOUR LIST, UNCONFIRMED (signature valid, but nobody here ever compared this key's word-pairs)"
            }
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
    /// signing pubkey -> the out-of-band confirmation a human performed on it.
    ///
    /// Separate from `keys` because they answer different questions. `keys`
    /// says a key is one you accept mail from; this says somebody compared
    /// its word-pairs against the other machine over a channel neither
    /// machine controls. Every route onto `keys` can be driven by software;
    /// the only thing that writes here is a human typing the pairs back at a
    /// terminal, which is why `gage confirm` exists as its own command.
    ///
    /// Absent for every contact added before this map existed, which
    /// deliberately drops them to `SENDER ON YOUR LIST, UNCONFIRMED` until
    /// someone confirms them. That is the honest state: nothing on the
    /// machine records that anyone ever checked. The same bill was paid when
    /// the fingerprint began covering the encryption key, and for the same
    /// reason -- what was confirmed did not cover what it needed to.
    #[serde(default)]
    pub confirmed: BTreeMap<String, Confirmed>,
}

/// A human compared this key's word-pairs and said they matched.
///
/// Holds **nothing the other party wrote**, for the reason `Declined` gives:
/// this file is read by every command. `covers` is derived from key material,
/// and `how` is written by this program, not by a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmed {
    pub at: String,
    /// The observation counter at the moment of confirmation, so a
    /// confirmation can be placed among the arrivals around it.
    #[serde(default)]
    pub seq: u64,
    /// Which route recorded it, in this program's own words -- never a
    /// peer's. Shown to a person asking why a contact counts as confirmed.
    pub how: String,
    /// **The exact fingerprint string that was compared.**
    ///
    /// Checked against the key's current fingerprint on every verdict, which
    /// is what makes the record mean something rather than merely exist. The
    /// case it catches is real and was found by review: a key confirmed from
    /// a bundle carries no encryption key, so what a person compared covers
    /// the signing half alone. Attach an encryption key later and the
    /// fingerprint changes -- and the old confirmation does not cover the new
    /// half, which is precisely the substitution the word-pairs exist to
    /// stop. So it stops counting, and says so.
    pub covers: String,
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
    /// Read the list, or stop the program.
    ///
    /// A missing file is an empty list, which is correct: a machine that has
    /// never added anybody knows nobody. A file that is PRESENT and does not
    /// parse is not an empty list -- it is a list this program cannot read,
    /// and treating it as "you know nobody" is the worst possible reading.
    /// Every contact silently becomes a stranger, every grant stops applying,
    /// and -- the part that makes it a security bug rather than an
    /// inconvenience -- `decline`, `add` and `retire` would then write a fresh
    /// file over the top, destroying the allowlist for good. One stray byte
    /// in this file used to do all of that without printing anything.
    ///
    /// So it stops, with the path and the parse error, and changes nothing.
    /// Failing closed on an unreadable allowlist is the only safe direction,
    /// and a caller that could "handle" this error would handle it by
    /// guessing.
    pub fn load() -> Self {
        let p = crate::identity::home().join("contacts.json");
        let raw = match fs::read_to_string(&p) {
            Ok(r) => r,
            // Any read error, not just not-found: a file that exists and
            // cannot be read is the same situation as one that cannot be
            // parsed, and `unwrap_or_default` treated both as "nobody".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                eprintln!("gage: cannot read your contact list at {}: {e}", p.display());
                eprintln!(
                    "      Refusing to continue: an unreadable allowlist is not an empty one,\n\
                     \x20     and carrying on would treat every contact you have as a stranger\n\
                     \x20     -- then overwrite the file the moment anything added a key."
                );
                std::process::exit(2);
            }
        };
        match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("gage: your contact list at {} does not parse: {e}", p.display());
                eprintln!(
                    "      Refusing to continue, and nothing has been changed. Every verdict\n\
                     \x20     this program prints is computed from this file, so reading it as\n\
                     \x20     an empty list would turn every contact you have confirmed into a\n\
                     \x20     stranger without saying so. Fix the file, or move it aside and\n\
                     \x20     re-add your contacts -- there is a copy in your backup if you\n\
                     \x20     made one with `gage export-identity`."
                );
                std::process::exit(2);
            }
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = crate::identity::home();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("contacts.json"), serde_json::to_vec_pretty(self)?)
    }

    pub fn knows(&self, pubkey: &str) -> bool {
        self.keys.contains_key(pubkey)
    }

    /// The fingerprint a person would be asked to compare for this key, over
    /// whatever halves of it this machine holds.
    pub fn fingerprint_for(&self, pubkey: &str) -> String {
        crate::words::fingerprint_of(pubkey, self.box_keys.get(pubkey).map(|s| s.as_str()))
    }

    /// Has a human confirmed this key's word-pairs, and does what they
    /// confirmed still cover the key on file?
    ///
    /// The second half is the part that earns the record its keep. A
    /// confirmation is not a flag that stays true; it is a statement about a
    /// specific value, and when that value changes the statement expires.
    pub fn is_confirmed(&self, pubkey: &str) -> bool {
        match self.confirmed.get(pubkey) {
            Some(c) => c.covers == self.fingerprint_for(pubkey),
            None => false,
        }
    }

    /// Why a confirmation stopped counting, for a person who is about to ask.
    ///
    /// `None` when it counts or when there never was one -- this answers only
    /// "there is a record and it no longer applies", which is the case nobody
    /// would otherwise work out.
    pub fn stale_confirmation(&self, pubkey: &str) -> Option<&Confirmed> {
        self.confirmed
            .get(pubkey)
            .filter(|c| c.covers != self.fingerprint_for(pubkey))
    }

    /// Record that a human compared this key's word-pairs out of band.
    ///
    /// Takes the pairs they typed and checks them, so the record cannot be
    /// written by something that did not do the comparison. Refuses a key
    /// that is not on the list: confirming is a statement about a contact,
    /// and a confirmation with nothing to attach to would be a stored claim
    /// about a stranger.
    pub fn confirm(&mut self, pubkey: &str, typed: &str, how: &str, seq: u64) -> Result<(), String> {
        if !self.knows(pubkey) {
            return Err("that key is not on your list, so there is nothing to confirm.                         Add it first, then confirm it."
                .to_string());
        }
        let real = self.fingerprint_for(pubkey);
        if !crate::words::echo_matches(typed, &real) {
            // The expected value is never echoed back here, for the reason
            // the viewer and the MCP server both give: telling the caller
            // what it should have said turns a comparison into a two-try
            // copying exercise.
            return Err("those are not this key's word-pairs, so nothing was recorded.                         All four pairs must come back as the OTHER machine shows them.                         If nobody has compared them yet, do not retry -- go and compare them."
                .to_string());
        }
        self.confirmed.insert(
            pubkey.to_string(),
            Confirmed {
                at: crate::bundle::now_rfc3339(),
                seq,
                how: how.to_string(),
                covers: real,
            },
        );
        Ok(())
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
            // On the list is two states, not one. See `Trust::Unconfirmed`:
            // every route onto `keys` can be driven by software, and only a
            // human typing the pairs back writes `confirmed`.
            return if self.is_confirmed(pubkey) {
                Trust::Known
            } else {
                Trust::Unconfirmed
            };
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
            if let Some(r) = self.retired.get_mut(k)
                && r.name == name
            {
                r.compromised = true;
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

/// What the caller is willing to say about an add, beyond the key itself.
///
/// Passed explicitly by every caller rather than defaulted, which is the
/// point: there used to be no way for this function to tell `gage add`
/// (a key off a web page) from `gage pair --confirm` (a human who compared
/// four word-pairs) from the MCP server (an agent's say-so), and so all three
/// produced a contact that printed `SENDER VERIFIED`. A struct with named
/// fields makes a new caller state its case at the call site, where a reader
/// of that caller can judge it.
pub struct AddOpts<'a> {
    /// Set only when a human has just typed this key's word-pairs back,
    /// having read them off the other machine. `None` leaves the contact
    /// unconfirmed, which is a working, useful state and not an error.
    ///
    /// Carries the pairs themselves rather than a boolean, so this function
    /// checks them against the key instead of trusting the caller to have
    /// done it. That matters most in the case review found: a key confirmed
    /// from a bundle has no encryption half, so a signing-only comparison
    /// cannot confirm a sealable contact -- and with a boolean the call site
    /// would simply assert that it had.
    pub confirmed: Option<Confirmation<'a>>,
    /// The caller has been told, by a human, to put back a key this machine
    /// retired or declined.
    ///
    /// Adding over such a record used to happen silently with a `note:` line,
    /// which meant an agent calling `add` could undo a revocation and the
    /// only trace was a line in output nobody had to read. Now the add is
    /// refused unless this is set, and the only thing that sets it is a flag
    /// a person typed.
    pub reinstate: bool,
    /// This machine generated the key itself, moments ago, and there is no
    /// channel to compare anything over.
    ///
    /// The one honest confirmation with no comparison in it, and it exists
    /// for exactly one caller: `gage agent new`, which makes a second
    /// identity in a directory beside this one and registers each with the
    /// other. There is no other party, no channel for anybody to sit on, and
    /// nothing a word-pair could tell you that this process does not already
    /// know -- it ran the keygen. Demanding a ceremony there would teach
    /// people that the ceremony is paperwork.
    ///
    /// Narrow on purpose. It must never be set for a key that came from
    /// anywhere other than this process's own `gage init`.
    pub same_machine: bool,
    /// The observation counter to stamp a confirmation with.
    pub seq: u64,
}

/// The word-pairs a human just typed back, and how they came to.
pub struct Confirmation<'a> {
    /// What they typed. Checked, not trusted.
    pub echo: &'a str,
    /// A short phrase naming the route, written by this program and never by
    /// a peer, shown to someone asking why a contact counts as confirmed.
    pub how: &'a str,
}

impl AddOpts<'_> {
    /// An add that confirms nothing and reinstates nothing: a key arriving
    /// over a channel this machine cannot vouch for.
    pub fn plain() -> Self {
        AddOpts {
            confirmed: None,
            reinstate: false,
            same_machine: false,
            seq: 0,
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
/// callers is a web page.
pub fn add_contact(name: &str, key: &str, opts: AddOpts) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let (sign, boxpub) = crate::identity::split_key(key);
    if !crate::bundle::b64_decode_ok(&sign) {
        return Err("that signing key is not valid base64".to_string());
    }
    if let Some(b) = &boxpub
        && !crate::bundle::b64_decode_ok(b)
    {
        return Err("that encryption key is not valid base64".to_string());
    }
    let mut c = Contacts::load();
    // Adding an existing name under a DIFFERENT key used to just overwrite
    // it, which is key rotation performed by accident and with no record:
    // every bundle the old key signed turned into SENDER UNVERIFIABLE, and a
    // stranger's key could take over a trusted name in one command.
    // `keychange` is the operation that does this with evidence; `retire` is
    // the one that does it deliberately without.
    if let Some(existing) = c.key_for_name(name)
        && existing != sign
    {
        return Err(format!(
            "{name} is already on your list under a different key. This would \
                 replace it and orphan everything that key signed.\n  \
                 If they rotated: gage keychange <their notice file> --accept\n  \
                 If you are doing it by hand: gage retire {name}, then add them \
                 again under a name you choose"
        ));
    }
    // A retirement and a decline are decisions a human took to narrow this
    // list, and undoing one is a bigger act than "add". Both used to be
    // cleared here with a `note:` line in the output -- so anything that
    // could call `add`, the MCP server included, could put a revoked key back
    // in service and the only record was a line a caller could ignore.
    // Reversing a decision is now its own, stated act: `--reinstate`.
    if let Some(r) = c.retired_record(&sign) {
        if r.compromised {
            return Err(format!(
                "that key is recorded as COMPROMISED (retired {}). Re-adding it undoes \
                 that decision; if it really is safe again, edit contacts.json \
                 deliberately.",
                r.retired_at
            ));
        }
        if !opts.reinstate {
            return Err(format!(
                "you retired this key on {}. Adding it again puts a key you took out \
                 of service back into it, so it is not something `add` does quietly:\n  \
                 gage add {name} <key> --reinstate\n  \
                 If you did not retire it and do not know why it is on that list, do \
                 not reinstate it -- ask them over another channel first.",
                r.retired_at
            ));
        }
        out.push(format!(
            "REINSTATED: you retired this key on {} and it is back in service",
            r.retired_at
        ));
        let k = sign.clone();
        c.retired.remove(&k);
    }
    // A name you retired is still a name your reader recognises, and
    // `authority` matches grants by name: `allow alice review-request`
    // follows whoever holds the name "alice" now. Retiring alice frees the
    // name, so a different key added under it used to inherit her grants
    // with nothing said. Found by review, twice over.
    if let Some((oldk, r)) = c.retired_by_name(name)
        && oldk != sign
        && !opts.reinstate
    {
        return Err(format!(
            "you retired a DIFFERENT key under the name {name} on {}. Re-using that \
             name hands this key anything you granted to the old one -- `gage authority` \
             matches grants by name, not by key -- and makes every bundle the old key \
             signed look like this one.\n  \
             Pick a name you have not used, or, if you mean to re-use it:\n  \
             gage add {name} <key> --reinstate\n  \
             Either way, check `gage authority` afterwards.",
            r.retired_at
        ));
    }
    // An explicit add is a later decision than a decline, so it overrides
    // it -- but it says so. A human who declined this key last week and is
    // now adding it should see that, because the ordinary cause of adding a
    // key you refused is being asked twice by something that wants in.
    if let Some(d) = c.declined.get(&sign).cloned() {
        if !opts.reinstate {
            return Err(format!(
                "you looked at this key on {} and refused it. Adding it now reverses \
                 that decision, so say so:\n  \
                 gage add {name} <key> --reinstate\n  \
                 The ordinary reason to be adding a key you refused is that something \
                 asked you twice.",
                d.at
            ));
        }
        c.declined.remove(&sign);
        out.push(format!(
            "REINSTATED: you declined this key on {} and that is now reversed",
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
    // Both halves. The value a person is asked to confirm has to cover the
    // encryption key too, or an attacker substitutes the half nobody checks
    // and the comparison passes while they read everything.
    let words = c.key_for_name(name).map(|k| c.fingerprint_for(&k));

    // A caller that watched a human compare the pairs says so, and the record
    // is written from the key material rather than from the caller's word for
    // it -- `confirm` recomputes and compares. A caller that did not, does
    // not, and the contact works while reading `UNCONFIRMED` until somebody
    // does. That is the whole of the difference the review found missing.
    if let Some(cf) = &opts.confirmed {
        let k = c.key_for_name(name).unwrap_or_default();
        c.confirm(&k, cf.echo, cf.how, opts.seq)?;
    } else if opts.same_machine {
        // No echo to check, because there is nothing to compare: see
        // `AddOpts::same_machine`. The fingerprint is computed here rather
        // than taken from the caller, so the record still describes the key
        // actually on file.
        let k = c.key_for_name(name).unwrap_or_default();
        let w = c.fingerprint_for(&k);
        c.confirm(&k, &w, "key generated on this machine", opts.seq)?;
    }
    c.save().map_err(|e| e.to_string())?;

    // Shown AFTER the add, not before, because this is the step where a
    // person checks they added the key they meant to. An out-of-band
    // confirmation is the only thing that makes a key belong to a person, and
    // it is a great deal easier to do when the thing being compared can be
    // read aloud.
    if let Some(w) = words {
        out.push(String::new());
        out.push(format!("  this key says : {w}"));
        match &opts.confirmed.as_ref().map(|cf| cf.how).or(if opts.same_machine {
            Some("key generated on this machine")
        } else {
            None
        }) {
            Some(how) => {
                out.push(format!("  confirmed     : {how}"));
                out.push(format!(
                    "  Bundles signed by this key will read SENDER VERIFIED."
                ));
            }
            None => {
                // Said plainly, because the previous version of these lines
                // asked for the comparison and then printed `SENDER
                // VERIFIED` whether or not anyone did it. Asking for
                // something and not noticing when it does not happen is how
                // a ceremony becomes decoration.
                out.push(format!(
                    "  Read those four pairs to {name} over a channel that is NOT this one \
                     -- a voice call, in person."
                ));
                out.push("  If their machine says anything else, you have the wrong key."
                    .to_string());
                out.push(String::new());
                out.push(format!(
                    "  Until you do, bundles from this key read SENDER ON YOUR LIST, \
                     UNCONFIRMED."
                ));
                out.push(format!("  Once you have compared them:  gage confirm {name}"));
            }
        }
    }
    Ok(out)
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
        // On the list, and nobody compared it: the replacement key arrived
        // in a rotation notice, which is a channel, not a confirmation.
        assert_eq!(c.verdict("NEW", Some(11)), Trust::Unconfirmed);
    }

    #[test]
    fn on_the_list_is_not_confirmed_until_somebody_confirms_it() {
        // The property the whole record exists for. Before it, these two
        // situations produced the same verdict, and every document described
        // that verdict as meaning the second one.
        let mut c = Contacts::default();
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        c.keys.insert(k.into(), "bob".into());
        assert_eq!(c.verdict(k, Some(1)), Trust::Unconfirmed);
        assert!(!c.is_confirmed(k));

        // A confirmation is checked against the key, not taken on trust, so
        // a caller cannot assert its way to `Known`.
        assert!(c.confirm(k, "wrong words entirely", "test", 1).is_err());
        assert_eq!(c.verdict(k, Some(1)), Trust::Unconfirmed);

        let fp = c.fingerprint_for(k);
        c.confirm(k, &fp, "test", 1).unwrap();
        assert_eq!(c.verdict(k, Some(1)), Trust::Known);
        assert!(c.stale_confirmation(k).is_none());

        // And it expires when what was confirmed stops covering the key.
        // This is the substitution the word-pairs exist to catch: the signing
        // half was compared, an encryption half was attached afterwards, and
        // nobody ever looked at the value that now matters.
        c.box_keys.insert(
            k.into(),
            "7amQkpwKszbeF801n5EzMRm4jQlx3BylW8c59lsDcX0=".into(),
        );
        assert!(!c.is_confirmed(k));
        assert_eq!(c.verdict(k, Some(1)), Trust::Unconfirmed);
        assert!(
            c.stale_confirmation(k).is_some(),
            "a confirmation that stopped covering the key must be \
             distinguishable from never having had one"
        );
        // Confirming a key that is not on the list has nothing to attach to.
        assert!(c.confirm("STRANGER", "anything", "test", 1).is_err());
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
    fn every_verdict_is_listed_in_the_documents_that_tabulate_them() {
        // A cross-file drift test, and it is here because this exact mistake
        // has now been made three times: `spec.md` listed six verdicts when
        // the code had seven, `docs/agents.md` listed six and was missing two
        // (one of which WITHHOLDS CONTENTS), and `AGENTS.md` listed five.
        // Each was found by a human reading, which is not a mechanism.
        //
        // A reader checking a verdict against one of these tables and not
        // finding it does not conclude the table is wrong -- they conclude
        // they misread the verdict, or they guess. For an agent branching on
        // the label, a missing row is a branch that falls through to whatever
        // the catch-all does.
        //
        // So every document that claims to enumerate verdicts must contain
        // every one. `ALL` is kept complete by `index`'s exhaustive match, so
        // adding a variant fails to build until it is listed, and then fails
        // this test until it is documented.
        for doc in [
            ("docs/spec.md", include_str!("../docs/spec.md")),
            ("docs/agents.md", include_str!("../docs/agents.md")),
            ("AGENTS.md", include_str!("../AGENTS.md")),
        ] {
            let (name, body) = doc;
            for t in ALL {
                // The label up to its parenthetical, which is the part these
                // tables print and the part a reader matches on.
                let key = t.label().split(" (").next().unwrap_or(t.label());
                assert!(
                    body.contains(key),
                    "{name} does not mention the verdict {key:?}. Every document that \
                     tabulates verdicts has to carry all of them -- a short list reads as \
                     a complete one."
                );
            }
        }
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
