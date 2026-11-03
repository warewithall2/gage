//! Reading and writing bundles on disk.
//!
//! A bundle is a directory, not an archive, so a human can look inside it
//! with `ls` before any agent reads it. Inspectability beats compactness for
//! something whose job is to be trusted.
//!
//! The signature covers the manifest file's EXACT BYTES, which are stored and
//! re-read rather than re-serialized. Re-serializing to verify would make the
//! check depend on serializer field order and whitespace -- a canonicalization
//! problem that has broken real signing schemes.

use crate::identity::Identity;
use crate::manifest::{
    AgentInfo, FORMAT_VERSION, Hop, HopAction, Item, ItemKind, Manifest, Peer, one_line,
    path_is_safe,
};
use crate::trust::{Contacts, Trust};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// The witness for a bundle: the signer's key and the exact bytes their
/// signature covers.
///
/// Deliberately not the bundle id. `load` never recomputes the id, so the
/// signer chooses it, and a witness keyed on it was transferable: take an id
/// this machine stamped before a retirement, attach a different payload, sign
/// with the retired key, and inherit the witness. These bytes are the ones the
/// signature is over, so a different document is a different witness.
pub fn witness_of(from_key: &str, manifest_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(from_key.as_bytes());
    h.update([0x1f]);
    h.update(manifest_bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The witness for a bundle directory, but ONLY if the bundle is sound:
/// signature valid over these bytes, id addressing this content, declared
/// paths safe, and stored payload matching its digests.
///
/// Verifying here is not belt-and-braces, it is the whole point. An earlier
/// version recorded the hash without looking at `manifest.sig`, which let an
/// attacker pre-seed a witness: deliver a directory with the right manifest
/// bytes and a junk signature while the old key was still current, let
/// observation stamp it, then drop the real signature in afterwards. The
/// bundle then verified against a witness recorded before the retirement
/// although nothing authentic had ever been seen. The codex reviewer found
/// that sequence.
// The no-override form of `witness_if_sound_unless`; kept as the API every
// caller but the skip-optimising one should reach for.
#[allow(dead_code)]
pub fn witness_if_sound(dir: &Path) -> Option<String> {
    witness_if_sound_unless(dir, &|_| false)
}

/// As `witness_if_sound`, but `known` lets the caller say a witness is already
/// recorded so the expensive half can be skipped.
///
/// The cheap half is reading `manifest.json` and hashing it. The expensive
/// half is one signature verification plus a full re-read and re-hash of every
/// payload, and the retirement path does that for the whole inbox while
/// holding the state lock. Bounding it to bundles that are actually new keeps
/// a large inbox from pushing that hold past anyone's patience.
pub fn witness_if_sound_unless(dir: &Path, known: &dyn Fn(&str) -> bool) -> Option<String> {
    let bytes = fs::read(dir.join("manifest.json")).ok()?;
    let m: Manifest = serde_json::from_slice(&bytes).ok()?;
    let w = witness_of(&m.from.key, &bytes);
    if known(&w) {
        return Some(w);
    }
    let sig = fs::read_to_string(dir.join("manifest.sig")).ok()?;
    if sig.trim().is_empty() || !crate::identity::verify(&m.from.key, &bytes, &sig) {
        return None;
    }
    if m.expected_id().as_deref() != Some(m.id.as_str()) {
        return None;
    }
    for it in &m.items {
        if !path_is_safe(&it.path) {
            return None;
        }
        match fs::read(dir.join(&it.path)) {
            Ok(d) if sha256_hex(&d) == it.sha256 => {}
            _ => return None,
        }
    }
    Some(w)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs)
}

/// A UTC timestamp from seconds since the epoch.
///
/// Split out from `now_rfc3339` so that a cutoff -- "sends in the last 7
/// days" -- is formatted by the same code that writes the field it will be
/// compared against. Two formatters for one format is how a comparison that
/// looks like string equality stops being one.
pub fn rfc3339(secs: i64) -> String {
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (mut y, mut d) = (1970i64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if d < len {
            break;
        }
        d -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while d >= ml[m] {
        d -= ml[m];
        m += 1;
    }
    format!(
        "{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        m + 1,
        d + 1,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Seconds since the epoch for an RFC 3339 timestamp, or None if it is not
/// one.
///
/// The inverse of `rfc3339`, and a real parser rather than a string compare,
/// which is the whole reason it exists. Everything else in this tree that
/// orders timestamps -- `created` in the inbox listing, the `--since` window --
/// compares strings, and that is sound BECAUSE both sides were written by
/// `rfc3339`: fixed width, UTC, `Z`. An expiry is different in kind. It is the
/// one timestamp a sender may type by hand, and any other client may write,
/// so it can legitimately arrive as `2026-11-05T09:00:00+02:00` or with
/// fractional seconds -- both of which sort WRONG against a `Z` string and
/// would make a live bundle read as expired, or an expired one as live.
///
/// So the offset is applied and the result is a number. Fractional seconds
/// are accepted and discarded: a bundle's freshness is not decided in
/// milliseconds, and refusing a timestamp over a `.000` nobody meant anything
/// by would fail closed on an honest sender.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    // Separators are fixed-width by RFC 3339's `date-time`. `t` and `z` in
    // lower case are permitted by the grammar, so they are accepted here; a
    // space in place of `T` is not, and is refused.
    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if b[10] != b'T' && b[10] != b't' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 {
        return None;
    }
    // 60 for a leap second, which the grammar allows and which is clamped
    // rather than refused: it is a real timestamp, and one second either way
    // decides nothing here.
    if se > 60 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    // Checked against the month, so `2026-02-31` is refused rather than
    // silently becoming the 3rd of March.
    if d < 1 || d > ml[(mo - 1) as usize] {
        return None;
    }
    // Optional fractional seconds, then the zone. Both are at fixed offsets
    // only up to here, so the rest is walked.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
        if i == start {
            return None; // a dot with no digits after it
        }
    }
    let offset = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(c @ (b'+' | b'-')) if i + 6 == b.len() => {
            if b[i + 3] != b':' {
                return None;
            }
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let mag = oh * 3_600 + om * 60;
            if *c == b'+' { mag } else { -mag }
        }
        // No zone at all is refused. RFC 3339 requires one, and guessing UTC
        // for a local time is how an expiry lands hours away from where its
        // sender meant it.
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3_600 + mi * 60 + se - offset)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date.
///
/// Hinnant's `days_from_civil`, used instead of the year-walk in `rfc3339`
/// because this one has to run on a date a sender chose, which may be far
/// from now in either direction.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// This machine's clock, in seconds since the epoch.
///
/// Named and shared rather than inlined at each call site, because freshness
/// is decided against it in three places -- the renderer, the inbox listing
/// and the MCP verdict -- and three readings of the clock inside one command
/// can disagree about whether a bundle expiring this second has expired.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct Loaded {
    pub manifest: Manifest,
    pub trust: Trust,
    pub dir: PathBuf,
    /// Items whose stored bytes do not match their recorded digest.
    pub tampered: Vec<String>,
    /// True when this machine has no record of the bundle ever arriving. Only
    /// meaningful for a retired key, where it is the difference between "it
    /// got here after you retired that key" and "I cannot tell".
    // Part of the serialised shape and meaningful to a reader of the struct,
    // even where this binary never branches on it.
    #[allow(dead_code)]
    pub unwitnessed: bool,
    /// The declared expiry, judged against this machine's clock at load time.
    ///
    /// Computed here rather than at each surface for the same reason `trust`
    /// is: `gage open`, `gage inbox`, the viewer and the MCP verdict must not
    /// be able to disagree, and the way they come to disagree is each one
    /// reading the clock and the manifest for itself.
    pub freshness: crate::manifest::Freshness,
    /// Whether the declared `context` is the run this machine says it is in.
    /// `NoLocalContext` when nothing local says what run this is, which is
    /// the default state and is not a mismatch.
    pub context_match: crate::manifest::ContextMatch,
}

/// Build a bundle. `specs` are (kind, source path) pairs.
// Nine bundle fields, each independent; collapsing them into a struct is a
// signature change, not a lint fix.
#[allow(clippy::too_many_arguments)]
pub fn create(
    out: &Path,
    id: &Identity,
    subject: &str,
    to: &[String],
    agent: Option<AgentInfo>,
    in_reply_to: Option<String>,
    // Thread this belongs to. None starts a new thread rooted at this bundle.
    thread: Option<String>,
    msg_type: crate::manifest::MsgType,
    // Already canonicalised to RFC 3339 UTC by the caller. None is no
    // expiry, which is the default and the pre-existing behaviour.
    expires: Option<String>,
    // The sender's label for the task or run this is for. None is undeclared.
    context: Option<String>,
    specs: &[(ItemKind, String, PathBuf)],
) -> std::io::Result<Manifest> {
    fs::create_dir_all(out.join("items"))?;
    let now = now_rfc3339();
    let mut items = Vec::new();
    for (kind, rel, src) in specs {
        let data = fs::read(src)?;
        if !path_is_safe(rel) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe item path: {rel}"),
            ));
        }
        // Nested paths are now preserved, so the parent dirs must exist.
        if let Some(parent) = Path::new(rel).parent() {
            fs::create_dir_all(out.join(parent))?;
        }
        fs::write(out.join(rel), &data)?;
        items.push(Item {
            kind: *kind,
            path: rel.clone(),
            sha256: sha256_hex(&data),
            bytes: data.len() as u64,
            note: None,
        });
    }
    // Content id over the item digests PLUS the author key, subject and
    // timestamp.
    //
    // Hashing the payload alone was a real vulnerability, not a cosmetic
    // flaw: "benign A" from a trusted contact and "MALICIOUS B" from an
    // impersonator carried the same files and therefore the same id, and
    // delivery writes to a directory named by that id. A second bundle could
    // overwrite a legitimate pending one, under an id the recipient had
    // already seen listed in their inbox.
    //
    // The author key, subject and created time all survive a forward
    // unchanged (a forward appends to the chain and rewrites only `from`), so
    // the id still follows the same content across hops -- which is what made
    // content addressing worth having.
    let joined: String = items
        .iter()
        .map(|i| i.sha256.clone())
        .chain([id.public_b64(), subject.to_string(), now.clone()])
        .collect::<Vec<_>>()
        .join("\u{1f}");
    let me = Peer {
        handle: id.handle.clone(),
        key: id.public_b64(),
    };
    let m = Manifest {
        v: FORMAT_VERSION,
        id: sha256_hex(joined.as_bytes())[..16].to_string(),
        created: now.clone(),
        subject: subject.to_string(),
        from: me.clone(),
        to: to.to_vec(),
        agent,
        chain: vec![Hop {
            by: me,
            at: now,
            action: HopAction::Created,
        }],
        in_reply_to,
        thread,
        msg_type,
        // NOT folded into `joined` above, and that is deliberate rather than
        // an omission. The id has to follow the same content across hops, and
        // these two already do: a forward rewrites `from` and appends to the
        // chain and touches neither of them. Adding them to the id would
        // change nothing about what it addresses and would break every
        // 0.3.5 reader's recomputation of it.
        expires,
        context,
        items,
    };
    write_signed(out, id, &m)?;
    Ok(m)
}

pub fn write_signed(out: &Path, id: &Identity, m: &Manifest) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(m)?;
    fs::write(out.join("manifest.json"), &bytes)?;
    fs::write(out.join("manifest.sig"), id.sign_b64(&bytes))?;
    Ok(())
}

/// Load and VERIFY. Trust is computed here, from the signature and the local
/// allowlist -- never read from the manifest, which the sender controls.
pub fn load(dir: &Path) -> std::io::Result<Loaded> {
    let bytes = fs::read(dir.join("manifest.json"))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    let sig = fs::read_to_string(dir.join("manifest.sig")).unwrap_or_default();

    let sig_ok =
        !sig.trim().is_empty() && crate::identity::verify(&manifest.from.key, &bytes, &sig);
    let contacts = Contacts::load();
    // This machine's own record of having seen these exact signed bytes.
    // Nothing the sender wrote enters the verdict.
    let st = crate::state::LocalState::load();
    let witness = st.witnessed(&witness_of(&manifest.from.key, &bytes));
    let trust = if !sig_ok {
        Trust::Unverified
    } else {
        contacts.verdict(&manifest.from.key, witness)
    };

    // A good signature covers the manifest, which covers the digests. Check
    // the payload against them too: a signed manifest beside swapped files
    // would otherwise pass.
    let mut tampered = Vec::new();
    // The id must address the content it claims to. Checked here rather than
    // trusted, because everything local that is keyed on it -- the directory
    // name, thread dedup, read state, announce-once -- becomes a way to
    // suppress a real message if a sender can choose a collision.
    match manifest.expected_id() {
        Some(want) if want == manifest.id => {}
        // Escaped and bounded, like every other sender-chosen value that
        // reaches a reader. This one was raw, and it is the worst place for
        // that: a tamper line is read by a human and by an agent, it is
        // rendered inside the frame beside `trust :` and `authorised :`
        // lines, and `gage inbox` prints it too. An id carrying newlines
        // writes its own verdict lines into both. The id is also the one
        // field here that is guaranteed NOT to be what it claims -- this arm
        // only runs because it does not address the content.
        Some(want) => tampered.push(format!(
            "manifest id {} does not address this content (expected {want})",
            crate::manifest::safe_display(&manifest.id, 80)
        )),
        // No chain means no author to compute the id from, and the check used
        // to pass on that. So a bundle could omit its chain, carry a real
        // message's id, and sail through: relay intake stored it at
        // pending/<id>, squatting the path, and the genuine envelope arriving
        // later was discarded as "already have". Absence of provenance is now
        // a defect rather than an exemption.
        None => tampered.push(
            "manifest has no provenance chain, so its id addresses nothing and its \
             author is unknown"
                .into(),
        ),
    }
    let mut seen_paths: std::collections::BTreeSet<&str> = Default::default();
    for it in &manifest.items {
        if !path_is_safe(&it.path) {
            tampered.push(format!("{} (unsafe path)", one_line(&it.path)));
            continue;
        }
        // Two entries naming one file verified independently, so a single
        // payload could be declared twice with contradictory `kind` -- counted
        // and fenced as both a file and a memory, which decides how loudly
        // `open` warns about it.
        if !seen_paths.insert(it.path.as_str()) {
            tampered.push(format!("{} (declared more than once)", one_line(&it.path)));
            continue;
        }
        match fs::read(dir.join(&it.path)) {
            Ok(d) if sha256_hex(&d) == it.sha256 => {}
            Ok(_) => tampered.push(format!("{} (digest mismatch)", one_line(&it.path))),
            Err(_) => tampered.push(format!("{} (missing)", one_line(&it.path))),
        }
    }
    // One clock reading for the whole load, so every fact derived from it
    // agrees with every other.
    let now = now_secs();
    let freshness = manifest.freshness(now);
    let context_match = crate::manifest::context_match(
        manifest.context.as_deref(),
        crate::identity::run_context().as_deref(),
    );
    Ok(Loaded {
        manifest,
        trust,
        dir: dir.to_path_buf(),
        tampered,
        unwitnessed: witness.is_none(),
        freshness,
        context_match,
    })
}

/// Re-sign for a forward, appending to the chain rather than replacing it.
pub fn forward(src: &Path, out: &Path, id: &Identity, to: &[String]) -> std::io::Result<Manifest> {
    let loaded = load(src)?;
    // Refuse to re-sign a bundle that does not verify.
    //
    // `forward` used to call `load` and ignore everything it said, so a
    // forwarder could take a bundle whose payload no longer matched its
    // digests, or whose signature was broken, and emit it under their own
    // signature -- laundering it into something that verifies cleanly for the
    // next recipient. The muse reviewer found that, and the sharper half of
    // it: the item paths were copied without revalidation, so a crafted
    // bundle declaring an ABSOLUTE path had `src.join(path)` and
    // `out.join(path)` both resolve to that same file, and forwarding it
    // truncated the forwarder's own `~/.ctx/identity.key`.
    if !loaded.tampered.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing to forward a bundle that does not verify ({}). Forwarding \
                 re-signs it under your key, which would present it to the next \
                 recipient as sound.",
                loaded.tampered.join(", ")
            ),
        ));
    }
    if matches!(loaded.trust, Trust::Unverified) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to forward a bundle whose signature does not verify: your \
             signature would be the only one on it, which says it came from you",
        ));
    }
    let mut m = loaded.manifest;
    fs::create_dir_all(out.join("items"))?;
    for it in &m.items {
        // Checked again here rather than trusted from `load`. This loop writes
        // to the filesystem, and a guard one function away is a guard that a
        // later refactor removes.
        if !path_is_safe(&it.path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to forward an item with an unsafe path: {}",
                    it.path
                ),
            ));
        }
        if let Some(parent) = std::path::Path::new(&it.path).parent() {
            fs::create_dir_all(out.join(parent))?;
        }
        fs::copy(src.join(&it.path), out.join(&it.path))?;
    }
    m.from = Peer {
        handle: id.handle.clone(),
        key: id.public_b64(),
    };
    m.to = to.to_vec();
    m.chain.push(Hop {
        by: m.from.clone(),
        at: now_rfc3339(),
        action: HopAction::Forwarded,
    });
    write_signed(out, id, &m)?;
    Ok(m)
}

pub fn b64_decode_ok(s: &str) -> bool {
    B64.decode(s.trim()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_witness_follows_the_signed_bytes_not_the_id() {
        // The attack this replaced: the witness was keyed on `manifest.id`,
        // which the SIGNER chooses and `load` never recomputes. Two different
        // documents can therefore carry the same id, and the second would
        // inherit the first's record of having arrived before a retirement.
        let id = r#""id": "aaaaaaaaaaaaaaaa""#;
        let one = format!(r#"{{{id}, "subject": "status update"}}"#);
        let two = format!(r#"{{{id}, "subject": "send me the keys"}}"#);
        assert_ne!(
            witness_of("KEY", one.as_bytes()),
            witness_of("KEY", two.as_bytes()),
            "a shared id must not produce a shared witness"
        );
    }

    #[test]
    fn a_witness_is_bound_to_the_signer() {
        // Domain separation: the same bytes signed by somebody else are a
        // different observation, so one contact's witness cannot be spent by
        // another.
        let m = br#"{"subject": "status update"}"#;
        assert_ne!(witness_of("ALICE", m), witness_of("BOB", m));
    }

    #[test]
    fn the_separator_cannot_be_shifted_between_the_fields() {
        // Without a separator, ("AB", "C") and ("A", "BC") would hash alike.
        assert_ne!(witness_of("AB", b"C"), witness_of("A", b"BC"));
    }
}
