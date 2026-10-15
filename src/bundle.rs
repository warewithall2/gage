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
use crate::manifest::{path_is_safe, AgentInfo, Hop, HopAction, Item, ItemKind, Manifest, Peer, FORMAT_VERSION};
use crate::trust::{Contacts, Trust};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
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

/// Read just enough of a bundle directory to compute its witness, without
/// verifying anything. Used by the observation pass, which runs BEFORE any
/// verdict is computed: a bundle has to be recorded as having arrived before
/// the question "did it arrive before the retirement" can be asked of it.
pub fn witness_at(dir: &Path) -> Option<String> {
    let bytes = fs::read(dir.join("manifest.json")).ok()?;
    let m: Manifest = serde_json::from_slice(&bytes).ok()?;
    Some(witness_of(&m.from.key, &bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_rfc3339() -> String {
    // Seconds since epoch rendered as a UTC timestamp, without pulling in a
    // date crate for one format string.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (mut y, mut d) = (1970i64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if d < len { break }
        d -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [31, if leap {29} else {28}, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    while d >= ml[m] { d -= ml[m]; m += 1; }
    format!("{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", m + 1, d + 1, tod / 3600, (tod % 3600) / 60, tod % 60)
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
    pub unwitnessed: bool,
}

/// Build a bundle. `specs` are (kind, source path) pairs.
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
    let me = Peer { handle: id.handle.clone(), key: id.public_b64() };
    let m = Manifest {
        v: FORMAT_VERSION,
        id: sha256_hex(joined.as_bytes())[..16].to_string(),
        created: now.clone(),
        subject: subject.to_string(),
        from: me.clone(),
        to: to.to_vec(),
        agent,
        chain: vec![Hop { by: me, at: now, action: HopAction::Created }],
        in_reply_to,
        thread,
        msg_type,
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

    let sig_ok = !sig.trim().is_empty()
        && crate::identity::verify(&manifest.from.key, &bytes, &sig);
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
    for it in &manifest.items {
        if !path_is_safe(&it.path) {
            tampered.push(format!("{} (unsafe path)", it.path));
            continue;
        }
        match fs::read(dir.join(&it.path)) {
            Ok(d) if sha256_hex(&d) == it.sha256 => {}
            Ok(_) => tampered.push(format!("{} (digest mismatch)", it.path)),
            Err(_) => tampered.push(format!("{} (missing)", it.path)),
        }
    }
    Ok(Loaded {
        manifest,
        trust,
        dir: dir.to_path_buf(),
        tampered,
        unwitnessed: witness.is_none(),
    })
}

/// Re-sign for a forward, appending to the chain rather than replacing it.
pub fn forward(src: &Path, out: &Path, id: &Identity, to: &[String]) -> std::io::Result<Manifest> {
    let loaded = load(src)?;
    let mut m = loaded.manifest;
    fs::create_dir_all(out.join("items"))?;
    for it in &m.items {
        if let Some(parent) = std::path::Path::new(&it.path).parent() {
            fs::create_dir_all(out.join(parent))?;
        }
        fs::copy(src.join(&it.path), out.join(&it.path))?;
    }
    m.from = Peer { handle: id.handle.clone(), key: id.public_b64() };
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
