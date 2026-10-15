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
    /// Which timestamp decided a retired-key verdict: this machine's record of
    /// when the bundle turned up, or, for a bundle that has never been in this
    /// inbox, the sender's own `created` field. Worth saying out loud, because
    /// only one of the two is trustworthy.
    pub dated_by_sender: bool,
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
    // Prefer this machine's own record of when the bundle arrived. `created`
    // is the signer's field, and for a retired key it was the whole basis of
    // "this predates the retirement".
    let st = crate::state::LocalState::load();
    let seen = st.first_seen(&manifest.id).map(|s| s.to_string());
    let dated_by_sender = seen.is_none();
    let when = seen.unwrap_or_else(|| manifest.created.clone());
    let trust = if !sig_ok {
        Trust::Unverified
    } else {
        contacts.verdict(&manifest.from.key, &when)
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
    Ok(Loaded { manifest, trust, dir: dir.to_path_buf(), tampered, dated_by_sender })
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
