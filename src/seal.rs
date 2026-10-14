//! Encryption for anything that leaves this machine.
//!
//! Signing proves who wrote a bundle. It does not hide what is in it. That is
//! fine on your own filesystem and not fine on a server, so nothing reaches a
//! relay unsealed.
//!
//! A sealed box (X25519 + XSalsa20-Poly1305, the NaCl construction) encrypts
//! to the recipient's public key using a fresh ephemeral keypair. Two
//! consequences, both wanted:
//!
//! * The relay learns nothing but a recipient key, a size and a time. It
//!   cannot read the subject, the filenames, or who sent it. A relay that
//!   could read bundles would be one box holding every project and prompt its
//!   users ever exchanged.
//! * The transport is anonymous, and authorship is proved by the signature
//!   INSIDE the bundle instead. That split is deliberate: end-to-end
//!   authorship survives the relay, and the relay never becomes an authority
//!   on who said what.
//!
//! The package is JSON with base64 payloads rather than an archive format.
//! It costs about a third in size and avoids a tar dependency for a payload
//! already capped at 25 MB, and what comes out of `unseal` is inspectable.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Package {
    manifest: String,
    sig: String,
    items: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    /// Recipient's X25519 public key. The only routing information a relay
    /// needs, and all it gets.
    pub to_box: String,
    pub ct: String,
}

/// Read a bundle directory into one sealed envelope.
pub fn seal_dir(dir: &Path, to_box_b64: &str) -> std::io::Result<Envelope> {
    let manifest = std::fs::read(dir.join("manifest.json"))?;
    let m: crate::manifest::Manifest = serde_json::from_slice(&manifest)?;
    let sig = std::fs::read_to_string(dir.join("manifest.sig")).unwrap_or_default();
    let mut items = Vec::new();
    for it in &m.items {
        if !crate::manifest::path_is_safe(&it.path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe path: {}", it.path),
            ));
        }
        items.push((it.path.clone(), B64.encode(std::fs::read(dir.join(&it.path))?)));
    }
    let pkg = serde_json::to_vec(&Package {
        manifest: B64.encode(&manifest),
        sig,
        items,
    })?;

    let raw = B64
        .decode(to_box_b64.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "box key is not 32 bytes")
    })?;
    let pk = crypto_box::PublicKey::from_bytes(raw);
    let ct = pk
        .seal(&mut crypto_box::aead::OsRng, &pkg)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "sealing failed"))?;
    Ok(Envelope { v: 1, to_box: to_box_b64.trim().to_string(), ct: B64.encode(ct) })
}

/// Decrypt an envelope back into a bundle directory.
///
/// Every path is re-checked against the manifest on the way out. Decryption
/// proves only that the sender knew your public key, which anybody does --
/// so the contents are still untrusted input at this point, and a path like
/// `../../.ssh/authorized_keys` must not be written just because it arrived
/// encrypted.
pub fn unseal_to_dir(
    env: &Envelope,
    id: &crate::identity::Identity,
    out: &Path,
) -> std::io::Result<()> {
    let ct = B64
        .decode(env.ct.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let plain = id
        .unseal(&ct)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let pkg: Package = serde_json::from_slice(&plain)?;
    let manifest = B64
        .decode(&pkg.manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let m: crate::manifest::Manifest = serde_json::from_slice(&manifest)?;

    std::fs::create_dir_all(out.join("items"))?;
    std::fs::write(out.join("manifest.json"), &manifest)?;
    std::fs::write(out.join("manifest.sig"), &pkg.sig)?;
    let declared: std::collections::BTreeSet<&str> =
        m.items.iter().map(|i| i.path.as_str()).collect();
    for (path, b64) in &pkg.items {
        // Two distinct refusals, reported distinctly. They were one branch
        // with one message, and the path-escape test passed while reading
        // "does not declare" -- a security refusal that misreports its own
        // reason is how the wrong guard gets removed later.
        if !crate::manifest::path_is_safe(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("envelope item path escapes the bundle: {path}"),
            ));
        }
        if !declared.contains(path.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("envelope contained an item the manifest does not declare: {path}"),
            ));
        }
        let data = B64
            .decode(b64)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(out.join(parent))?;
        }
        std::fs::write(out.join(path), data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an envelope from an arbitrary package, which is what a malicious
    /// SENDER can do -- `seal_dir` cannot produce one, because it derives the
    /// item list from the manifest. The guard being tested lives on the
    /// receiving side, so it has to be exercised from here.
    fn seal_raw(pkg: &Package, to: &crypto_box::PublicKey) -> Envelope {
        let bytes = serde_json::to_vec(pkg).unwrap();
        let ct = to.seal(&mut crypto_box::aead::OsRng, &bytes).unwrap();
        Envelope { v: 1, to_box: B64.encode(to.as_bytes()), ct: B64.encode(ct) }
    }

    fn manifest_json(paths: &[&str]) -> Vec<u8> {
        let items: Vec<String> = paths
            .iter()
            .map(|p| {
                format!(
                    r#"{{"kind":"file","path":"{p}","sha256":"00","bytes":2}}"#
                )
            })
            .collect();
        format!(
            r#"{{"v":1,"id":"x","created":"2026-01-01T00:00:00Z","subject":"s",
                 "from":{{"handle":"a","key":"k"}},"to":["b"],"chain":[],
                 "items":[{}]}}"#,
            items.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn rejects_items_the_manifest_does_not_declare() {
        let tmp = std::env::temp_dir().join(format!("ctx-seal-test-{}", std::process::id()));
        // set_var is unsafe in this edition; the tests are single-threaded here.
        unsafe { std::env::set_var("CTX_HOME", tmp.join("home")) };
        let id = crate::identity::Identity::create("tester").unwrap();

        let man = manifest_json(&["items/ok.txt"]);
        // The package carries a second item the manifest never mentions.
        let pkg = Package {
            manifest: B64.encode(&man),
            sig: String::new(),
            items: vec![
                ("items/ok.txt".into(), B64.encode(b"ok")),
                ("items/evil.txt".into(), B64.encode(b"no")),
            ],
        };
        let env = seal_raw(&pkg, &crypto_box::PublicKey::from_bytes(
            B64.decode(id.box_public_b64()).unwrap().try_into().unwrap(),
        ));
        let err = unseal_to_dir(&env, &id, &tmp.join("out")).unwrap_err();
        assert!(
            err.to_string().contains("does not declare"),
            "undeclared item was accepted: {err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_a_path_that_escapes_the_bundle() {
        let tmp = std::env::temp_dir().join(format!("ctx-esc-test-{}", std::process::id()));
        // set_var is unsafe in this edition; the tests are single-threaded here.
        unsafe { std::env::set_var("CTX_HOME", tmp.join("home")) };
        let id = crate::identity::Identity::create("tester2").unwrap();

        // Declared in the manifest AND present in the package, so the only
        // thing standing between this and a write outside the bundle is
        // path_is_safe.
        let escape = "items/../../../../tmp/ctx-pwned";
        let man = manifest_json(&[escape]);
        let pkg = Package {
            manifest: B64.encode(&man),
            sig: String::new(),
            items: vec![(escape.into(), B64.encode(b"owned"))],
        };
        let env = seal_raw(&pkg, &crypto_box::PublicKey::from_bytes(
            B64.decode(id.box_public_b64()).unwrap().try_into().unwrap(),
        ));
        let err = unseal_to_dir(&env, &id, &tmp.join("out")).unwrap_err();
        assert!(
            err.to_string().contains("escapes the bundle"),
            "escaping path was accepted, or refused for the wrong reason: {err}"
        );
        assert!(
            !std::path::Path::new("/tmp/ctx-pwned").exists(),
            "a file was written outside the bundle"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
