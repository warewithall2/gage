//! Keys and signatures.
//!
//! The seed comes from /dev/urandom rather than a crate, which drops a
//! dependency and makes the one security-critical source of randomness
//! something a reader can check in four lines.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct Identity {
    pub handle: String,
    signing: SigningKey,
    /// X25519 secret for sealed boxes. Separate from the signing key rather
    /// than derived from it: deriving one key from another needs a
    /// domain-separated KDF done exactly right, and there is no benefit here
    /// worth inventing crypto for.
    sealing: crypto_box::SecretKey,
}

/// On-disk identity. The signing seed is preserved across an upgrade so that
/// adding encryption does not change who you are -- every bundle you signed
/// before stays verifiable.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKeys {
    v: u32,
    sign_seed: String,
    box_secret: String,
}

pub fn home() -> PathBuf {
    let base = std::env::var("CTX_HOME").unwrap_or_else(|_| {
        let h = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{h}/.ctx")
    });
    PathBuf::from(base)
}

fn b64_32(s: &str) -> std::io::Result<[u8; 32]> {
    let v = B64
        .decode(s.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    v.try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "key is not 32 bytes"))
}

/// Split a `signpub.boxpub` token. The signing key alone is still accepted,
/// because contacts added before encryption existed only have that one -- they
/// can be verified but not sealed to.
pub fn split_key(token: &str) -> (String, Option<String>) {
    match token.trim().split_once('.') {
        Some((a, b)) if !b.is_empty() => (a.to_string(), Some(b.to_string())),
        _ => (token.trim().to_string(), None),
    }
}

fn urandom32() -> std::io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

impl Identity {
    /// Create a new keypair. Refuses to clobber an existing one: silently
    /// replacing a key would make every bundle you ever sent unverifiable
    /// and look exactly like a key-rotation feature.
    pub fn create(handle: &str) -> std::io::Result<Self> {
        let dir = home();
        fs::create_dir_all(&dir)?;
        let kp = dir.join("identity.key");
        if kp.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists; remove it deliberately to rotate", kp.display()),
            ));
        }
        let seed = urandom32()?;
        let box_seed = urandom32()?;
        let stored = StoredKeys {
            v: 2,
            sign_seed: B64.encode(seed),
            box_secret: B64.encode(box_seed),
        };
        fs::write(&kp, serde_json::to_vec_pretty(&stored)?)?;
        set_private(&kp)?;
        fs::write(dir.join("handle"), handle)?;
        Ok(Self {
            handle: handle.to_string(),
            signing: SigningKey::from_bytes(&seed),
            sealing: crypto_box::SecretKey::from_bytes(box_seed),
        })
    }

    pub fn load() -> std::io::Result<Self> {
        let dir = home();
        let kp = dir.join("identity.key");
        let raw = fs::read_to_string(&kp)?;
        let handle = fs::read_to_string(dir.join("handle"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();

        // v2 is JSON. A v1 file is a bare base64 signing seed from before
        // encryption existed: upgrade it in place by ADDING a sealing key and
        // keeping the signing seed, so the upgrade is not a key change.
        if let Ok(st) = serde_json::from_str::<StoredKeys>(&raw) {
            let seed = b64_32(&st.sign_seed)?;
            let bs = b64_32(&st.box_secret)?;
            return Ok(Self {
                handle,
                signing: SigningKey::from_bytes(&seed),
                sealing: crypto_box::SecretKey::from_bytes(bs),
            });
        }
        let seed = b64_32(raw.trim())?;
        let box_seed = urandom32()?;
        let stored = StoredKeys {
            v: 2,
            sign_seed: B64.encode(seed),
            box_secret: B64.encode(box_seed),
        };
        fs::write(&kp, serde_json::to_vec_pretty(&stored)?)?;
        set_private(&kp)?;
        eprintln!("ctx: added an encryption key to this identity; your signing key is unchanged");
        Ok(Self {
            handle,
            signing: SigningKey::from_bytes(&seed),
            sealing: crypto_box::SecretKey::from_bytes(box_seed),
        })
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    pub fn box_public_b64(&self) -> String {
        B64.encode(self.sealing.public_key().as_bytes())
    }

    /// What you hand a colleague: both public keys, one token.
    pub fn full_key(&self) -> String {
        format!("{}.{}", self.public_b64(), self.box_public_b64())
    }

    pub fn unseal(&self, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.sealing.unseal(ct).map_err(|_| "decryption failed: not sealed to your key")
    }

    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.signing.sign(msg).to_bytes())
    }
}

#[cfg(unix)]
fn set_private(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_private(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Verify a detached signature. `verify_strict` is deliberate: it rejects
/// small-order public keys, which the permissive variant accepts.
pub fn verify(pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let Ok(pk) = B64.decode(pubkey_b64.trim()) else { return false };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sb) = B64.decode(sig_b64.trim()) else { return false };
    let Ok(sb): Result<[u8; 64], _> = sb.try_into() else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sb)).is_ok()
}
