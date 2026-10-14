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
}

pub fn home() -> PathBuf {
    let base = std::env::var("CTX_HOME").unwrap_or_else(|_| {
        let h = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{h}/.ctx")
    });
    PathBuf::from(base)
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
        let signing = SigningKey::from_bytes(&seed);
        fs::write(&kp, B64.encode(seed))?;
        set_private(&kp)?;
        fs::write(dir.join("handle"), handle)?;
        Ok(Self { handle: handle.to_string(), signing })
    }

    pub fn load() -> std::io::Result<Self> {
        let dir = home();
        let raw = fs::read_to_string(dir.join("identity.key"))?;
        let bytes = B64
            .decode(raw.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "key is not 32 bytes")
        })?;
        let handle = fs::read_to_string(dir.join("handle"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        Ok(Self { handle, signing: SigningKey::from_bytes(&seed) })
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
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
