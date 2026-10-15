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

/// One of your own past keypairs.
///
/// The secrets are KEPT by an ordinary rotation and dropped by a compromise
/// rotation, and the difference matters in both directions. Keeping them is
/// what lets you collect mail that was already sealed to the old key and is
/// sitting on a relay -- rotating would otherwise silently destroy anything
/// in flight, which is a good way to make people never rotate. Dropping them
/// is right when the key is stolen: the thief has that secret, so every
/// envelope sealed to it is already readable by them, and your copy only
/// extends the window in which you keep reading mail they can read too.
pub struct RetiredSelf {
    pub retired_at: String,
    pub sign_pub: String,
    pub box_pub: String,
    pub reason: String,
    signing: Option<SigningKey>,
    sealing: Option<crypto_box::SecretKey>,
}

impl RetiredSelf {
    /// Still able to prove possession of the old mailbox.
    pub fn can_collect(&self) -> bool {
        self.signing.is_some() && self.sealing.is_some()
    }

    pub fn sign_b64(&self, msg: &[u8]) -> Option<String> {
        self.signing.as_ref().map(|k| B64.encode(k.sign(msg).to_bytes()))
    }
}

pub struct Identity {
    pub handle: String,
    signing: SigningKey,
    /// X25519 secret for sealed boxes. Separate from the signing key rather
    /// than derived from it: deriving one key from another needs a
    /// domain-separated KDF done exactly right, and there is no benefit here
    /// worth inventing crypto for.
    sealing: crypto_box::SecretKey,
    /// Newest first.
    retired: Vec<RetiredSelf>,
}

/// On-disk identity. The signing seed is preserved across an upgrade so that
/// adding encryption does not change who you are -- every bundle you signed
/// before stays verifiable.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKeys {
    v: u32,
    sign_seed: String,
    box_secret: String,
    #[serde(default)]
    retired: Vec<StoredRetired>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRetired {
    retired_at: String,
    sign_pub: String,
    box_pub: String,
    #[serde(default)]
    reason: String,
    /// Absent once the secrets have been dropped. The PUBLIC halves stay
    /// forever: they are what makes your own old signatures identifiable as
    /// yours rather than as some stranger's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    box_secret: Option<String>,
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

/// What `ctx rotate` hands you to give to your contacts.
pub struct RotationNotice {
    pub old_key: String,
    pub new_key: String,
    pub json: String,
}

impl Identity {
    /// Create a new keypair. Refuses to clobber an existing one: silently
    /// replacing a key would make every bundle you ever sent unverifiable,
    /// and `ctx rotate` is the operation that does it properly.
    pub fn create(handle: &str) -> std::io::Result<Self> {
        let dir = home();
        fs::create_dir_all(&dir)?;
        let kp = dir.join("identity.key");
        if kp.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists. To replace your key use `ctx rotate`, which \
                     keeps the old one on record so your past bundles stay verifiable.",
                    kp.display()
                ),
            ));
        }
        let seed = urandom32()?;
        let box_seed = urandom32()?;
        let stored = StoredKeys {
            v: 3,
            sign_seed: B64.encode(seed),
            box_secret: B64.encode(box_seed),
            retired: Vec::new(),
        };
        write_store(&kp, &stored)?;
        fs::write(dir.join("handle"), handle)?;
        Ok(Self {
            handle: handle.to_string(),
            signing: SigningKey::from_bytes(&seed),
            sealing: crypto_box::SecretKey::from_bytes(box_seed),
            retired: Vec::new(),
        })
    }

    /// Mint a new keypair and push the current one onto the retired list.
    ///
    /// The notice is signed by BOTH keys. The new signature says "this is who
    /// I am now"; the old one says "and I am the same party you already
    /// trusted", which is the only part a recipient could not have got from a
    /// stranger. For a compromised key the old signature is omitted on
    /// purpose: a thief can produce it, so including it would dress up a
    /// notice that proves nothing as one that proves something.
    pub fn rotate(compromised: bool, at: &str) -> std::io::Result<(Self, RotationNotice)> {
        let dir = home();
        let kp = dir.join("identity.key");
        let old = Self::load()?;
        let old_sign_pub = old.public_b64();
        let old_full = old.full_key();

        let seed = urandom32()?;
        let box_seed = urandom32()?;
        let new_signing = SigningKey::from_bytes(&seed);
        let new_sealing = crypto_box::SecretKey::from_bytes(box_seed);
        let new_full = format!(
            "{}.{}",
            B64.encode(new_signing.verifying_key().to_bytes()),
            B64.encode(new_sealing.public_key().as_bytes())
        );

        let reason = if compromised { "compromised" } else { "rotated" };
        // The signed statement binds old key, new key, handle and time
        // together. Omitting any one of them would let a notice be replayed:
        // without the old key it could be aimed at a different contact,
        // without the time an older notice could be used to roll a key back.
        let claim = serde_json::json!({
            "v": 1,
            "old_key": old_full,
            "new_key": new_full,
            "handle": old.handle,
            "at": at,
            "reason": reason,
        });
        let claim_bytes = serde_json::to_vec(&claim)?;
        // Countersigned ALWAYS, compromise included, and signed here before
        // the old secrets are dropped below.
        //
        // The first version omitted it on compromise, reasoning that a thief
        // could produce it so it proved nothing. That inverted the signal.
        // Possession is the one bit a stranger cannot fake: anyone can send a
        // notice with no countersignature, only the key holder can send one
        // with it. Worse, the thief's best move was an ordinary
        // `reason: "rotated"` notice -- countersigned, and therefore the one
        // the receiver would apply -- while the honest victim's unsigned
        // compromise notice was the one it refused. The receiver now gets the
        // signature in both cases, and is told what it does and does not
        // prove.
        let notice = serde_json::json!({
            "claim": String::from_utf8_lossy(&claim_bytes),
            "sig_new": B64.encode(new_signing.sign(&claim_bytes).to_bytes()),
            "sig_old": old.sign_b64(&claim_bytes),
        });

        let mut retired = vec![StoredRetired {
            retired_at: at.to_string(),
            sign_pub: old_sign_pub.clone(),
            box_pub: old.box_public_b64(),
            reason: reason.to_string(),
            sign_seed: (!compromised).then(|| B64.encode(old.signing.to_bytes())),
            box_secret: (!compromised).then(|| B64.encode(old.sealing.to_bytes())),
        }];
        for r in &old.retired {
            retired.push(StoredRetired {
                retired_at: r.retired_at.clone(),
                sign_pub: r.sign_pub.clone(),
                box_pub: r.box_pub.clone(),
                reason: r.reason.clone(),
                sign_seed: r.signing.as_ref().map(|k| B64.encode(k.to_bytes())),
                box_secret: r.sealing.as_ref().map(|k| B64.encode(k.to_bytes())),
            });
        }
        let stored = StoredKeys {
            v: 3,
            sign_seed: B64.encode(seed),
            box_secret: B64.encode(box_seed),
            retired,
        };
        write_store(&kp, &stored)?;
        let me = Self::load()?;
        Ok((
            me,
            RotationNotice {
                old_key: old_full,
                new_key: new_full,
                json: serde_json::to_string_pretty(&notice)?,
            },
        ))
    }

    pub fn load() -> std::io::Result<Self> {
        let dir = home();
        let kp = dir.join("identity.key");
        let raw = fs::read_to_string(&kp)?;
        let handle = fs::read_to_string(dir.join("handle"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();

        // v2/v3 are JSON. A v1 file is a bare base64 signing seed from before
        // encryption existed: upgrade it in place by ADDING a sealing key and
        // keeping the signing seed, so the upgrade is not a key change.
        if let Ok(st) = serde_json::from_str::<StoredKeys>(&raw) {
            let seed = b64_32(&st.sign_seed)?;
            let bs = b64_32(&st.box_secret)?;
            let mut retired = Vec::new();
            for r in &st.retired {
                retired.push(RetiredSelf {
                    retired_at: r.retired_at.clone(),
                    sign_pub: r.sign_pub.clone(),
                    box_pub: r.box_pub.clone(),
                    reason: r.reason.clone(),
                    signing: r
                        .sign_seed
                        .as_deref()
                        .and_then(|s| b64_32(s).ok())
                        .map(|s| SigningKey::from_bytes(&s)),
                    sealing: r
                        .box_secret
                        .as_deref()
                        .and_then(|s| b64_32(s).ok())
                        .map(crypto_box::SecretKey::from_bytes),
                });
            }
            return Ok(Self {
                handle,
                signing: SigningKey::from_bytes(&seed),
                sealing: crypto_box::SecretKey::from_bytes(bs),
                retired,
            });
        }
        let seed = b64_32(raw.trim())?;
        let box_seed = urandom32()?;
        let stored = StoredKeys {
            v: 3,
            sign_seed: B64.encode(seed),
            box_secret: B64.encode(box_seed),
            retired: Vec::new(),
        };
        write_store(&kp, &stored)?;
        eprintln!("ctx: added an encryption key to this identity; your signing key is unchanged");
        Ok(Self {
            handle,
            signing: SigningKey::from_bytes(&seed),
            sealing: crypto_box::SecretKey::from_bytes(box_seed),
            retired: Vec::new(),
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

    pub fn retired(&self) -> &[RetiredSelf] {
        &self.retired
    }

    /// Sign a relay challenge for one of your mailboxes, current or retired.
    /// Returns None for a mailbox whose secret has been dropped.
    pub fn sign_for_box(&self, box_pub: &str, msg: &[u8]) -> Option<String> {
        if box_pub == self.box_public_b64() {
            return Some(self.sign_b64(msg));
        }
        self.retired
            .iter()
            .find(|r| r.box_pub == box_pub)
            .and_then(|r| r.sign_b64(msg))
    }

    /// Try the current sealing key, then retired ones.
    ///
    /// Order matters only for speed, not correctness: a sealed box either
    /// opens under a given secret or it does not, so there is no ambiguity to
    /// resolve. An envelope that opens under a RETIRED key still says nothing
    /// about who sent it -- `ctx open` and the inner signature do that.
    pub fn unseal(&self, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
        if let Ok(pt) = self.sealing.unseal(ct) {
            return Ok(pt);
        }
        for r in &self.retired {
            if let Some(k) = &r.sealing {
                if let Ok(pt) = k.unseal(ct) {
                    return Ok(pt);
                }
            }
        }
        Err("decryption failed: not sealed to your key")
    }

    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.signing.sign(msg).to_bytes())
    }
}

/// Write the key file through a temp file and a rename.
///
/// Rotation rewrites the file that holds BOTH the new key and the only copy
/// of the old secrets. A half-written file there is not an inconvenience, it
/// is a destroyed identity, so the new contents are complete on disk before
/// anything replaces the old ones.
fn write_store(kp: &Path, st: &StoredKeys) -> std::io::Result<()> {
    let tmp = kp.with_extension("key.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(st)?)?;
    set_private(&tmp)?;
    fs::rename(&tmp, kp)?;
    set_private(kp)
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
