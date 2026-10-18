//! Keys and signatures.
//!
//! The seed comes from /dev/urandom rather than a crate, which drops a
//! dependency and makes the one security-critical source of randomness
//! something a reader can check in four lines.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
        self.signing
            .as_ref()
            .map(|k| B64.encode(k.sign(msg).to_bytes()))
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

/// Where this identity lives.
///
/// The project was renamed from `gage` to `gage`, and **nothing on
/// disk moves**. An identity key is the one file whose loss cannot be
/// undone: every contact who confirmed your word-pairs confirmed *that* key,
/// and a rename that mislaid it would silently turn a working install into a
/// stranger. So this looks for the new home, falls back to the old one if it
/// is there, and never copies, moves or creates one to replace the other.
///
/// Both environment variables are honoured for the same reason: scripts,
/// systemd units and test suites written against `CTX_HOME` keep working.
pub fn home() -> PathBuf {
    // An empty-but-SET variable is not a path. `CTX_HOME=` in a shell sets
    // it to the empty string, `var()` returns `Ok("")`, and the first
    // version turned that into `PathBuf::from("")` -- a home of "", which
    // resolves to the current directory. A test written for the rename
    // caught it immediately, which is the only reason it is not a way to
    // scatter identity files wherever someone happened to be standing.
    let set = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    for k in ["GAGE_HOME", "COUNTERSIGN_HOME", "CTX_HOME"] {
        if let Some(v) = set(k) {
            return PathBuf::from(v);
        }
    }
    let h = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    // Newest first. The project was `ctx`, then briefly `countersign`, now
    // `gage` -- and an install from any of those eras must keep working,
    // because the identity key is the one file whose loss cannot be undone.
    // The first home that exists wins; nothing is ever copied or created to
    // replace another, so a machine that has already moved on is never
    // dragged back.
    let homes = [
        PathBuf::from(format!("{h}/.gage")),
        PathBuf::from(format!("{h}/.countersign")),
        PathBuf::from(format!("{h}/.ctx")),
    ];
    for p in &homes {
        if p.exists() {
            return p.clone();
        }
    }
    homes.into_iter().next().expect("the list is not empty")
}

#[cfg(test)]
mod home_tests {
    /// The rename must not be able to mislay an identity.
    ///
    /// Not a unit test of `home()` itself -- it reads process-wide
    /// environment, and two tests racing on `set_var` is a worse bug than
    /// the one being tested. This pins the DECISION TABLE instead, which is
    /// the part that could be got wrong, and the shell suite exercises the
    /// real function against real directories.
    /// Newest-first, first-existing-wins, over `[gage, countersign, ctx]`.
    fn pick(exists: [bool; 3]) -> &'static str {
        let names = ["gage", "countersign", "ctx"];
        for (i, e) in exists.iter().enumerate() {
            if *e {
                return names[i];
            }
        }
        names[0]
    }

    #[test]
    fn a_home_from_any_era_is_still_found() {
        // The cases that matter: installs predating each rename.
        assert_eq!(pick([false, false, true]), "ctx");
        assert_eq!(pick([false, true, false]), "countersign");
        // Already moved on: never dragged back to an older one.
        assert_eq!(pick([true, true, true]), "gage");
        assert_eq!(pick([true, false, true]), "gage");
        assert_eq!(pick([false, true, true]), "countersign");
        // Fresh machine gets the current name.
        assert_eq!(pick([false, false, false]), "gage");
    }
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

/// What `gage rotate` hands you to give to your contacts.
pub struct RotationNotice {
    pub old_key: String,
    pub new_key: String,
    pub json: String,
}

impl Identity {
    /// Create a new keypair. Refuses to clobber an existing one: silently
    /// replacing a key would make every bundle you ever sent unverifiable,
    /// and `gage rotate` is the operation that does it properly.
    /// Create an identity, naming it after its own key when no name is given.
    ///
    /// LocalSend never asks you to pick a name, and that is most of why
    /// opening it feels like nothing. The difference here is that the name is
    /// DERIVED from the signing key rather than drawn at random, so it is one
    /// nobody chooses -- which makes it a slightly better label than a random
    /// one, at no cost to the person. It is still only a label: 16 bits, and
    /// grindable, so nothing is ever confirmed against it. See `words`.
    pub fn create_named(handle: Option<&str>) -> std::io::Result<Self> {
        match handle {
            Some(h) => Self::create(h),
            None => {
                // The name comes from the key, so the key has to exist
                // first. Created under a placeholder and renamed, rather
                // than generating a seed out here and duplicating the write
                // path that `create` already gets right.
                let me = Self::create("unnamed")?;
                let label = crate::words::label(&me.public_b64());
                fs::write(home().join("handle"), &label)?;
                Ok(Self {
                    handle: label,
                    ..me
                })
            }
        }
    }

    pub fn create(handle: &str) -> std::io::Result<Self> {
        let dir = home();
        fs::create_dir_all(&dir)?;
        let kp = dir.join("identity.key");
        if kp.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists. To replace your key use `gage rotate`, which \
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

        let reason = if compromised {
            "compromised"
        } else {
            "rotated"
        };
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
        eprintln!("gage: added an encryption key to this identity; your signing key is unchanged");
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
    /// about who sent it -- `gage open` and the inner signature do that.
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
    let Ok(pk) = B64.decode(pubkey_b64.trim()) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sb) = B64.decode(sig_b64.trim()) else {
        return false;
    };
    let Ok(sb): Result<[u8; 64], _> = sb.try_into() else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sb)).is_ok()
}
