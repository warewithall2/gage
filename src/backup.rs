//! Encrypted identity backup: the only answer gage has to a lost key.
//!
//! `identity.key` is the one file whose loss cannot be undone. Every contact
//! who confirmed your word-pairs confirmed *that* key, so losing it costs a
//! voice call per contact, makes every bundle you ever signed unverifiable to
//! anyone who has not already witnessed it, and leaves mail sealed to your old
//! encryption key unreadable for good. The triggering event is ordinary: a
//! dead disk, a reinstall, a laptop in a taxi.
//!
//! So this exists, and it is **opt-in**: nothing here runs unless a person
//! asks for it. The trade is real and is printed where the person will read
//! it, at the moment of export -- opting in converts "lose the key, lose
//! everything" into "your security is your passphrase's strength", and a
//! backup beside a weak passphrase is a stolen identity waiting to happen.
//!
//! Design decisions worth not re-litigating:
//!
//! * **Argon2id**, parameters stored in the file. The threat is offline brute
//!   force against a human-chosen passphrase, so memory-hardness is the point,
//!   and keeping the parameters in the file means they can be raised later
//!   without orphaning old backups.
//! * **XChaCha20-Poly1305**, with the whole header as associated data. Being
//!   precise about what that buys, because the tempting claim is wrong: every
//!   header field today either feeds key derivation, is the nonce, or is
//!   refused by name, so editing any one of them already fails without any
//!   associated data. The AAD authenticates the header *as a whole*, so a
//!   field added later cannot end up silently unauthenticated -- which is the
//!   kind of mistake nobody notices until someone edits that field.
//! * **The plaintext is the `identity.key` bytes, verbatim**, plus the handle.
//!   Not a re-serialisation of the key material: that file already holds both
//!   keypairs and the retired-key records, and a parallel format would be a
//!   second thing to keep in step with the first. Retired records are in scope
//!   because `KEY RETIRED` and `KEY REJECTED` depend on knowing what was
//!   retired and when.
//! * **Nothing about who you talk to.** No contacts, no journal, no inbox, no
//!   relay address. A leaked backup should cost the key and nothing more, and
//!   should not even say whose it is -- which is why the fingerprint is shown
//!   after a successful decrypt and appears nowhere in the file.

use crate::identity::home;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::Path;

pub const MAGIC: &str = "gage-identity-backup";
pub const FORMAT_VERSION: u32 = 1;
/// Short enough that a determined person will accept it, long enough that the
/// Argon2 cost below is doing the work rather than carrying it alone.
pub const MIN_PASSPHRASE: usize = 12;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20 takes a 24-byte nonce.

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfParams {
    pub name: String,
    /// Memory cost, KiB.
    pub m: u32,
    /// Time cost, iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CipherParams {
    pub name: String,
    pub nonce: String,
}

/// The file. `ct` is the only secret part; everything else is the header, and
/// the header is authenticated as associated data so none of it can be edited.
#[derive(Serialize, Deserialize)]
pub struct Backup {
    pub fmt: String,
    pub v: u32,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub ct: String,
}

/// What is inside the ciphertext.
#[derive(Serialize, Deserialize)]
struct Secret {
    v: u32,
    handle: String,
    /// The exact bytes of `identity.key`, as a string.
    identity_key: String,
}

/// Defaults: 64 MiB, 3 passes, 1 lane. Enough to make a GPU farm pay for each
/// guess without making a restore on a modest laptop feel broken.
fn default_params() -> (u32, u32, u32) {
    (64 * 1024, 3, 1)
}

fn argon2_key(pass: &[u8], kdf: &KdfParams) -> Result<[u8; 32], String> {
    if kdf.name != "argon2id" {
        return Err(format!("unknown key derivation `{}`", kdf.name));
    }
    let salt = B64
        .decode(kdf.salt.as_bytes())
        .map_err(|_| "the salt in this file is not valid base64".to_string())?;
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(32))
        .map_err(|e| format!("those key-derivation parameters are not usable: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(pass, &salt, &mut out)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(out)
}

fn random_bytes(n: usize) -> io::Result<Vec<u8>> {
    // The same source the fence nonce uses, for the same reason: this is the
    // one place a predictable value would be fatal, so there is no fallback.
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

/// The header, serialised exactly as it will be stored, for use as associated
/// data. Built from the same struct the file carries so the two cannot drift.
fn header_aad(b: &Backup) -> Result<Vec<u8>, String> {
    let h = serde_json::json!({
        "fmt": b.fmt, "v": b.v,
        "kdf": { "name": b.kdf.name, "m": b.kdf.m, "t": b.kdf.t, "p": b.kdf.p, "salt": b.kdf.salt },
        "cipher": { "name": b.cipher.name, "nonce": b.cipher.nonce },
    });
    serde_json::to_vec(&h).map_err(|e| e.to_string())
}

/// Seal the identity material. Pure, so it can be tested without a home.
pub fn seal(handle: &str, identity_key: &str, pass: &str) -> Result<Backup, String> {
    let (m, t, p) = default_params();
    let salt = random_bytes(SALT_LEN).map_err(|e| format!("no randomness available: {e}"))?;
    let nonce = random_bytes(NONCE_LEN).map_err(|e| format!("no randomness available: {e}"))?;
    let mut b = Backup {
        fmt: MAGIC.to_string(),
        v: FORMAT_VERSION,
        kdf: KdfParams {
            name: "argon2id".into(),
            m,
            t,
            p,
            salt: B64.encode(&salt),
        },
        cipher: CipherParams {
            name: "xchacha20poly1305".into(),
            nonce: B64.encode(&nonce),
        },
        ct: String::new(),
    };
    let key = argon2_key(pass.as_bytes(), &b.kdf)?;
    let plain = serde_json::to_vec(&Secret {
        v: FORMAT_VERSION,
        handle: handle.to_string(),
        identity_key: identity_key.to_string(),
    })
    .map_err(|e| e.to_string())?;
    let aad = header_aad(&b)?;
    let c = XChaCha20Poly1305::new(&key.into());
    let ct = c
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    b.ct = B64.encode(ct);
    Ok(b)
}

/// What a successful open yields: the handle and the key file's bytes.
#[derive(Debug)]
pub struct Opened {
    pub handle: String,
    pub identity_key: String,
}

/// Open a backup. Every failure here is a plain message and no side effects:
/// a wrong passphrase and a flipped bit are the same event to Poly1305, and
/// neither must leave anything half-written anywhere.
pub fn open(b: &Backup, pass: &str) -> Result<Opened, String> {
    if b.fmt != MAGIC {
        return Err(format!(
            "this is not a gage identity backup (its format says `{}`)",
            b.fmt
        ));
    }
    if b.v != FORMAT_VERSION {
        return Err(format!(
            "this backup is format version {} and this gage understands {}. \
             Use a gage new enough to read it rather than guessing at the contents.",
            b.v, FORMAT_VERSION
        ));
    }
    if b.cipher.name != "xchacha20poly1305" {
        return Err(format!("unknown cipher `{}`", b.cipher.name));
    }
    let nonce = B64
        .decode(b.cipher.nonce.as_bytes())
        .map_err(|_| "the nonce in this file is not valid base64".to_string())?;
    if nonce.len() != NONCE_LEN {
        return Err("the nonce in this file is the wrong length".into());
    }
    let ct = B64
        .decode(b.ct.as_bytes())
        .map_err(|_| "the ciphertext in this file is not valid base64".to_string())?;
    let key = argon2_key(pass.as_bytes(), &b.kdf)?;
    let aad = header_aad(b)?;
    let c = XChaCha20Poly1305::new(&key.into());
    let plain = c
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        // One message for both causes, because it is one event: the tag did
        // not check out. Saying which would be a guess, and a confident wrong
        // guess sends someone hunting a corrupt file when they mistyped.
        .map_err(|_| {
            "could not decrypt: the passphrase is wrong, or this file has been \
             altered since it was written. Nothing has been changed."
                .to_string()
        })?;
    let s: Secret = serde_json::from_slice(&plain)
        .map_err(|_| "decrypted, but the contents are not a gage identity backup".to_string())?;
    if s.v != FORMAT_VERSION {
        return Err(format!("backup contents are version {}, not 1", s.v));
    }
    Ok(Opened {
        handle: s.handle,
        identity_key: s.identity_key,
    })
}

// ---------------------------------------------------------------- the commands

/// Read a passphrase without putting it on screen.
///
/// Never an argument and never an environment variable: argv is visible in
/// `ps` to every user on the machine and the environment is readable through
/// `/proc`. When stdin is a terminal the echo is turned off around the read.
/// When it is not -- a pipe, which is how the test suite drives this -- there
/// is no echo to turn off, and the value was never on screen to begin with.
fn read_passphrase(prompt: &str) -> io::Result<String> {
    use std::io::IsTerminal;
    eprint!("{prompt}");
    io::stderr().flush()?;
    let tty = io::stdin().is_terminal();
    let saved = if tty { stty(&["-g"]).ok() } else { None };
    if tty {
        let _ = stty(&["-echo"]);
    }
    let mut line = String::new();
    let r = io::stdin().read_line(&mut line);
    if let Some(s) = saved {
        let _ = stty(&[s.trim()]);
    }
    if tty {
        eprintln!();
    }
    r?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// `stty` rather than a termios FFI declaration: the struct layout differs per
/// platform and getting it wrong silently is worse than shelling out once.
fn stty(args: &[&str]) -> io::Result<String> {
    let out = std::process::Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Temp file then rename, with the mode set before the rename, so the file
    // is never readable at the final path even for an instant.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

pub fn export(out: &Path) -> Result<(), String> {
    let dir = home();
    let kp = dir.join("identity.key");
    if !kp.exists() {
        return Err(format!(
            "there is no identity in {} to export. `gage init <name>` makes one.",
            dir.display()
        ));
    }
    if out.exists() {
        return Err(format!(
            "{} already exists. Choose another path rather than writing over a \
             backup you may still need.",
            out.display()
        ));
    }
    let key_bytes = std::fs::read_to_string(&kp).map_err(|e| format!("cannot read {kp:?}: {e}"))?;
    let handle = std::fs::read_to_string(dir.join("handle"))
        .map(|h| h.trim().to_string())
        .unwrap_or_default();

    // Said before the passphrase is chosen, because this is the one moment the
    // person is thinking about it and the only moment it can change what they
    // type.
    eprintln!("This writes your identity to a file that anyone who has it can");
    eprintln!("open with your passphrase -- and offline, as fast as they like.");
    eprintln!("Opting in trades \"lose the key, lose everything\" for \"your");
    eprintln!("security is your passphrase's strength\". Choose accordingly, and");
    eprintln!("keep the file somewhere other than the machine it came from.");
    eprintln!();

    let p1 = read_passphrase("passphrase: ").map_err(|e| e.to_string())?;
    if p1.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "that passphrase is {} characters and the minimum is {MIN_PASSPHRASE}. \
             This file's whole security is this passphrase.",
            p1.chars().count()
        ));
    }
    let p2 = read_passphrase("again: ").map_err(|e| e.to_string())?;
    if p1 != p2 {
        // Compared because a typo here is discovered on the worst day.
        return Err("those do not match. Nothing was written.".into());
    }

    let b = seal(&handle, &key_bytes, &p1)?;
    let json = serde_json::to_vec_pretty(&b).map_err(|e| e.to_string())?;
    write_private(out, &json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;

    let id = crate::identity::Identity::load().map_err(|e| e.to_string())?;
    println!("wrote {}", out.display());
    println!("  handle    : {}", crate::manifest::one_line(&handle));
    println!(
        "  this key says : {}",
        crate::words::fingerprint_of(&id.public_b64(), Some(&id.box_public_b64()))
    );
    println!();
    println!("  Those four pairs are what a restore will show you. If they ever");
    println!("  differ, the file is not this identity.");
    println!("  Keep this file and your passphrase apart, and keep both away from");
    println!("  the machine they came from -- a backup stored next to the thing it");
    println!("  protects protects nothing.");
    Ok(())
}

pub fn restore(file: &Path, replace: bool) -> Result<(), String> {
    let dir = home();
    let kp = dir.join("identity.key");
    let bytes = std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let b: Backup = serde_json::from_slice(&bytes)
        .map_err(|_| format!("{} is not a gage identity backup", file.display()))?;

    // Everything that can be decided before a passphrase is typed, is.
    let existing = if kp.exists() {
        let cur = crate::identity::Identity::load().map_err(|e| e.to_string())?;
        let fp = crate::words::fingerprint_of(&cur.public_b64(), Some(&cur.box_public_b64()));
        if !replace {
            return Err(format!(
                "{} already holds an identity, and restoring would replace it.\n  \
                 on disk now : {fp}\n  \
                 Nothing has been changed. If that identity is one you still use, \
                 this is not the command you want -- a restore cannot be undone by \
                 another restore.\n  \
                 If you are sure, re-run with --replace, which will ask you to type \
                 the word `replace` and will move the existing key aside rather than \
                 deleting it.",
                dir.display()
            ));
        }
        Some(fp)
    } else {
        None
    };

    let pass = read_passphrase("passphrase: ").map_err(|e| e.to_string())?;
    let opened = open(&b, &pass)?;

    // Decrypted, so the fingerprint can be computed from the real material and
    // shown BEFORE anything is written. A restore that wrote first and reported
    // second is a restore that can silently install the wrong identity.
    let fp = fingerprint_of_key_file(&opened.identity_key)?;
    println!("this backup holds:");
    println!(
        "  handle    : {}",
        crate::manifest::one_line(&opened.handle)
    );
    println!("  this key says : {fp}");
    println!();

    if let Some(cur) = existing {
        println!("  !! {} already holds a DIFFERENT identity:", dir.display());
        println!("     on disk now : {cur}");
        println!("     in this file: {fp}");
        println!();
        println!("     Continuing moves the existing key aside, it does not delete it.");
        let typed = read_passphrase("     type the word `replace` to continue: ")
            .map_err(|e| e.to_string())?;
        if typed.trim() != "replace" {
            return Err("not confirmed. Nothing has been changed.".into());
        }
        let aside = dir.join(format!(
            "identity.key.replaced.{}",
            crate::bundle::now_rfc3339()
        ));
        std::fs::rename(&kp, &aside)
            .map_err(|e| format!("could not move the existing key aside: {e}"))?;
        println!("     moved the previous key to {}", aside.display());
    }

    // All of it or none of it. A half-restored identity -- signing key present,
    // retired records missing -- produces wrong trust verdicts, which is worse
    // than no restore at all.
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    write_private(&kp, opened.identity_key.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", kp.display()))?;
    if !opened.handle.is_empty() {
        std::fs::write(dir.join("handle"), format!("{}\n", opened.handle))
            .map_err(|e| format!("cannot write the handle: {e}"))?;
    }

    println!("restored into {}", dir.display());
    println!();
    println!("  Compare those four pairs against your own record of this identity");
    println!("  before you trust it. If they do not match what your contacts");
    println!("  confirmed, this is not the key they confirmed.");
    println!();
    println!("  This brought back the key, not this machine's memory of what it has");
    println!("  seen. Bundles signed under a key you had retired will read as");
    println!("  unplaceable rather than attributable, because the witness record is");
    println!("  not in a backup and cannot honestly be reconstructed.");
    Ok(())
}

/// The fingerprint of the identity a key file describes, without installing it.
fn fingerprint_of_key_file(key_json: &str) -> Result<String, String> {
    let (sign, boxpub) = crate::identity::public_halves_of(key_json)?;
    Ok(crate::words::fingerprint_of(&sign, Some(&boxpub)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYFILE: &str = r#"{"v":1,"sign_seed":"AAAA","box_secret":"BBBB","retired":[]}"#;

    fn seal_cheap(pass: &str) -> Backup {
        let (m, t, p) = (8u32, 1u32, 1u32);
        let salt = random_bytes(SALT_LEN).unwrap();
        let nonce = random_bytes(NONCE_LEN).unwrap();
        let mut b = Backup {
            fmt: MAGIC.into(),
            v: FORMAT_VERSION,
            kdf: KdfParams {
                name: "argon2id".into(),
                m,
                t,
                p,
                salt: B64.encode(&salt),
            },
            cipher: CipherParams {
                name: "xchacha20poly1305".into(),
                nonce: B64.encode(&nonce),
            },
            ct: String::new(),
        };
        let key = argon2_key(pass.as_bytes(), &b.kdf).unwrap();
        let plain = serde_json::to_vec(&Secret {
            v: FORMAT_VERSION,
            handle: "alice".into(),
            identity_key: KEYFILE.into(),
        })
        .unwrap();
        let aad = header_aad(&b).unwrap();
        let c = XChaCha20Poly1305::new(&key.into());
        let ct = c
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .unwrap();
        b.ct = B64.encode(ct);
        b
    }

    #[test]
    fn a_backup_opens_with_its_own_passphrase() {
        let b = seal_cheap("correct horse battery");
        let got = open(&b, "correct horse battery").expect("should open");
        assert_eq!(got.handle, "alice");
        assert_eq!(got.identity_key, KEYFILE);
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let b = seal_cheap("correct horse battery");
        let e = open(&b, "correct horse batterz").unwrap_err();
        assert!(e.contains("could not decrypt"), "{e}");
        // And it does not say which of the two causes it was, because it
        // cannot tell and a confident wrong guess wastes someone's evening.
        assert!(e.contains("passphrase is wrong, or this file has been altered"));
    }

    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let mut b = seal_cheap("correct horse battery");
        let mut raw = B64.decode(b.ct.as_bytes()).unwrap();
        raw[4] ^= 0x01;
        b.ct = B64.encode(raw);
        assert!(open(&b, "correct horse battery").is_err());
    }

    /// Every header field refuses an edit. Worth being precise about *why*,
    /// because the obvious reading is wrong: these fail because the KDF
    /// parameters and the nonce are inputs to the decryption, so changing
    /// them changes the key or the stream. They would fail with no associated
    /// data at all. The AAD binding is tested separately, below.
    #[test]
    fn a_tampered_header_is_refused() {
        let pass = "correct horse battery";

        let mut b = seal_cheap(pass);
        b.kdf.t = 99;
        assert!(open(&b, pass).is_err(), "time cost edit should be refused");

        let mut b = seal_cheap(pass);
        b.kdf.m = 1024;
        assert!(
            open(&b, pass).is_err(),
            "memory cost edit should be refused"
        );

        let mut b = seal_cheap(pass);
        let mut salt = B64.decode(b.kdf.salt.as_bytes()).unwrap();
        salt[0] ^= 0xff;
        b.kdf.salt = B64.encode(salt);
        assert!(open(&b, pass).is_err(), "salt edit should be refused");

        let mut b = seal_cheap(pass);
        let mut n = B64.decode(b.cipher.nonce.as_bytes()).unwrap();
        n[0] ^= 0xff;
        b.cipher.nonce = B64.encode(n);
        assert!(open(&b, pass).is_err(), "nonce edit should be refused");
    }

    /// The AAD binding itself, tested at the layer it lives in.
    ///
    /// This is the property the header edits above do NOT isolate: every
    /// header field today either feeds key derivation, is the nonce, or is
    /// refused by name before decryption, so each of those edits fails for a
    /// reason other than the tag. What the AAD buys is that the header is
    /// authenticated *as a whole*, so a field added later cannot end up
    /// silently unauthenticated -- the kind of mistake nobody notices until
    /// someone edits that field.
    #[test]
    fn the_header_is_bound_to_the_ciphertext() {
        let key = [7u8; 32];
        let nonce = [9u8; NONCE_LEN];
        let c = XChaCha20Poly1305::new(&key.into());
        let ct = c
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: b"secret",
                    aad: br#"{"fmt":"gage-identity-backup","v":1}"#,
                },
            )
            .unwrap();
        // Same key, same nonce, same ciphertext; one byte of header different.
        assert!(
            c.decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: br#"{"fmt":"gage-identity-backup","v":2}"#,
                },
            )
            .is_err(),
            "a changed header must break the tag"
        );
        let right = c
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: br#"{"fmt":"gage-identity-backup","v":1}"#,
                },
            )
            .unwrap();
        assert_eq!(right, b"secret");
    }

    #[test]
    fn a_foreign_or_future_file_is_refused_by_name() {
        let mut b = seal_cheap("correct horse battery");
        b.fmt = "something-else".into();
        let e = open(&b, "correct horse battery").unwrap_err();
        assert!(e.contains("not a gage identity backup"), "{e}");

        let mut b = seal_cheap("correct horse battery");
        b.v = 2;
        let e = open(&b, "correct horse battery").unwrap_err();
        assert!(e.contains("format version 2"), "{e}");
    }

    /// The file must not say whose identity it is, or carry the secret in the
    /// clear. Checked on the serialised bytes, which is what lands on disk.
    #[test]
    fn the_file_leaks_neither_the_key_nor_the_identity() {
        let b = seal_cheap("correct horse battery");
        let json = serde_json::to_string_pretty(&b).unwrap();
        assert!(!json.contains("alice"), "the handle is in the file");
        assert!(!json.contains("sign_seed"), "key structure is in the file");
        assert!(!json.contains("AAAA"), "the signing seed is in the file");
        assert!(!json.contains("BBBB"), "the box secret is in the file");
        // The header is readable on purpose -- a reader has to know how to
        // derive the key before they can try.
        assert!(json.contains("argon2id"));
        assert!(json.contains("xchacha20poly1305"));
    }
}
