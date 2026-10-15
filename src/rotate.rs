//! Key rotation notices.
//!
//! A rotation is the one message in this system that is ABOUT trust rather
//! than carried inside it, and that makes it the most dangerous thing here.
//! "I have a new key, use this one instead" is precisely what an attacker who
//! has stolen your old key wants to say, and it is also what an honest person
//! whose laptop died needs to say. The two are indistinguishable from the
//! bytes alone.
//!
//! So the notice is evidence, never an instruction. `verify` establishes two
//! separate facts and refuses to blur them:
//!
//! * the NEW key signed this, so whoever holds it meant to publish it;
//! * the OLD key signed this, so the party you already trusted authorised the
//!   handover.
//!
//! The second is the one that matters, and it is still not proof -- a thief
//! holding the old key produces it just as easily. Nothing in this module
//! applies a change; applying one takes a separate, explicit act by the
//! person, who is the only party able to go and ask over another channel.

use crate::identity::{split_key, verify};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Notice {
    /// The signed statement, stored as the exact string that was signed.
    /// Re-serializing it to verify would make the check depend on field
    /// order -- the same reason bundle signatures cover stored bytes.
    pub claim: String,
    pub sig_new: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_old: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claim {
    pub v: u32,
    pub old_key: String,
    pub new_key: String,
    pub handle: String,
    pub at: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct Verified {
    pub claim: Claim,
    pub old_sign: String,
    pub new_sign: String,
    pub new_box: Option<String>,
    /// The old key countersigned. False means this notice establishes nothing
    /// beyond the existence of a new key.
    pub old_signed: bool,
}

pub fn verify_notice(n: &Notice) -> Result<Verified, String> {
    let claim: Claim = serde_json::from_str(&n.claim)
        .map_err(|e| format!("notice claim is not readable: {e}"))?;
    if claim.v != 1 {
        return Err(format!("notice format v{} is not understood", claim.v));
    }
    let (old_sign, _) = split_key(&claim.old_key);
    let (new_sign, new_box) = split_key(&claim.new_key);
    let bytes = n.claim.as_bytes();
    if !verify(&new_sign, bytes, &n.sig_new) {
        // Without this the notice could name any key at all as the new one,
        // including a key its author does not hold -- handing a third party's
        // mail to them, or just breaking the contact outright.
        return Err("the new key did not sign this notice; it is not usable".into());
    }
    let old_signed = match &n.sig_old {
        Some(sig) => verify(&old_sign, bytes, sig),
        None => false,
    };
    if n.sig_old.is_some() && !old_signed {
        return Err("a countersignature from the old key is present but does NOT \
                    verify. Treat this notice as forged."
            .into());
    }
    Ok(Verified { claim, old_sign, new_sign, new_box, old_signed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubs(k: &SigningKey) -> String {
        B64.encode(k.verifying_key().to_bytes())
    }

    fn notice(old: &SigningKey, new: &SigningKey, sign_old: bool, reason: &str) -> Notice {
        let claim = serde_json::json!({
            "v": 1,
            "old_key": pubs(old),
            "new_key": pubs(new),
            "handle": "bob",
            "at": "2026-10-14T12:00:00Z",
            "reason": reason,
        })
        .to_string();
        Notice {
            sig_new: B64.encode(new.sign(claim.as_bytes()).to_bytes()),
            sig_old: sign_old.then(|| B64.encode(old.sign(claim.as_bytes()).to_bytes())),
            claim,
        }
    }

    #[test]
    fn a_countersigned_notice_verifies_both_halves() {
        let v = verify_notice(&notice(&key(1), &key(2), true, "rotated")).unwrap();
        assert!(v.old_signed);
        assert_eq!(v.new_sign, pubs(&key(2)));
    }

    #[test]
    fn an_uncountersigned_notice_verifies_but_claims_nothing() {
        let v = verify_notice(&notice(&key(1), &key(2), false, "compromised")).unwrap();
        assert!(!v.old_signed, "no old signature must not read as authorised");
    }

    #[test]
    fn a_forged_countersignature_is_refused_outright() {
        // Signed by a third key pretending to be the old one. Reporting this
        // as merely "not countersigned" would lose the distinction between
        // an honest unsigned notice and an attempted forgery.
        let mut n = notice(&key(1), &key(2), true, "rotated");
        n.sig_old = Some(B64.encode(key(9).sign(n.claim.as_bytes()).to_bytes()));
        let e = verify_notice(&n).unwrap_err();
        assert!(e.contains("forged"), "got: {e}");
    }

    #[test]
    fn a_notice_not_signed_by_the_new_key_is_refused() {
        let mut n = notice(&key(1), &key(2), true, "rotated");
        n.sig_new = B64.encode(key(9).sign(n.claim.as_bytes()).to_bytes());
        assert!(verify_notice(&n).is_err());
    }

    #[test]
    fn the_claim_bytes_are_what_is_verified_not_a_reserialization() {
        // Flip one character of the signed string; both signatures must fail.
        let mut n = notice(&key(1), &key(2), true, "rotated");
        n.claim = n.claim.replace("\"bob\"", "\"eve\"");
        assert!(verify_notice(&n).is_err());
    }
}
