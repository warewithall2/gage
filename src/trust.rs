//! The buddy list, which is the entire access-control model.
//!
//! AIM had this right in 1997: you accept people, and anyone else cannot
//! reach you. Here it does double duty -- it stops unsolicited bundles, and
//! it is what turns a signature into a *meaning*. A valid signature only
//! proves the sender holds a key; the allowlist is what says you have ever
//! agreed to hear from that key.
//!
//! Keyed by public key, not by handle. A handle is a label anybody can claim.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signature valid and the key is on the allowlist.
    Known,
    /// Signature valid, key not on the allowlist. Real sender, stranger.
    Unknown,
    /// Signature absent, malformed, or does not match the manifest bytes.
    /// Nothing about the sender can be believed.
    Unverified,
}

impl Trust {
    /// Labels are deliberately NOT substrings of one another. The first
    /// version used "KNOWN SENDER" and "UNKNOWN SENDER", and a test that
    /// asserted the absence of the former matched the latter -- so any reader
    /// grepping for trust, an agent included, could read "unknown" as
    /// "known". A safety label that fails a substring check is not a label.
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Known => "SENDER VERIFIED (signature valid, key is on your list)",
            Trust::Unknown => "SENDER NOT ON YOUR LIST (signature valid, you have never accepted this key)",
            Trust::Unverified => "SENDER UNVERIFIABLE (signature missing or invalid)",
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    /// pubkey -> handle you chose for them. Your label, not their claim.
    #[serde(default)]
    pub keys: BTreeMap<String, String>,
    /// group name -> member pubkeys. A group is a list of keys you trust in
    /// that context, so leaving a group cannot be done by the group.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// signing pubkey -> X25519 pubkey, for sealing to them. Separate map so
    /// contacts added before encryption existed keep working: they can be
    /// verified, just not sealed to.
    #[serde(default)]
    pub box_keys: BTreeMap<String, String>,
}

impl Contacts {
    pub fn load() -> Self {
        let p = crate::identity::home().join("contacts.json");
        fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = crate::identity::home();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("contacts.json"), serde_json::to_vec_pretty(self)?)
    }

    pub fn knows(&self, pubkey: &str) -> bool {
        self.keys.contains_key(pubkey)
    }

    pub fn name_for(&self, pubkey: &str) -> Option<&str> {
        self.keys.get(pubkey).map(|s| s.as_str())
    }

    pub fn key_for_name(&self, name: &str) -> Option<String> {
        self.keys
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(k, _)| k.clone())
    }
}
