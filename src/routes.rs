//! Local delivery, so agents stop passing paths to each other by hand.
//!
//! A route maps a handle to a directory on this machine. `ctx send --to codex`
//! then lands in Codex's pending inbox with no --out, which is the difference
//! between a tool you use and a tool you demo once.
//!
//! Delivery is to `pending/`, never straight to `accepted/`. That is the
//! instant-messenger accept step, and it is the one gate that keeps a channel
//! for passing prompts between models from being an open door: arrival is not
//! consent, and nothing reaches an agent's context until someone moves it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Routes {
    /// handle -> that agent's ctx home on this machine
    #[serde(default)]
    pub local: BTreeMap<String, String>,
}

impl Routes {
    pub fn load() -> Self {
        let p = crate::identity::home().join("routes.json");
        fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = crate::identity::home();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("routes.json"), serde_json::to_vec_pretty(self)?)
    }

    pub fn home_of(&self, handle: &str) -> Option<PathBuf> {
        self.local.get(handle).map(PathBuf::from)
    }
}

/// Record that everything currently in the inbox has been seen here.
///
/// Called at the top of every path that is about to show a verdict, and never
/// from `bundle::load`: load is also used for temporary pull directories, for
/// bundles you sent, and for arbitrary paths a person passes on the command
/// line, none of which is evidence that something arrived in this inbox.
///
/// It must run BEFORE the verdict, not after. An earlier version stamped at
/// the end of the listing, so the first time a bundle was displayed it was
/// judged without its own witness.
pub fn observe_inbox() -> std::io::Result<crate::state::LocalState> {
    crate::state::LocalState::observe(&scan_inbox())
}

/// Witnesses for every sound bundle currently in the inbox.
pub fn scan_inbox() -> Vec<String> {
    let st = crate::state::LocalState::load();
    scan_inbox_knowing(&|w| st.witnessed(w).is_some())
}

/// `known` reports witnesses already on record, so the signature and payload
/// verification can be skipped for them.
pub fn scan_inbox_knowing(known: &dyn Fn(&str) -> bool) -> Vec<String> {
    let home = crate::identity::home();
    let mut w = Vec::new();
    for stage in [pending_dir(&home), accepted_dir(&home)] {
        let Ok(rd) = std::fs::read_dir(&stage) else { continue };
        for e in rd.flatten() {
            if e.path().is_dir() {
                if let Some(x) = crate::bundle::witness_if_sound_unless(&e.path(), known) {
                    w.push(x);
                }
            }
        }
    }
    w
}

pub fn pending_dir(ctx_home: &std::path::Path) -> PathBuf {
    ctx_home.join("inbox/pending")
}

pub fn accepted_dir(ctx_home: &std::path::Path) -> PathBuf {
    ctx_home.join("inbox/accepted")
}

/// Your own outgoing messages.
///
/// Kept because a thread assembled from only the other side's half is not a
/// conversation: the first version showed an answer with no question above
/// it, and took its subject from the reply. It doubles as the local audit
/// trail -- both ends hold a copy of what was said.
pub fn sent_dir(ctx_home: &std::path::Path) -> PathBuf {
    ctx_home.join("sent")
}

/// Copy a bundle directory. Only the files the manifest names are copied, so a
/// sender cannot smuggle extra paths into the recipient's inbox alongside the
/// declared items.
pub fn deliver(src: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    // Never clobber. Defence in depth behind the id fix: if two bundles ever
    // land on one id again -- a hash collision, a replayed bundle, a future
    // change to how ids are built -- the second must fail loudly rather than
    // quietly replace a bundle the recipient has already been shown.
    if dest.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; refusing to overwrite a bundle already delivered",
                dest.display()
            ),
        ));
    }
    let bytes = fs::read(src.join("manifest.json"))?;
    let m: crate::manifest::Manifest = serde_json::from_slice(&bytes)?;
    fs::create_dir_all(dest.join("items"))?;
    fs::write(dest.join("manifest.json"), &bytes)?;
    if let Ok(sig) = fs::read(src.join("manifest.sig")) {
        fs::write(dest.join("manifest.sig"), sig)?;
    }
    for it in &m.items {
        if !crate::manifest::path_is_safe(&it.path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to deliver unsafe path: {}", it.path),
            ));
        }
        if let Some(parent) = std::path::Path::new(&it.path).parent() {
            fs::create_dir_all(dest.join(parent))?;
        }
        fs::copy(src.join(&it.path), dest.join(&it.path))?;
    }
    Ok(())
}

/// Bundles waiting in a stage, newest first.
pub fn list(stage: &std::path::Path) -> Vec<(String, crate::bundle::Loaded)> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(stage) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            if let Ok(l) = crate::bundle::load(&e.path()) {
                let name = e.file_name().to_string_lossy().to_string();
                out.push((name, l));
            }
        }
    }
    out.sort_by(|a, b| b.1.manifest.created.cmp(&a.1.manifest.created));
    out
}
