//! Local delivery, so agents stop passing paths to each other by hand.
//!
//! A route maps a handle to a directory on this machine. `gage send --to codex`
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
    /// handle -> that agent's gage home on this machine
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
    let st = crate::state::LocalState::observe(&scan_inbox())?;
    // Dated here because this is where the inbox is noticed, and noticing is
    // the only arrival gage can honestly claim -- nothing tells this machine
    // when a bundle was placed in its inbox. After `observe`, so the entry
    // carries the sequence number the witness was recorded at rather than the
    // one before it.
    let failed = crate::journal::record_arrivals();
    if failed > 0 {
        eprintln!("gage: could not journal {failed} arrival(s)");
    }
    Ok(st)
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
        let Ok(rd) = std::fs::read_dir(&stage) else {
            continue;
        };
        for e in rd.flatten() {
            if e.path().is_dir()
                && let Some(x) = crate::bundle::witness_if_sound_unless(&e.path(), known)
            {
                w.push(x);
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
///
/// Validate-then-write, staged through a temp directory and finished with one
/// rename. It used to create the destination and write the manifest before
/// checking the item paths, so a bundle whose fifth item was unsafe or missing
/// left a half-built directory behind -- and because delivery refuses to
/// overwrite, that leftover permanently blocked any retry of the same id. The
/// rename is what makes the destination either absent or complete, never
/// partial, which is also what lets `accept` be restartable.
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

    let bad = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg);

    // --- validate: nothing is written until every item has passed ---
    let mut seen = std::collections::BTreeSet::new();
    for it in &m.items {
        if !crate::manifest::path_is_safe(&it.path) {
            return Err(bad(format!("refusing to deliver unsafe path: {}", it.path)));
        }
        // Items live under items/ and nowhere else. Without this, an item
        // declared as `manifest.json` was copied straight over the manifest
        // written moments earlier -- harmless while the bytes matched, and a
        // corrupt bundle the moment they did not.
        if !it.path.starts_with("items/") {
            return Err(bad(format!(
                "refusing to deliver an item outside items/: {}",
                it.path
            )));
        }
        // A path declared twice was copied twice and reported success, leaving
        // a bundle whose payload digests no longer line up with its manifest.
        if !seen.insert(it.path.as_str()) {
            return Err(bad(format!("manifest declares {} twice", it.path)));
        }
        // Checked here so a missing file fails before anything is created,
        // rather than halfway through the copy loop.
        if !src.join(&it.path).is_file() {
            return Err(bad(format!(
                "manifest declares {} but the file is missing",
                it.path
            )));
        }
    }

    // --- write: into a temp directory beside the destination, then rename ---
    let parent = dest
        .parent()
        .ok_or_else(|| bad("destination has no parent".into()))?;
    let leaf = dest
        .file_name()
        .ok_or_else(|| bad("destination has no name".into()))?
        .to_string_lossy()
        .to_string();
    fs::create_dir_all(parent)?;
    // Per-process, so two concurrent deliveries of different bundles cannot
    // land on one another's staging directory.
    let tmp = parent.join(format!(".partial-{}-{}", std::process::id(), leaf));
    let _ = fs::remove_dir_all(&tmp);

    let staged = (|| -> std::io::Result<()> {
        fs::create_dir_all(tmp.join("items"))?;
        fs::write(tmp.join("manifest.json"), &bytes)?;
        if let Ok(sig) = fs::read(src.join("manifest.sig")) {
            fs::write(tmp.join("manifest.sig"), sig)?;
        }
        for it in &m.items {
            if let Some(p) = std::path::Path::new(&it.path).parent() {
                fs::create_dir_all(tmp.join(p))?;
            }
            fs::copy(src.join(&it.path), tmp.join(&it.path))?;
        }
        Ok(())
    })();
    if let Err(e) = staged {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }

    // Rename onto a non-empty directory fails rather than merging, so the
    // never-clobber promise holds even against a racing delivery that won.
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Move a bundle from one stage to another, restartably.
///
/// The move is a delivery followed by a removal, and it used to be written out
/// at each call site. A crash between the two left the bundle in both stages,
/// and the retry then failed on delivery's refusal to overwrite -- so the
/// bundle was stuck in pending forever while a complete copy sat in accepted.
///
/// `deliver` finishes with a rename, so a destination that exists is a
/// destination that is complete. That makes the already-delivered case the
/// resumable one: finish the removal instead of failing. The never-clobber
/// promise is kept, because the only thing treated as resumable is a
/// destination holding the same bundle id, which is what this move would have
/// put there.
pub fn restage(from: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    match deliver(from, dest) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && resumable(from, dest) => {
            // Second half of an interrupted move. Fall through to the removal.
        }
        Err(e) => return Err(e),
    }
    fs::remove_dir_all(from)
}

/// Whether the destination is this same move's completed first half, and
/// therefore safe to finish by removing the source.
///
/// Identical manifests are necessary but not sufficient. The id is computed
/// over the item digests, so two bundles sharing a manifest should share a
/// payload -- and if the destination's payload does *not* match its own
/// manifest, something has rewritten it since delivery. Removing the source
/// then would delete the sound copy and keep the altered one. So the
/// destination has to verify before it counts as resumable; when it does not,
/// the AlreadyExists refusal stands and the source stays put.
///
/// Payload digests only, deliberately -- not `bundle::load`, which also checks
/// the signature and the id. A bundle whose signature does not verify is still
/// legitimately delivered (it arrives and reads SENDER UNVERIFIABLE), so
/// gating on that would leave exactly those bundles stuck in both stages
/// forever, which is the state this function exists to clear.
fn resumable(from: &std::path::Path, dest: &std::path::Path) -> bool {
    let bytes = match (
        fs::read(from.join("manifest.json")),
        fs::read(dest.join("manifest.json")),
    ) {
        (Ok(x), Ok(y)) if x == y => x,
        _ => return false,
    };
    let Ok(m) = serde_json::from_slice::<crate::manifest::Manifest>(&bytes) else {
        return false;
    };
    m.items.iter().all(|it| {
        crate::manifest::path_is_safe(&it.path)
            && matches!(fs::read(dest.join(&it.path)),
                        Ok(b) if crate::bundle::sha256_hex(&b) == it.sha256)
    })
}

/// Where a bundle id lives, searched across the stages a bundle can be in.
///
/// Every command that prints a bundle prints its id -- `inbox`, `accept`,
/// `send`, `threads` -- and `open` took only a path, so the obvious next
/// command failed with a bare "No such file or directory". Two separate
/// users (me and the codex reviewer) lost time in the same place on the same
/// day, which is the definition of an ergonomic bug rather than a preference.
///
/// Accepted is searched before pending: once a bundle has been staged, that
/// is the copy the reader means. The id is validated before it reaches the
/// filesystem, so this cannot be used to walk out of the gage home.
pub fn find_by_id(ctx_home: &std::path::Path, id: &str) -> Option<PathBuf> {
    if !crate::manifest::id_is_safe(id) {
        return None;
    }
    [
        accepted_dir(ctx_home),
        pending_dir(ctx_home),
        sent_dir(ctx_home),
    ]
    .into_iter()
    .map(|d| d.join(id))
    .find(|p| p.join("manifest.json").is_file())
}

/// Bundles waiting in a stage, newest first.
pub fn list(stage: &std::path::Path) -> Vec<(String, crate::bundle::Loaded)> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(stage) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            // Delivery stages into `.partial-*` beside the destination. A
            // half-written staging directory must never be listed as mail.
            if e.file_name().to_string_lossy().starts_with('.') {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `paths` is (bundle path, contents), so the fixture's digests are real.
    fn manifest_json(paths: &[(&str, &[u8])]) -> Vec<u8> {
        let items: Vec<String> = paths
            .iter()
            .map(|(p, body)| {
                format!(
                    r#"{{"kind":"file","path":"{p}","sha256":"{}","bytes":{}}}"#,
                    crate::bundle::sha256_hex(body),
                    body.len()
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

    /// A source bundle whose manifest declares `decl` and whose files are
    /// `on_disk`. They differ in the tests that need a declaration with no
    /// file behind it.
    fn src_bundle(
        tmp: &std::path::Path,
        decl: &[(&str, &[u8])],
        on_disk: &[(&str, &[u8])],
    ) -> PathBuf {
        let d = tmp.join("src");
        fs::create_dir_all(d.join("items")).unwrap();
        fs::write(d.join("manifest.json"), manifest_json(decl)).unwrap();
        fs::write(d.join("manifest.sig"), b"sig").unwrap();
        for (p, body) in on_disk {
            let f = d.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, body).unwrap();
        }
        d
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gage-routes-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_bundle_id_resolves_across_the_stages_but_never_out_of_the_home() {
        let t = scratch("find");
        let src = src_bundle(&t, &[("items/a", b"one")], &[("items/a", b"one")]);
        let id = "abcdef0123456789";

        assert_eq!(find_by_id(&t, id), None, "nothing staged yet");

        deliver(&src, &pending_dir(&t).join(id)).unwrap();
        assert_eq!(find_by_id(&t, id), Some(pending_dir(&t).join(id)));

        // Accepted wins: once staged, that is the copy the reader means.
        deliver(&src, &accepted_dir(&t).join(id)).unwrap();
        assert_eq!(find_by_id(&t, id), Some(accepted_dir(&t).join(id)));

        // An id is validated before it touches the filesystem, so the
        // convenience cannot be turned into a traversal.
        for bad in ["../../etc", "..", "a/b", "ABCDEF0123456789", "", "zz"] {
            assert_eq!(find_by_id(&t, bad), None, "{bad:?} should not resolve");
        }
    }

    #[test]
    fn a_duplicate_item_path_is_refused_rather_than_copied_twice() {
        let t = scratch("dup");
        let src = src_bundle(
            &t,
            &[("items/a", b"one"), ("items/a", b"one")],
            &[("items/a", b"one")],
        );
        let dest = t.join("dest");
        let e = deliver(&src, &dest).unwrap_err();
        assert!(e.to_string().contains("twice"), "{e}");
        // The point of validate-then-write: a refusal leaves nothing behind to
        // block the retry.
        assert!(!dest.exists());
    }

    #[test]
    fn an_item_outside_items_cannot_overwrite_the_delivered_manifest() {
        let t = scratch("outside");
        // This is the shape that mattered: an item declared as the manifest
        // itself, copied over the manifest written moments earlier.
        // Declared only: the outside-items/ refusal fires before the file
        // check, and writing this one to disk would clobber the fixture's own
        // manifest instead of testing anything.
        let src = src_bundle(&t, &[("manifest.json", b"{}")], &[]);
        let dest = t.join("dest");
        let e = deliver(&src, &dest).unwrap_err();
        assert!(e.to_string().contains("outside items/"), "{e}");
        assert!(!dest.exists());
    }

    #[test]
    fn a_declared_item_with_no_file_leaves_no_partial_destination() {
        let t = scratch("missing");
        // Second item has no file, so the old code failed after creating the
        // destination and writing the manifest -- and the leftover then made
        // every retry fail on "already exists".
        let src = src_bundle(
            &t,
            &[("items/a", b"one"), ("items/b", b"two")],
            &[("items/a", b"one")],
        );
        let dest = t.join("dest");
        let e = deliver(&src, &dest).unwrap_err();
        assert!(e.to_string().contains("missing"), "{e}");
        assert!(
            !dest.exists(),
            "a refused delivery must not block the retry"
        );
    }

    #[test]
    fn delivery_stages_out_of_sight_and_is_not_listed_as_mail() {
        let t = scratch("staging");
        let stage = t.join("pending");
        fs::create_dir_all(&stage).unwrap();
        // A leftover staging directory from an interrupted delivery. It is a
        // directory in a stage, so the lister would have tried to read it.
        fs::create_dir_all(stage.join(".partial-1-abc/items")).unwrap();
        fs::write(
            stage.join(".partial-1-abc/manifest.json"),
            manifest_json(&[]),
        )
        .unwrap();
        assert!(list(&stage).is_empty());
    }

    #[test]
    fn an_interrupted_accept_can_be_finished_rather_than_stuck() {
        let t = scratch("restage");
        let src = src_bundle(&t, &[("items/a", b"one")], &[("items/a", b"one")]);
        let dest = t.join("accepted").join("x");

        // Simulate the crash window: delivery completed, removal did not.
        deliver(&src, &dest).unwrap();
        assert!(dest.is_dir() && src.is_dir());

        // The retry used to fail here on "refusing to overwrite", leaving the
        // bundle in both stages forever. It now finishes the move.
        restage(&src, &dest).unwrap();
        assert!(!src.exists(), "the source stage should be clear");
        assert!(dest.join("items/a").is_file(), "the delivered copy stays");
    }

    #[test]
    fn a_destination_whose_payload_was_rewritten_is_not_treated_as_resumable() {
        let t = scratch("swapped");
        let src = src_bundle(&t, &[("items/a", b"one")], &[("items/a", b"one")]);
        let dest = t.join("accepted").join("x");
        deliver(&src, &dest).unwrap();

        // Same manifest, payload altered after delivery. Finishing the move
        // here would delete the sound copy and keep the altered one.
        fs::write(dest.join("items/a"), b"ONE").unwrap();

        let e = restage(&src, &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(src.is_dir(), "the sound source must survive");
    }

    #[test]
    fn a_different_bundle_on_the_same_id_is_still_refused() {
        let t = scratch("clobber");
        let dest = t.join("accepted").join("x");
        let first = src_bundle(&t, &[("items/a", b"one")], &[("items/a", b"one")]);
        deliver(&first, &dest).unwrap();

        // Same id, different contents. Resumability must not become a licence
        // to overwrite mail the recipient may already have been shown.
        let other = t.join("other");
        fs::create_dir_all(other.join("items")).unwrap();
        fs::write(
            other.join("manifest.json"),
            manifest_json(&[("items/a", b"TWO")]),
        )
        .unwrap();
        fs::write(other.join("items/a"), b"TWO").unwrap();

        let e = restage(&other, &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(other.is_dir(), "a refused move must not delete the source");
        assert_eq!(fs::read(dest.join("items/a")).unwrap(), b"one");
    }
}
