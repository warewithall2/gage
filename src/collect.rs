//! Turning paths into bundle items.
//!
//! `--file` used to flatten everything to `items/<basename>`, so a project
//! with `src/mod.rs` and `src/net/mod.rs` produced two items at one path and
//! the second silently overwrote the first. Sending a project was therefore
//! lossy in a way nobody would notice until the receiver was missing code.
//! Relative structure is now preserved and a collision is an error.
//!
//! The deny list is the other half. Handing over a whole project directory is
//! exactly how a .env, a private key or a .netrc leaves your machine, and the
//! sender is an agent that will not think to check. Those files are skipped by
//! default and the skip is REPORTED, because a silent omission is its own
//! kind of surprise.

use crate::manifest::ItemKind;
use std::path::{Path, PathBuf};

/// Build dirs and caches: large, regenerable, and never the point.
const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", "target", "node_modules", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".turbo", ".gradle", ".terraform", "vendor", ".DS_Store", ".ctx",
];

/// Files that should essentially never be handed to another party. Matched on
/// the file name, lowercased.
fn looks_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with(".env")
        || n == ".netrc"
        || n == ".npmrc"
        || n == ".pypirc"
        || n == ".git-credentials"
        || n == "credentials"
        || n == "identity.key"
        || n.starts_with("id_rsa")
        || n.starts_with("id_ed25519")
        || n.starts_with("id_ecdsa")
        || n.ends_with(".pem")
        || n.ends_with(".key")
        || n.ends_with(".p12")
        || n.ends_with(".pfx")
        || n.ends_with(".keystore")
        || n.contains("secret")
        || n.contains("_token")
        || n.contains("apikey")
        || n.contains("api_key")
}

pub struct Collected {
    /// (kind, path inside the bundle, source on disk)
    pub items: Vec<(ItemKind, String, PathBuf)>,
    pub skipped_secret: Vec<String>,
    pub skipped_dir: Vec<String>,
    pub skipped_big: Vec<String>,
}

pub const MAX_ITEM_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 25 * 1024 * 1024;

impl Collected {
    fn new() -> Self {
        Collected {
            items: Vec::new(),
            skipped_secret: Vec::new(),
            skipped_dir: Vec::new(),
            skipped_big: Vec::new(),
        }
    }

    pub fn total(&self) -> u64 {
        self.items
            .iter()
            .filter_map(|(_, _, p)| std::fs::metadata(p).ok().map(|m| m.len()))
            .sum()
    }
}

fn add_one(
    c: &mut Collected,
    kind: ItemKind,
    rel: String,
    src: &Path,
    allow_secret: bool,
) -> std::io::Result<()> {
    let name = src.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if looks_secret(&name) && !allow_secret {
        c.skipped_secret.push(rel);
        return Ok(());
    }
    let len = std::fs::metadata(src)?.len();
    if len > MAX_ITEM_BYTES {
        c.skipped_big.push(format!("{rel} ({len} bytes)"));
        return Ok(());
    }
    let bundle_path = format!("items/{rel}");
    if !crate::manifest::path_is_safe(&bundle_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe path: {rel}"),
        ));
    }
    if c.items.iter().any(|(_, p, _)| *p == bundle_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("two items would land on {bundle_path}; rename one or send the directory"),
        ));
    }
    c.items.push((kind, bundle_path, src.to_path_buf()));
    Ok(())
}

fn walk(c: &mut Collected, kind: ItemKind, root: &Path, base: &Path, allow_secret: bool) -> std::io::Result<()> {
    for e in std::fs::read_dir(base)? {
        let e = e?;
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                c.skipped_dir.push(name);
                continue;
            }
            walk(c, kind, root, &p, allow_secret)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            add_one(c, kind, rel, &p, allow_secret)?;
        }
    }
    Ok(())
}

/// `files`/`prompts`/`decisions`/`memories` are individual paths; `dirs` are
/// trees sent with their structure intact.
pub fn collect(
    files: &[PathBuf],
    prompts: &[PathBuf],
    decisions: &[PathBuf],
    memories: &[PathBuf],
    dirs: &[PathBuf],
    allow_secret: bool,
) -> std::io::Result<Collected> {
    let mut c = Collected::new();
    for (kind, list) in [
        (ItemKind::File, files),
        (ItemKind::Prompt, prompts),
        (ItemKind::Decision, decisions),
        (ItemKind::Memory, memories),
    ] {
        for p in list {
            if p.is_dir() {
                let root = p.parent().unwrap_or(Path::new(""));
                walk(&mut c, kind, root, p, allow_secret)?;
            } else {
                let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                add_one(&mut c, kind, name, p, allow_secret)?;
            }
        }
    }
    for d in dirs {
        if !d.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("--dir {} is not a directory", d.display()),
            ));
        }
        // Paths are kept relative to the directory's PARENT, so the project
        // name survives: items/myproj/src/net/mod.rs, not items/src/net/mod.rs.
        let root = d.parent().unwrap_or(Path::new(""));
        walk(&mut c, ItemKind::File, root, d, allow_secret)?;
    }
    let total = c.total();
    if total > MAX_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "bundle would be {total} bytes, over the {MAX_TOTAL_BYTES} limit; \
                 send fewer paths or a narrower directory"
            ),
        ));
    }
    Ok(c)
}
