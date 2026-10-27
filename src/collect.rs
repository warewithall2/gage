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
//!
//! Symlinks are refused outright, which is the third thing. The deny list
//! matches on a NAME, and a symlink's name says nothing about what it points
//! at: `notes.md -> ~/.ssh/id_rsa` passed every check and shipped the key.
//! The content scan did not save it either, since a .env-shaped target is
//! neither a PEM block nor a vendor key pattern. A link is an instruction to
//! read somewhere else, and a bundle contains the files you named.

use crate::manifest::ItemKind;
use std::path::{Path, PathBuf};

/// Build dirs and caches: large, regenerable, and never the point.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".gradle",
    ".terraform",
    "vendor",
    ".DS_Store",
    // The gage home itself, under both names it has had. `.ctx` was the old
    // one and stayed here alone after the rename, so collecting a directory
    // that contained a live `.gage` swept up identity.key, contacts.json and
    // the whole inbox. `.ctx` is kept because a machine that predates the
    // rename still has one.
    ".ctx",
    ".gage",
];

/// Directories whose contents are secrets regardless of what the files in
/// them are called.
///
/// The deny list matched only a basename, so `proj/.ssh/config`,
/// `proj/.aws/credentials` and `proj/.docker/config.json` -- which holds
/// base64 registry auth in a file named `config.json` -- all walked straight
/// through. The muse reviewer found that. A name says nothing about a file
/// sitting in a directory whose entire purpose is to hold credentials.
const SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".docker",
    ".kube",
    ".config/gcloud",
    "secrets",
    "secret",
    ".azure",
    ".gcp",
    "keys",
    ".netlify",
    ".terraform.d",
    ".chef",
    ".vault",
];

/// Files that should essentially never be handed to another party. Matched on
/// the file name, lowercased.
fn looks_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // Suffix forms as well as prefix ones: `.env` was caught and `prod.env`
    // was not, which is the form a real repository actually contains.
    n.starts_with(".env")
        || n.ends_with(".env")
        || n.contains(".env.")
        // `contains` rather than `ends_with` for the named credential files,
        // because the copy that leaks is `.npmrc-old` or `.netrc.bak` -- a
        // backup somebody made while editing the real one.
        || n.contains(".netrc")
        || n.contains(".npmrc")
        || n.contains(".pypirc")
        || n.contains("git-credentials")
        || n == "credentials"
        || n.starts_with("credentials.")
        || n == "identity.key"
        || n.starts_with("id_rsa")
        || n.starts_with("id_ed25519")
        || n.starts_with("id_ecdsa")
        || n.starts_with("id_dsa")
        || n.ends_with(".pem")
        || n.ends_with(".key")
        || n.ends_with(".p12")
        || n.ends_with(".p8")
        || n.ends_with(".pfx")
        || n.ends_with(".jks")
        || n.ends_with(".keystore")
        || n.ends_with(".kdbx")
        || n.ends_with(".ovpn")
        || n == "service-account.json"
        || n == "token.json"
        || n == "token"
        || n.contains("secret")
        // Hyphen as well as underscore: `access-token.txt` and `api-key.txt`
        // were both missed.
        || n.contains("_token")
        || n.contains("-token")
        || n.contains("token_")
        || n.contains("apikey")
        || n.contains("api_key")
        || n.contains("api-key")
        || n.contains("passwd")
        || n.contains("password")
}

/// True when any directory component on the way to this file is one whose
/// contents are credentials by definition.
fn in_secret_dir(rel: &str) -> Option<String> {
    let lower = rel.to_ascii_lowercase().replace('\\', "/");
    let parts: Vec<&str> = lower.split('/').collect();
    // The last component is the file itself, which `looks_secret` handles.
    for (i, seg) in parts.iter().enumerate() {
        if i + 1 == parts.len() {
            break;
        }
        if SECRET_DIRS.contains(seg) {
            return Some((*seg).to_string());
        }
        // Two-part entries like .config/gcloud.
        if i + 2 < parts.len() {
            let pair = format!("{}/{}", seg, parts[i + 1]);
            if SECRET_DIRS.contains(&pair.as_str()) {
                return Some(pair);
            }
        }
    }
    None
}

pub struct Collected {
    /// (kind, path inside the bundle, source on disk)
    pub items: Vec<(ItemKind, String, PathBuf)>,
    pub skipped_secret: Vec<String>,
    pub skipped_dir: Vec<String>,
    pub skipped_big: Vec<String>,
    /// Links, with what they point at, so the report says why.
    pub skipped_link: Vec<String>,
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
            skipped_link: Vec::new(),
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
    // Checked with symlink_metadata, which does NOT follow the link, before
    // anything reads through it. `--allow-secrets` does not override this: it
    // is an override for files you can see the names of, and the whole problem
    // with a link is that you cannot.
    match std::fs::symlink_metadata(src) {
        Ok(md) if md.file_type().is_symlink() => {
            let target = std::fs::read_link(src)
                .map(|t| t.display().to_string())
                .unwrap_or_else(|_| "?".into());
            c.skipped_link.push(format!("{rel} -> {target}"));
            return Ok(());
        }
        _ => {}
    }
    let name = src
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if !allow_secret {
        if looks_secret(&name) {
            c.skipped_secret.push(rel);
            return Ok(());
        }
        if let Some(dir) = in_secret_dir(&rel) {
            c.skipped_secret.push(format!("{rel} (inside {dir}/)"));
            return Ok(());
        }
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

fn walk(
    c: &mut Collected,
    kind: ItemKind,
    root: &Path,
    base: &Path,
    allow_secret: bool,
) -> std::io::Result<()> {
    for e in std::fs::read_dir(base)? {
        let e = e?;
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        // A directory symlink is worse than a file one: following it walks a
        // whole tree from somewhere the person did not name, and `--dir
        // ./shared` with a link to $HOME in it would collect everything.
        // `is_dir()` below follows links, so this has to come first.
        if std::fs::symlink_metadata(&p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            let target = std::fs::read_link(&p)
                .map(|t| t.display().to_string())
                .unwrap_or_else(|_| "?".into());
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            c.skipped_link.push(format!("{rel} -> {target}"));
            continue;
        }
        if p.is_dir() {
            let lower = name.to_ascii_lowercase();
            if SKIP_DIRS.iter().any(|d| d.eq_ignore_ascii_case(&lower)) {
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
    for (kind, flag, list) in [
        (ItemKind::File, "--file", files),
        (ItemKind::Prompt, "--prompt", prompts),
        (ItemKind::Decision, "--decision", decisions),
        (ItemKind::Memory, "--memory", memories),
    ] {
        for p in list {
            // Named, with the flag, because these flags all take a PATH and the
            // bare io error ("No such file or directory") says neither which
            // path nor which flag -- which reads as a broken tool rather than
            // as text passed where a file was wanted.
            if !p.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "{flag} {}: no such file. {flag} takes a path to a file, \
                         not text to include.",
                        p.display()
                    ),
                ));
            }
            if p.is_dir() {
                let root = p.parent().unwrap_or(Path::new(""));
                walk(&mut c, kind, root, p, allow_secret)?;
            } else {
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                add_one(&mut c, kind, name, p, allow_secret)?;
            }
        }
    }
    for d in dirs {
        // The root itself, too: `--dir link-to-home` would otherwise walk it.
        if std::fs::symlink_metadata(d)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "--dir {} is a symlink. Pass the real path: a link is a pointer \
                     somewhere else, and what it points at is not what you named.",
                    d.display()
                ),
            ));
        }
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
