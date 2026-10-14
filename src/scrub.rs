//! Outbound content scanning.
//!
//! The deny list in collect.rs matches FILENAMES, which catches `.env` and
//! `id_rsa` and nothing else. The leak that actually happens is a perfectly
//! innocent `notes.md` that quotes a customer's email address, or a log
//! fragment pasted into a decision file with a bearer token still in it.
//! Filenames say nothing about that; only the bytes do.
//!
//! So this reads every item before it is sealed and refuses rather than
//! warns. A warning on an outbound path is advice to an agent that is not
//! going to take it -- by the time a human reads the warning the bundle is
//! built, and if the recipient is remote it has already left.
//!
//! Findings are reported REDACTED. A tool whose job is to stop secrets
//! leaving should not print them to a terminal, a log, or an agent's context
//! on its way to refusing.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: String,
    pub preview: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Policy {
    /// Literal strings that must never leave: a customer domain, a project
    /// codename, an account id. Case-insensitive substring match.
    #[serde(default)]
    pub never_send: Vec<String>,
    /// Rule names from the built-in set to switch off, for when a repo
    /// legitimately contains the shape.
    #[serde(default)]
    pub disable: Vec<String>,
}

impl Policy {
    pub fn load() -> Self {
        let p = crate::identity::home().join("scrub.json");
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
}

/// Redact the middle of a match. Enough to recognise, not enough to use.
fn redact(s: &str) -> String {
    let t: String = s.chars().take(80).collect();
    let n = t.chars().count();
    if n <= 10 {
        return "*".repeat(n);
    }
    let head: String = t.chars().take(4).collect();
    let tail: String = t.chars().skip(n - 3).collect();
    format!("{head}{}{tail}", "*".repeat(n.saturating_sub(7).min(24)))
}

/// Hand-written matchers rather than a regex dependency. Each returns the
/// matched span so it can be redacted.
fn scan_line(line: &str, policy: &Policy) -> Option<(String, String)> {
    let disabled = |n: &str| policy.disable.iter().any(|d| d == n);
    let lower = line.to_ascii_lowercase();

    for lit in &policy.never_send {
        if !lit.is_empty() && lower.contains(&lit.to_ascii_lowercase()) {
            return Some(("never_send".into(), redact(lit)));
        }
    }
    // A PEM header is unambiguous and worth catching before anything else.
    if !disabled("private_key") && line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
        return Some(("private_key".into(), "-----BEGIN ... PRIVATE KEY-----".into()));
    }
    for (name, prefix) in [
        ("aws_key", "AKIA"),
        ("anthropic_key", "sk-ant-"),
        ("openai_key", "sk-proj-"),
        ("github_token", "ghp_"),
        ("github_pat", "github_pat_"),
        ("slack_token", "xox"),
        ("google_key", "AIza"),
        ("stripe_key", "sk_live_"),
    ] {
        if disabled(name) {
            continue;
        }
        if let Some(i) = line.find(prefix) {
            let tok: String = line[i..].chars().take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'').collect();
            // A bare prefix in prose is not a credential; a long token is.
            if tok.len() >= prefix.len() + 8 {
                return Some((name.to_string(), redact(&tok)));
            }
        }
    }
    if !disabled("bearer") {
        if let Some(i) = lower.find("bearer ") {
            let tok: String = line[i + 7..].chars().take_while(|c| !c.is_whitespace()).collect();
            if tok.len() >= 16 {
                return Some(("bearer".into(), redact(&tok)));
            }
        }
    }
    if !disabled("email") {
        for word in line.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '<' || c == '>' || c == '"') {
            let w = word.trim_end_matches(|c: char| c == '.' || c == ')' || c == ']');
            if let Some(at) = w.find('@') {
                let (u, d) = (&w[..at], &w[at + 1..]);
                if !u.is_empty()
                    && d.contains('.')
                    && !d.ends_with('.')
                    && d.len() >= 4
                    && u.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
                    && d.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
                    // example.com and friends are documentation, not people.
                    && !["example.com", "example.org", "example.net", "test.com", "localhost"]
                        .iter()
                        .any(|x| d.eq_ignore_ascii_case(x))
                {
                    return Some(("email".into(), redact(w)));
                }
            }
        }
    }
    None
}

/// Scan the files that are about to become bundle items.
pub fn scan(specs: &[(crate::manifest::ItemKind, String, std::path::PathBuf)]) -> Vec<Finding> {
    let policy = Policy::load();
    let mut out = Vec::new();
    for (_, rel, src) in specs {
        let Ok(text) = std::fs::read_to_string(src) else { continue };
        for (n, line) in text.lines().enumerate() {
            if line.len() > 4000 {
                continue;
            }
            if let Some((rule, preview)) = scan_line(line, &policy) {
                out.push(Finding {
                    path: display_path(rel),
                    line: n + 1,
                    rule,
                    preview,
                });
                break; // one finding per file is enough to refuse
            }
        }
    }
    out
}

fn display_path(rel: &str) -> String {
    rel.strip_prefix("items/").unwrap_or(rel).to_string()
}

pub fn policy_path() -> std::path::PathBuf {
    crate::identity::home().join("scrub.json")
}

pub fn ensure_policy_file() -> std::io::Result<()> {
    let p = policy_path();
    if p.exists() {
        return Ok(());
    }
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let seed = Policy {
        never_send: vec![],
        disable: vec![],
    };
    std::fs::write(p, serde_json::to_vec_pretty(&seed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(line: &str) -> Option<String> {
        scan_line(line, &Policy::default()).map(|(r, _)| r)
    }

    #[test]
    fn catches_credentials_in_otherwise_innocent_text() {
        assert_eq!(hit("export KEY=sk-ant-api03-abcdefghijklmnop").as_deref(), Some("anthropic_key"));
        assert_eq!(hit("Authorization: Bearer abcdefghijklmnopqrstuvwx").as_deref(), Some("bearer"));
        assert_eq!(hit("aws id AKIAIOSFODNN7EXAMPLE here").as_deref(), Some("aws_key"));
        assert_eq!(hit("-----BEGIN OPENSSH PRIVATE KEY-----").as_deref(), Some("private_key"));
        assert_eq!(hit("ping dana.smith@acmecorp.co.uk about it").as_deref(), Some("email"));
    }

    #[test]
    fn does_not_fire_on_ordinary_prose() {
        assert!(hit("we decided against tokio-retry for the backoff").is_none());
        assert!(hit("see docs at example.com or mail me@example.com").is_none());
        assert!(hit("the sk-ant- prefix identifies an Anthropic key").is_none(), "a bare prefix in prose is not a credential");
        assert!(hit("bearer of bad news").is_none());
    }

    #[test]
    fn a_finding_never_exposes_the_secret() {
        let (_, prev) = scan_line("KEY=sk-ant-api03-SUPERSECRETVALUE1234", &Policy::default()).unwrap();
        assert!(!prev.contains("SUPERSECRETVALUE"), "preview leaked the secret: {prev}");
        assert!(prev.contains('*'), "preview was not redacted: {prev}");
    }

    #[test]
    fn literal_never_send_entries_match_case_insensitively() {
        let p = Policy { never_send: vec!["ProjectHalibut".into()], disable: vec![] };
        assert!(scan_line("notes on projecthalibut rollout", &p).is_some());
    }
}
