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

/// Redact a match to a fixed shape that reveals neither its content nor its
/// length.
///
/// The first version showed four leading characters, three trailing ones, and
/// a star count that was the exact length up to 31 -- so for a short bearer
/// token that was seven of sixteen characters plus the length, printed to a
/// terminal, a log, and an agent's context on the way to refusing. The module
/// header promises a finding never exposes the secret; this now keeps that
/// promise rather than approximately keeping it.
///
/// Two leading characters survive for one reason: `aws_key` and `anthropic_key`
/// are told apart by their prefix, and the rule name already says which
/// matched, so the first two characters add recognisability without adding
/// usable key material. Nothing from the end is shown, and the mask is a fixed
/// width, so neither the length nor the tail leaks.
fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 6 {
        return "*".repeat(8);
    }
    let head: String = s.chars().take(2).collect();
    format!("{head}{}", "*".repeat(8))
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
        return Some((
            "private_key".into(),
            "-----BEGIN ... PRIVATE KEY-----".into(),
        ));
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
            let tok: String = line[i..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
                .collect();
            // A bare prefix in prose is not a credential; a long token is.
            if tok.len() >= prefix.len() + 8 {
                return Some((name.to_string(), redact(&tok)));
            }
        }
    }
    if !disabled("bearer")
        && let Some(i) = lower.find("bearer ")
    {
        let tok: String = line[i + 7..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if tok.len() >= 16 {
            return Some(("bearer".into(), redact(&tok)));
        }
    }
    if !disabled("email") {
        for word in line.split(|c: char| {
            c.is_whitespace() || c == ',' || c == ';' || c == '<' || c == '>' || c == '"'
        }) {
            let w = word.trim_end_matches(['.', ')', ']']);
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
                    // An email is reported by DOMAIN rather than redacted
                    // to nothing: the point of the finding is "this names a
                    // real person at a real company", and the domain is what
                    // makes that legible without printing the address.
                    return Some(("email".into(), format!("**@{d}")));
                }
            }
        }
    }
    None
}

/// How much of one line is looked at in a single pass, and how much the next
/// pass overlaps it so a token lying across the boundary is still seen. No
/// credential shape here is anywhere near 256 characters.
const WINDOW: usize = 4000;
const OVERLAP: usize = 256;

/// Scan the files that are about to become bundle items.
///
/// Two bypasses lived here, each a single character wide:
///
/// * the file was read with `read_to_string`, so anything that was not valid
///   UTF-8 was silently skipped -- appending one invalid byte to a file made
///   the entire content scan ignore it. It is read as bytes now and converted
///   lossily, which leaves every ASCII credential shape intact.
/// * a line longer than 4000 bytes was skipped rather than truncated, so
///   padding a line past that made the secret on it invisible. Long lines are
///   scanned in overlapping windows instead.
///
/// Both were found while reviewing this file against its own threat model: a
/// scan that can be turned off by the thing it is scanning is decoration.
pub fn scan(specs: &[(crate::manifest::ItemKind, String, std::path::PathBuf)]) -> Vec<Finding> {
    let policy = Policy::load();
    let mut out = Vec::new();
    for (_, rel, src) in specs {
        let Ok(raw) = std::fs::read(src) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw);
        for (n, line) in text.lines().enumerate() {
            if let Some((rule, preview)) = scan_long_line(line, &policy) {
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

/// `scan_line` over a line of any length, in overlapping windows.
///
/// Char-indexed rather than byte-indexed: lossy conversion leaves multi-byte
/// characters in place, and slicing one in half would panic.
fn scan_long_line(line: &str, policy: &Policy) -> Option<(String, String)> {
    if line.len() <= WINDOW {
        return scan_line(line, policy);
    }
    let chars: Vec<char> = line.chars().collect();
    let step = WINDOW - OVERLAP;
    let mut start = 0;
    while start < chars.len() {
        let end = (start + WINDOW).min(chars.len());
        let window: String = chars[start..end].iter().collect();
        if let Some(hit) = scan_line(&window, policy) {
            return Some(hit);
        }
        if end == chars.len() {
            break;
        }
        start += step;
    }
    None
}

fn display_path(rel: &str) -> String {
    rel.strip_prefix("items/").unwrap_or(rel).to_string()
}

// Where scrub.json lives; paired with `ensure_policy_file` below.
#[allow(dead_code)]
pub fn policy_path() -> std::path::PathBuf {
    crate::identity::home().join("scrub.json")
}

// Seeds scrub.json on demand; kept for the command that will offer it.
#[allow(dead_code)]
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

    fn long_hit(line: &str) -> Option<String> {
        scan_long_line(line, &Policy::default()).map(|(r, _)| r)
    }

    #[test]
    fn a_long_line_is_scanned_rather_than_skipped() {
        // The bypass: lines over the window were skipped, so padding a line
        // past it hid whatever was on it. One character of padding was the
        // whole attack.
        let padded = "x".repeat(5000) + " ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnN0123";
        assert_eq!(long_hit(&padded).as_deref(), Some("github_token"));
    }

    #[test]
    fn a_token_straddling_a_window_boundary_is_still_seen() {
        // Which is what the overlap is for. Placed deliberately across the
        // first boundary, where a naive chunker loses it.
        let tok = "ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnN0123";
        let line = "y".repeat(WINDOW - 10) + tok + &"z".repeat(5000);
        assert_eq!(long_hit(&line).as_deref(), Some("github_token"));
    }

    #[test]
    fn a_window_boundary_in_the_middle_of_a_character_does_not_panic() {
        // Lossy conversion leaves multi-byte characters in place, and the
        // windows are char-indexed for exactly this reason.
        let line = "é".repeat(WINDOW + 50) + " ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnN0123";
        assert_eq!(long_hit(&line).as_deref(), Some("github_token"));
    }

    #[test]
    fn long_prose_with_nothing_in_it_is_still_clean() {
        let line = "ordinary words about exponential backoff ".repeat(300);
        assert_eq!(long_hit(&line), None);
    }

    #[test]
    fn catches_credentials_in_otherwise_innocent_text() {
        assert_eq!(
            hit("export KEY=sk-ant-api03-abcdefghijklmnop").as_deref(),
            Some("anthropic_key")
        );
        assert_eq!(
            hit("Authorization: Bearer abcdefghijklmnopqrstuvwx").as_deref(),
            Some("bearer")
        );
        assert_eq!(
            hit("aws id AKIAIOSFODNN7EXAMPLE here").as_deref(),
            Some("aws_key")
        );
        assert_eq!(
            hit("-----BEGIN OPENSSH PRIVATE KEY-----").as_deref(),
            Some("private_key")
        );
        assert_eq!(
            hit("ping dana.smith@acmecorp.co.uk about it").as_deref(),
            Some("email")
        );
    }

    #[test]
    fn does_not_fire_on_ordinary_prose() {
        assert!(hit("we decided against tokio-retry for the backoff").is_none());
        assert!(hit("see docs at example.com or mail me@example.com").is_none());
        assert!(
            hit("the sk-ant- prefix identifies an Anthropic key").is_none(),
            "a bare prefix in prose is not a credential"
        );
        assert!(hit("bearer of bad news").is_none());
    }

    #[test]
    fn a_redaction_reveals_neither_the_tail_nor_the_length() {
        // Both were leaking: the last three characters, and the star count as
        // the exact length.
        let tok = "ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnN0123";
        let short = "ghp_aAbBcCdDeEf";
        let (a, b) = (redact(tok), redact(short));
        assert!(!a.contains("0123"), "the tail survived: {a}");
        assert!(!a.contains("aAbBcCdD"), "the body survived: {a}");
        assert_eq!(
            a.chars().count(),
            b.chars().count(),
            "the mask leaks the length"
        );
        assert!(
            a.starts_with("gh"),
            "the prefix should stay recognisable: {a}"
        );
    }

    #[test]
    fn a_finding_never_exposes_the_secret() {
        let (_, prev) =
            scan_line("KEY=sk-ant-api03-SUPERSECRETVALUE1234", &Policy::default()).unwrap();
        assert!(
            !prev.contains("SUPERSECRETVALUE"),
            "preview leaked the secret: {prev}"
        );
        assert!(prev.contains('*'), "preview was not redacted: {prev}");
    }

    #[test]
    fn literal_never_send_entries_match_case_insensitively() {
        let p = Policy {
            never_send: vec!["ProjectHalibut".into()],
            disable: vec![],
        };
        assert!(scan_line("notes on projecthalibut rollout", &p).is_some());
    }
}
