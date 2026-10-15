//! Telling you something arrived.
//!
//! Polling is the only option: a relay that pushes would have to hold an open
//! connection per mailbox, and the agents are not processes that stay running
//! anyway -- they are invoked. So `ctx watch` pulls on an interval and fires a
//! desktop notification when something genuinely new lands.
//!
//! "Genuinely new" means unread AND not previously announced. Without the
//! second half, every poll re-announces the same bundle until you open it,
//! which trains you to dismiss the notification -- the failure mode that makes
//! a notifier worse than nothing.
//!
//! What the notification says is deliberately thin: who it is from, what type,
//! and the subject. Not the contents. A desktop notification is rendered by
//! another process, may be logged, and can sit on a lock screen, so a bundle's
//! payload has no business in one.

use std::collections::BTreeSet;
use std::process::Command;

/// Ids already announced, so a repeat poll stays quiet.
fn announced_path() -> std::path::PathBuf {
    crate::identity::home().join("announced.json")
}

fn load_announced() -> BTreeSet<String> {
    std::fs::read_to_string(announced_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_announced(s: &BTreeSet<String>) {
    // Keep it bounded; the oldest ids stop mattering once collected.
    let trimmed: BTreeSet<String> = s.iter().rev().take(2000).cloned().collect();
    if let Ok(v) = serde_json::to_vec(&trimmed) {
        let _ = std::fs::write(announced_path(), v);
    }
}

pub struct Pending {
    pub id: String,
    pub from: String,
    pub msg_type: String,
    pub subject: String,
    pub expects_reply: bool,
}

/// Unread, un-announced bundles sitting in pending.
pub fn new_arrivals() -> Vec<Pending> {
    let st = crate::state::LocalState::load();
    let contacts = crate::trust::Contacts::load();
    let seen = load_announced();
    let home = crate::identity::home();
    let mut out = Vec::new();
    for (_, l) in crate::routes::list(&crate::routes::pending_dir(&home)) {
        let m = &l.manifest;
        // A bundle that does not verify is not announced at all.
        //
        // Announce-once is keyed on the bundle id, so a bundle carrying
        // somebody else's id got announced, `mark_announced` recorded that
        // id, and the genuine arrival was then skipped as already seen -- a
        // real message silenced by a fake one. `load` already reports the id
        // mismatch; this is the part that was ignoring it.
        if !l.tampered.is_empty() || matches!(l.trust, crate::trust::Trust::Unverified) {
            continue;
        }
        if st.is_read(&m.id) || seen.contains(&m.id) {
            continue;
        }
        out.push(Pending {
            id: m.id.clone(),
            from: contacts
                .name_for(&m.from.key)
                .map(|s| s.to_string())
                // An unlisted key's claimed handle is quoted, because a
                // notification is exactly where a forged name would be
                // believed fastest.
                .unwrap_or_else(|| format!("\"{}\" (unlisted)", one_line(&m.from.handle, 40))),
            msg_type: m.msg_type.label().to_string(),
            subject: one_line(&m.subject, 120),
            expects_reply: m.msg_type.expects_reply(),
        });
    }
    out
}

pub fn mark_announced(ids: &[String]) {
    let mut s = load_announced();
    for i in ids {
        s.insert(i.clone());
    }
    save_announced(&s);
}

/// Flatten sender-controlled text to a single bounded line.
///
/// The subject and an unlisted handle go straight into a desktop
/// notification, and both are written by the sender. Newlines were the
/// problem: a subject containing them could forge extra arrival lines, or an
/// "awaiting your reply" that nobody asked for, in a popup the reader has
/// every reason to treat as the tool's own voice. Markup is stripped for the
/// same reason -- some notification daemons render it -- and the length is
/// capped so one subject cannot push the rest off the screen.
fn one_line(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| *c != '<' && *c != '>' && *c != '&')
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max).collect();
        format!("{cut}…")
    } else {
        flat
    }
}

/// Fire a desktop notification. Absence of a notifier is not an error: on a
/// server there is no desktop, and `ctx watch` still has to work there.
pub fn desktop(title: &str, body: &str, urgent: bool) -> bool {
    let mut c = Command::new("notify-send");
    c.arg("--app-name=ctx")
        .arg(format!("--urgency={}", if urgent { "critical" } else { "normal" }))
        // `--` before the positional arguments, so a subject that begins with
        // a dash is a subject rather than an option to notify-send. The
        // arguments are passed as argv and never through a shell, so nothing
        // here is executed; the risk was option injection, not command
        // injection.
        .arg("--")
        .arg(one_line(title, 160))
        .arg(body);
    matches!(c.status(), Ok(s) if s.success())
}

pub fn summarise(p: &[Pending]) -> (String, String) {
    if p.len() == 1 {
        let m = &p[0];
        let t = format!("ctx: {} from {}", m.msg_type, m.from);
        let b = if m.expects_reply {
            format!("{}\nawaiting your reply", m.subject)
        } else {
            m.subject.clone()
        };
        (t, b)
    } else {
        let needs = p.iter().filter(|x| x.expects_reply).count();
        let t = format!("ctx: {} new bundles", p.len());
        let mut b: Vec<String> = p.iter().take(4).map(|x| format!("{} — {}", x.from, x.subject)).collect();
        if p.len() > 4 {
            b.push(format!("and {} more", p.len() - 4));
        }
        if needs > 0 {
            b.push(format!("{needs} awaiting your reply"));
        }
        (t, b.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(from: &str, ty: &str, subj: &str, expects: bool) -> Pending {
        Pending {
            id: "x".into(),
            from: from.into(),
            msg_type: ty.into(),
            subject: subj.into(),
            expects_reply: expects,
        }
    }

    #[test]
    fn a_single_arrival_names_sender_and_type() {
        let (t, b) = summarise(&[p("codex", "question", "key rotation", true)]);
        assert!(t.contains("question") && t.contains("codex"), "{t}");
        assert!(b.contains("awaiting your reply"), "{b}");
    }

    #[test]
    fn many_arrivals_collapse_rather_than_spam() {
        let v: Vec<Pending> = (0..7).map(|i| p("grok", "share", &format!("s{i}"), false)).collect();
        let (t, b) = summarise(&v);
        assert!(t.contains('7'), "{t}");
        assert!(b.contains("and 3 more"), "{b}");
    }

    #[test]
    fn sender_text_cannot_forge_extra_notification_lines() {
        // A subject with newlines in it could write its own "awaiting your
        // reply" line, or invent further arrivals, inside a popup the reader
        // treats as the tool's own voice.
        let forged = "innocent\nawaiting your reply\nctx: 4 new bundles";
        let flat = one_line(forged, 120);
        assert!(!flat.contains('\n'), "newlines survived: {flat:?}");
        assert!(flat.starts_with("innocent"));
    }

    #[test]
    fn notification_text_is_bounded_and_unmarked_up() {
        let long = "x".repeat(500);
        assert!(one_line(&long, 120).chars().count() <= 121);
        assert_eq!(one_line("<b>bold</b> &amp;", 120), "bbold/b amp;");
        // control characters go, including the ones that move a cursor
        // a control character becomes a space, then whitespace collapses
        assert_eq!(one_line("a\u{1b}[2Kb\tc", 120), "a [2Kb c");
    }

    #[test]
    fn a_notification_never_carries_payload_contents() {
        // summarise only ever sees metadata; this pins that it cannot grow a
        // contents field without the test failing.
        let (t, b) = summarise(&[p("dana", "share", "quarterly numbers", false)]);
        for s in [&t, &b] {
            assert!(!s.contains("items/"), "notification referenced bundle contents: {s}");
        }
    }
}
