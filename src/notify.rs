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
                .unwrap_or_else(|| format!("\"{}\" (unlisted)", m.from.handle)),
            msg_type: m.msg_type.label().to_string(),
            subject: m.subject.clone(),
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

/// Fire a desktop notification. Absence of a notifier is not an error: on a
/// server there is no desktop, and `ctx watch` still has to work there.
pub fn desktop(title: &str, body: &str, urgent: bool) -> bool {
    let mut c = Command::new("notify-send");
    c.arg("--app-name=ctx")
        .arg(format!("--urgency={}", if urgent { "critical" } else { "normal" }))
        .arg(title)
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
    fn a_notification_never_carries_payload_contents() {
        // summarise only ever sees metadata; this pins that it cannot grow a
        // contents field without the test failing.
        let (t, b) = summarise(&[p("dana", "share", "quarterly numbers", false)]);
        for s in [&t, &b] {
            assert!(!s.contains("items/"), "notification referenced bundle contents: {s}");
        }
    }
}
