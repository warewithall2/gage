//! Telling you something arrived.
//!
//! Polling is the only option: a relay that pushes would have to hold an open
//! connection per mailbox, and the agents are not processes that stay running
//! anyway -- they are invoked. So `gage watch` pulls on an interval and fires a
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

/// Announced ids, **oldest first**.
///
/// It used to be a `BTreeSet`, and a reviewer found what that cost. A set has
/// no arrival order, so trimming it to a bound kept the lexicographically
/// largest ids rather than the newest -- and bundle ids are hex, so the ids
/// dropped first were the ones beginning `0`, `1`, `2`. Dropped from this
/// file, a bundle is announced again on the next poll, and with
/// `--on-arrival` it is *acted on* again. The comment said "the oldest ids
/// stop mattering once collected", which was true of the intent and false of
/// the code.
///
/// A list in insertion order trims the end that the comment always meant.
/// The old format still loads: a set of ids read back as a list is in sorted
/// rather than arrival order, which is wrong but harmless, because every id
/// in it has already been announced and the only cost is trimming the wrong
/// one once more before the file turns over.
fn load_announced() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(announced_path()) else {
        return Vec::new();
    };
    if let Ok(v) = serde_json::from_str::<Vec<String>>(&text) {
        return v;
    }
    serde_json::from_str::<BTreeSet<String>>(&text)
        .map(|s| s.into_iter().collect())
        .unwrap_or_default()
}

fn save_announced(v: &[String]) {
    // Trim the FRONT, which is the old end. 2000 is a bound on the file, not
    // a policy about what matters: every id in here has been announced, and
    // the only thing dropping one costs is announcing that bundle twice.
    let start = v.len().saturating_sub(2000);
    if let Ok(bytes) = serde_json::to_vec(&v[start..]) {
        let _ = std::fs::write(announced_path(), bytes);
    }
}

pub struct Pending {
    pub id: String,
    pub from: String,
    pub msg_type: String,
    pub subject: String,
    pub expects_reply: bool,
    /// The sender's signing key, as `gage whoami` prints it. Carried so the
    /// hook can be given it without re-deriving it from `from`, which is a
    /// contact name or a quoted claim and is not an identity.
    pub key: String,
    /// The grant in the receiver's own authority file that covers this
    /// message, rendered as the line it came from. `None` is the normal case
    /// and means no hook runs: see `run_hook`.
    pub grant: Option<String>,
}

/// Unread, un-announced bundles sitting in pending.
pub fn new_arrivals() -> Vec<Pending> {
    let st = crate::state::LocalState::load();
    let contacts = crate::trust::Contacts::load();
    let authority = crate::authority::Authority::load();
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
        // The same lookup `gage open` performs, on the same inputs. A
        // reviewer was right that the old comment here -- "a hook can never
        // fire on an authority the reader was not shown" -- claimed more
        // than the code does: this is a fresh snapshot taken at poll time,
        // and contacts or the authority file can change before anyone reads
        // the frame. What is true is that the two call the one function, so
        // they cannot disagree about the same inputs.
        let grant = authority
            .lookup(
                &contacts,
                l.trust,
                &m.from.key,
                m.msg_type,
                crate::authority::answers_something_i_sent(&home, m).is_some(),
            )
            .ok()
            .map(|g| g.to_string());
        out.push(Pending {
            key: m.from.key.clone(),
            grant,
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
    let mut v = load_announced();
    for i in ids {
        if !v.iter().any(|x| x == i) {
            v.push(i.clone());
        }
    }
    save_announced(&v);
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
/// server there is no desktop, and `gage watch` still has to work there.
pub fn desktop(title: &str, body: &str, urgent: bool) -> bool {
    let mut c = Command::new("notify-send");
    c.arg("--app-name=gage")
        .arg(format!(
            "--urgency={}",
            if urgent { "critical" } else { "normal" }
        ))
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
        let t = format!("gage: {} from {}", m.msg_type, m.from);
        let b = if m.expects_reply {
            format!("{}\nawaiting your reply", m.subject)
        } else {
            m.subject.clone()
        };
        (t, b)
    } else {
        let needs = p.iter().filter(|x| x.expects_reply).count();
        let t = format!("gage: {} new bundles", p.len());
        let mut b: Vec<String> = p
            .iter()
            .take(4)
            .map(|x| format!("{} — {}", x.from, x.subject))
            .collect();
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
            key: "k".into(),
            grant: None,
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
        let v: Vec<Pending> = (0..7)
            .map(|i| p("grok", "share", &format!("s{i}"), false))
            .collect();
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
            assert!(
                !s.contains("items/"),
                "notification referenced bundle contents: {s}"
            );
        }
    }
}

/// Run the receiver's own command for one arrival.
///
/// This is the only place in gage where something arriving causes something to
/// happen without a human in the loop, so the shape of it is the whole
/// security argument:
///
/// 1. **It fires only where a grant matched at the moment of the poll.** Not
///    "verified", which only says whose key signed it -- the authority file
///    is the only thing in the tool that says an agent may act, and this is
///    the unattended path, so it is the one caller that must not settle for
///    less. An unlisted sender, or a verified sender with no grant, notifies
///    exactly as before and runs nothing.
///
///    Stated that precisely because a reviewer was right that the looser
///    phrasing ("a grant already covers it") implies a freshness the lookup
///    does not establish. It is a snapshot of local files: the grant has no
///    expiry, it was not necessarily written recently, and any process
///    running as this user can edit the file. What it proves is that a line
///    the user's own machine holds names this sender and this kind -- which
///    is the strongest thing available locally and less than "a human just
///    approved this".
/// 2. **The hook never receives the bundle's items.** It gets the id, the
///    sender's key, the contact name, the type and the subject. A bundle's
///    contents are the thing the accept gate exists to hold back; a hook that
///    handed them over would have quietly removed the gate for every arrival
///    that happened to match a grant.
///
///    Not "never receives message content", which a reviewer rightly called
///    out: the subject is written by the sender and travels here. It is one
///    bounded line rather than a file, and it is already in the notification
///    the human sees, so it leaks nothing the desktop popup does not -- but
///    it is the sender's text, and a hook that treats it as trustworthy input
///    is a hook with a problem.
/// 3. **This code does not accept the bundle.** `run_hook` moves nothing.
///
///    With `--auto-accept` ALSO given, though, the bundle may already be in
///    `accepted` before this runs: the watcher does its auto-accept pass
///    first, deliberately, so that a hook written for an unattended loop
///    finds the bundle settled rather than racing the watcher for it. So
///    "still unread, still in `pending`" -- which this note and the README
///    both used to say flatly -- is true of `--on-arrival` alone and false of
///    the two flags together. `CTX_AUTO_ACCEPTED` tells the hook which world
///    it is in, and was already being set when the claim above still read as
///    unconditional.
///
///    Stated about this code rather than about the world, because a reviewer
///    was right that the stronger phrasing was false. The hook is handed
///    `CTX_BUNDLE_ID` and can perfectly well run `gage accept && gage open`
///    itself -- and for an agent loop, that is the point. What gage guarantees
///    is that *nothing here* crosses the gate, so crossing it remains an act
///    the receiver's own hook performs, under its own name, with a journal
///    entry to show it. The gate is not removed; it is left where it is, for
///    the hook to walk through deliberately.
/// 4. **gage does not interpolate sender text into the command string.** The subject is written by whoever sent it. Pasted
///    into a shell line it would be a command injection with extra steps, so
///    the command the receiver wrote is passed to `sh -c` untouched and every
///    sender-chosen value arrives as `$CTX_SUBJECT` and friends -- already
///    flattened to one bounded line by `one_line`, because a newline in an
///    environment variable is still a newline in whatever the hook writes it
///    to.
///
///    Phrased as what gage does rather than "sender text is data, never
///    command", which a reviewer rightly called hook-dependent. `"$CTX_SUBJECT"`
///    quoted is data. `eval "$CTX_SUBJECT"`, an unquoted expansion inviting
///    word-splitting and globbing, a value used where a command expects an
///    option, or a second shell string built from it -- each hands the sender
///    a shell, and nothing here can prevent any of them, because the hook is
///    the receiver's own code. Environment values are also inherited by the
///    hook's children and readable from the process environment by anything
///    running as this user. The guarantee is one link in the chain, not the
///    chain.
///
/// A non-zero exit or a timeout is reported and otherwise ignored, and the
/// arrival is still marked announced.
///
/// That is an **at-most-once** policy, and it is a choice rather than the
/// only safe direction -- the first version of this comment claimed the
/// latter and a reviewer was right to object. The real trade is between
/// losing a hook and running one twice: marking first means a crash between
/// the mark and the hook loses it silently, while marking after would re-fire
/// a failing hook on every poll. There is no separate "hook completed" state
/// that would allow at-least-once without that loop, and adding one is the
/// honest fix if a hook ever does something that must not be skipped.
/// Until then: at most once, stated as such.
pub fn run_hook(cmd: &str, p: &Pending, timeout: u64, auto_accepted: bool) -> Result<(), String> {
    use std::process::Stdio;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("CTX_BUNDLE_ID", &p.id)
        .env("CTX_FROM", one_line(&p.from, 80))
        .env("CTX_FROM_KEY", &p.key)
        .env("CTX_TYPE", &p.msg_type)
        .env("CTX_SUBJECT", one_line(&p.subject, 200))
        .env("CTX_EXPECTS_REPLY", if p.expects_reply { "1" } else { "0" })
        .env("CTX_GRANT", p.grant.clone().unwrap_or_default())
        // So a hook does not have to guess where the bundle is, or race the
        // watcher for it. "1" means it is already in `accepted` and `gage
        // accept` would now fail; "0" means it is still pending and a hook
        // that accepts it is spending nothing a grant counted.
        .env("CTX_AUTO_ACCEPTED", if auto_accepted { "1" } else { "0" })
        // No payload on stdin either: a hook that read stdin expecting the
        // bundle would get EOF, which is the right answer to that question.
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start the hook: {e}"))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(st)) => return Err(format!("the hook exited {}", code_of(st))),
            Ok(None) => {}
            Err(e) => return Err(format!("could not wait for the hook: {e}")),
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "the hook ran longer than {timeout}s and was killed"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn code_of(st: std::process::ExitStatus) -> String {
    match st.code() {
        Some(c) => c.to_string(),
        None => "on a signal".to_string(),
    }
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    fn p() -> Pending {
        Pending {
            id: "abc123".into(),
            from: "mac".into(),
            msg_type: "share".into(),
            subject: "one\ntwo".into(),
            expects_reply: false,
            key: "KEY".into(),
            grant: Some("allow mac share".into()),
        }
    }

    #[test]
    fn the_hook_gets_sender_text_as_data_not_as_shell() {
        let out = std::env::temp_dir().join(format!("gage-hook-{}", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let mut hostile = p();
        // A subject that would run a command if it were ever pasted into the
        // command string instead of handed over in the environment.
        hostile.subject = format!("$(touch {})", out.display());
        run_hook(
            "printf '%s' \"$CTX_SUBJECT\" > /dev/null",
            &hostile,
            10,
            false,
        )
        .unwrap();
        assert!(!out.exists(), "a subject executed as shell");
    }

    #[test]
    fn a_newline_in_the_subject_cannot_forge_a_second_line() {
        // The hook writes one line per value; a subject holding a newline
        // would otherwise become two lines in whatever the hook writes to.
        let flat = one_line(&p().subject, 200);
        assert!(!flat.contains('\n'));
        assert_eq!(flat, "one two");
    }

    #[test]
    fn a_hook_that_hangs_is_killed_rather_than_stalling_the_watcher() {
        let err = run_hook("sleep 30", &p(), 1, false).unwrap_err();
        assert!(err.contains("was killed"), "{err}");
    }

    #[test]
    fn a_failing_hook_is_reported_with_its_code() {
        let err = run_hook("exit 7", &p(), 10, false).unwrap_err();
        assert!(err.contains("exited 7"), "{err}");
    }
}
