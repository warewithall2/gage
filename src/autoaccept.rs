//! Accepting a bundle with nobody watching.
//!
//! `accept` has always meant one thing: a human looked at a frame and moved a
//! bundle out of `pending`. This module is the one path where that happens
//! without the human, and it exists because the alternative people actually
//! build is worse -- a hook that runs `ctx accept` itself, which turns every
//! grant into an unbounded one and leaves ctx unable to tell an unattended
//! acceptance from a deliberate one afterwards.
//!
//! So it is in the tool, where it can be bounded and recorded. Four conditions,
//! all required:
//!
//! 1. **The watcher was started with `--auto-accept`.** A grant alone is not
//!    enough. The file says what the human permits; the flag says this process
//!    is the unattended one. An interactive `ctx watch` must not silently move
//!    things a reader is about to go looking for.
//! 2. **A grant covers the message and says `auto-accept`.** Which, per
//!    `authority::parse`, cannot be written without a bound and cannot be
//!    written against `any`.
//! 3. **It answers something this machine sent** -- implied by the grant, and
//!    checked against `sent/` rather than against the sender's own claim.
//! 4. **The thread's budget is not spent**, counted from the journal.
//!
//! ## What this is not
//!
//! It is not permission to *act*. Acceptance moves a directory and marks it
//! readable; it does not open it, hand it to a model, or run anything. The
//! separation is the point: an auto-accepted bundle still sits there until
//! something reads it, and what that something may do with it is still the
//! `authorised :` block in `ctx open`.
//!
//! It also does not make the budget a security boundary against a determined
//! sender with a verified key. That sender can still reply to each message
//! this machine sends, within the bound, forever. What the bound buys is that
//! a *runaway* exchange -- two agents answering each other, a loop, a sender
//! that got stuck -- stops at a number a human chose, instead of at whatever
//! the disk or the relay runs out of first.

use crate::authority::Authority;

/// Why a bundle was or was not accepted unattended. Carried rather than
/// collapsed to a bool so `watch` can print something true in each case, and
/// so the shell suite can assert on the reason rather than on the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Yes { grant: String, line: usize, used: u64, max: u64 },
    /// No grant matched. Covers an unverified sender, a missing file, the
    /// wrong kind, and a message that answers nothing this machine sent --
    /// `authority::Denied` distinguishes those for the frame; here they are
    /// one answer, because the action is the same.
    NoGrant,
    /// A grant matched and does not say `auto-accept`. The common case for
    /// anyone using grants at all, and worth separating: it means the human
    /// has considered this sender and declined exactly this.
    GrantIsNotAutoAccept(String),
    /// The grant says so, the budget is gone.
    BudgetSpent { grant: String, used: u64, max: u64 },
}

impl Decision {
    /// One line for the watcher's output. Never includes sender-written text.
    pub fn explain(&self) -> String {
        match self {
            Decision::Yes { grant, used, max, .. } => {
                format!("accepted unattended, {} of {max} in this thread ({grant})", used + 1)
            }
            Decision::NoGrant => "no grant covers it, so it stays pending".to_string(),
            Decision::GrantIsNotAutoAccept(g) => {
                format!("a grant covers it but does not say auto-accept ({g}), so it stays pending")
            }
            Decision::BudgetSpent { grant, used, max } => format!(
                "this thread has used {used} of {max} auto-accepts ({grant}), so it stays pending"
            ),
        }
    }
}

/// Decide, without doing anything.
///
/// Separate from `perform` so the decision is testable and so the reason can
/// be printed for a bundle that is left alone, which is most of them.
/// `trust` is taken from the loaded bundle rather than recomputed, for the
/// same reason `Authority::lookup` takes it: one place decides a verdict.
pub fn consider(
    home: &std::path::Path,
    contacts: &crate::trust::Contacts,
    authority: &Authority,
    l: &crate::bundle::Loaded,
) -> Decision {
    let m = &l.manifest;
    // A bundle whose items do not match its manifest is not a candidate for
    // anything unattended, whatever the grant says.
    if !l.tampered.is_empty() {
        return Decision::NoGrant;
    }
    let is_reply = crate::authority::answers_something_i_sent(home, m);
    let Ok(g) = authority.lookup(contacts, l.trust, &m.from.key, m.msg_type, is_reply) else {
        return Decision::NoGrant;
    };
    let rendered = g.to_string();
    if !g.auto_accept {
        return Decision::GrantIsNotAutoAccept(rendered);
    }
    // `parse` refuses `auto-accept` without a bound, so this is unreachable
    // through the file. It is written as a refusal rather than a default
    // because a future caller constructing a `Grant` in code should not get
    // an unbounded one by leaving a field at `None`.
    let Some(max) = g.max_exchanges else {
        return Decision::GrantIsNotAutoAccept(rendered);
    };
    let thread = crate::journal::clean_thread(m.thread.as_deref());
    let used = crate::journal::auto_accepts_in_thread(thread.as_ref());
    if used >= max {
        return Decision::BudgetSpent { grant: rendered, used, max };
    }
    Decision::Yes { grant: rendered, line: g.line, used, max }
}

/// Carry out an acceptance that `consider` returned `Yes` for.
///
/// Takes the decision rather than re-deciding, so there is no path where the
/// move happens under one answer and the record is written under another.
pub fn perform(
    home: &std::path::Path,
    id: &str,
    d: &Decision,
) -> std::io::Result<std::path::PathBuf> {
    let Decision::Yes { grant, line, used, max } = d else {
        return Err(std::io::Error::other("not an acceptance"));
    };
    let from = crate::routes::pending_dir(home).join(id);
    let to_dir = crate::routes::accepted_dir(home);
    std::fs::create_dir_all(&to_dir)?;
    let dest = to_dir.join(id);
    crate::routes::restage(&from, &dest)?;
    // Unlike every other journal site, a failure here is **fatal to the
    // feature**: the entry is not only the audit record, it is the budget.
    // An unattended accept whose line was lost is an accept that does not
    // count, and a sender could spend a budget indefinitely by arranging for
    // the write to fail. So it is reported loudly, and the caller stops
    // auto-accepting for this run.
    crate::journal::record_with_auto(
        crate::journal::Event::Accepted,
        &dest,
        Some(crate::journal::Auto {
            grant: grant.clone(),
            line: *line,
            used: *used,
            max: *max,
        }),
    )?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{parse, Grant};

    fn grant(text: &str) -> Grant {
        parse(text).expect("fixture parses").pop().expect("one grant")
    }

    #[test]
    fn auto_accept_cannot_be_written_without_a_bound() {
        // The failure direction that matters: a half-written grant must not
        // read as an unbounded one.
        let e = parse("allow codex question auto-accept\n").expect_err("needs a bound");
        assert!(e.contains("max-exchanges"), "{e}");
    }

    #[test]
    fn auto_accept_cannot_be_written_against_any() {
        let e = parse("allow codex any auto-accept max-exchanges 4\n").expect_err("any is refused");
        assert!(e.contains("name the one kind"), "{e}");
    }

    #[test]
    fn a_zero_budget_is_refused_rather_than_read_as_never() {
        assert!(parse("allow codex question auto-accept max-exchanges 0\n").is_err());
    }

    #[test]
    fn auto_accept_implies_in_reply_only_even_when_unwritten() {
        // The property the per-thread budget rests on. A thread id is chosen
        // by the sender, so without this a sender gets a fresh budget by
        // inventing a fresh thread.
        let g = grant("allow codex question auto-accept max-exchanges 4\n");
        assert!(g.in_reply_only, "auto-accept did not imply in-reply-only");
        assert!(g.auto_accept);
        assert_eq!(g.max_exchanges, Some(4));
    }

    #[test]
    fn a_rendered_grant_shows_what_is_in_force_not_what_was_typed() {
        // The reader is shown the implied modifier, because the rendered line
        // is what goes in the journal and what the watcher prints.
        let g = grant("allow codex question auto-accept max-exchanges 2\n");
        assert_eq!(
            g.to_string(),
            "allow codex question in-reply-only auto-accept max-exchanges 2"
        );
    }

    #[test]
    fn a_bound_without_auto_accept_is_accepted_and_grants_no_acceptance() {
        // `max-exchanges` on its own is harmless and means nothing. It is not
        // an error, because a human removing `auto-accept` from a line to
        // switch it off should not then be told the file is broken.
        let g = grant("allow codex question max-exchanges 9\n");
        assert!(!g.auto_accept);
        assert!(!g.in_reply_only);
    }

    #[test]
    fn every_refusal_explains_itself_without_quoting_a_sender() {
        for d in [
            Decision::NoGrant,
            Decision::GrantIsNotAutoAccept("allow codex question".into()),
            Decision::BudgetSpent { grant: "allow codex question".into(), used: 4, max: 4 },
        ] {
            let s = d.explain();
            assert!(s.contains("stays pending"), "{s}");
        }
        let yes = Decision::Yes {
            grant: "allow codex question".into(),
            line: 1,
            used: 0,
            max: 4,
        };
        // `used` is what was already spent, so the human-facing count is +1.
        assert!(yes.explain().contains("1 of 4"), "{}", yes.explain());
    }

    #[test]
    fn perform_refuses_a_decision_that_is_not_an_acceptance() {
        // So no caller can reach the move by passing the wrong answer.
        let d = Decision::NoGrant;
        assert!(perform(std::path::Path::new("/nonexistent"), "deadbeefdeadbeef", &d).is_err());
    }
}
