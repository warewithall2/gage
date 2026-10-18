//! Accepting a bundle with nobody watching.
//!
//! `accept` has always meant one thing: a human looked at a frame and moved a
//! bundle out of `pending`. This module is the one path where that happens
//! without the human, and it exists because the alternative people actually
//! build is worse -- a hook that runs `gage accept` itself, which turns every
//! grant into an unbounded one and leaves gage unable to tell an unattended
//! acceptance from a deliberate one afterwards.
//!
//! So it is in the tool, where it can be bounded and recorded. Four conditions,
//! all required:
//!
//! 1. **The watcher was started with `--auto-accept`.** A grant alone is not
//!    enough. The file says what the human permits; the flag says this process
//!    is the unattended one. An interactive `gage watch` must not silently move
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
//! `authorised :` block in `gage open`.
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
    Yes {
        grant: String,
        line: usize,
        used: u64,
        max: u64,
        /// The budget's key: the thread of the parent, read from the
        /// receiver's own `sent/`. Not `m.thread`, which the sender writes.
        thread: String,
    },
    /// The reply names a parent this machine sent but claims to be in a
    /// different thread from it. Refused rather than reinterpreted.
    ThreadClaimDisagreesWithParent,
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
            Decision::Yes {
                grant, used, max, ..
            } => {
                format!(
                    "accepted unattended, {} of {max} in this thread ({grant})",
                    used + 1
                )
            }
            Decision::NoGrant => "no grant covers it, so it stays pending".to_string(),
            Decision::ThreadClaimDisagreesWithParent => {
                "it claims a different thread from the message it answers, so it stays pending"
                    .to_string()
            }
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
    decide(
        contacts,
        authority,
        l,
        crate::authority::answers_something_i_sent(home, &l.manifest),
        &|t| crate::journal::auto_accepts_in_thread(t),
    )
}

/// The decision itself, with the two things it reads from disk handed in.
///
/// Split out from `consider` so the **choice of budget key** is testable, and
/// that is not a style preference. The hole a reviewer found was keying the
/// budget on the sender's `m.thread` instead of the parent's. When the fix
/// went in, the shell suite could not reach it -- `--reply-to` inherits the
/// parent's thread, so no sender built through this CLI ever disagrees with
/// its parent, and reaching the attack needs a sender that hand-signs its own
/// manifest. The unit test written at the same time was worse than useless:
/// it exercised `count_auto`, which counts the right field, while the
/// mutation was here, in the code that *picks* the field. Reinstating the
/// original bug left all 586 shell checks and all 97 unit tests green.
///
/// So the decision takes `parent` and `used` as inputs, and a test can hand
/// it a manifest whose thread claim disagrees with its parent's.
pub fn decide(
    contacts: &crate::trust::Contacts,
    authority: &Authority,
    l: &crate::bundle::Loaded,
    parent: Option<crate::authority::Parent>,
    used: &dyn Fn(&str) -> u64,
) -> Decision {
    let m = &l.manifest;
    // A bundle whose items do not match its manifest is not a candidate for
    // anything unattended, whatever the grant says.
    if !l.tampered.is_empty() {
        return Decision::NoGrant;
    }
    let Ok(g) = authority.lookup(contacts, l.trust, &m.from.key, m.msg_type, parent.is_some())
    else {
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
    // `auto_accept` implies `in_reply_only`, so a grant that reaches here has
    // a parent. Written as a refusal rather than an unwrap because the
    // implication lives in `parse` and a future caller building a `Grant` in
    // code could reach this without one.
    let Some(parent) = parent else {
        return Decision::NoGrant;
    };
    // A reply that claims a different thread from the parent it answers is
    // refused outright. It is not needed for the budget -- the key below is
    // the parent's thread whatever the reply says -- but it is precisely the
    // shape of an attempt to mint a bucket, and `state::thread_claim` already
    // treats such a claim as not joining the thread. There is no legitimate
    // sender that does this: `gage reply` and `--reply-to` both inherit.
    if let Some(claimed) = m.thread.as_deref() {
        if claimed != parent.thread {
            return Decision::ThreadClaimDisagreesWithParent;
        }
    }
    // The budget's key is read out of the receiver's own `sent/`, never off
    // the wire. This is the fix for the hole a reviewer found: keying on
    // `m.thread` let one granted sender answer the same parent under a new
    // thread id each time and collect a fresh budget for each.
    let used = used(&parent.thread);
    if used >= max {
        return Decision::BudgetSpent {
            grant: rendered,
            used,
            max,
        };
    }
    Decision::Yes {
        grant: rendered,
        line: g.line,
        used,
        max,
        thread: parent.thread,
    }
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
    let Decision::Yes {
        grant,
        line,
        used,
        max,
        thread,
    } = d
    else {
        return Err(std::io::Error::other("not an acceptance"));
    };
    let from = crate::routes::pending_dir(home).join(id);
    let to_dir = crate::routes::accepted_dir(home);
    std::fs::create_dir_all(&to_dir)?;
    let dest = to_dir.join(id);
    // **Record first, then move.** The other order is what this function did
    // first, and it is wrong in both directions that matter.
    //
    // Unlike every other journal site -- where a failed write is reported and
    // ignored, because a machine that refuses a bundle over a log line has
    // turned an audit feature into an outage -- here the entry *is* the
    // budget. Moving first means a failed or raced write leaves a bundle
    // accepted with nothing counting it, which is both an unrecorded
    // unattended acceptance and a budget that can be spent indefinitely by
    // arranging for the write to fail.
    //
    // This order fails the other way: a successful entry followed by a failed
    // move spends a budget on a bundle still sitting in `pending`, where a
    // human will deal with it. Over-counting costs an exchange; under-counting
    // costs the bound.
    //
    // `record_with_auto` rechecks the budget under the journal lock and
    // errors if it went, so the count that authorises the move and the count
    // that records it are one read of one file.
    crate::journal::record_with_auto(
        crate::journal::Event::Accepted,
        &from,
        Some(crate::journal::Auto {
            grant: grant.clone(),
            line: *line,
            used: *used,
            max: *max,
            thread: thread.clone(),
        }),
    )?;
    crate::routes::restage(&from, &dest)?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{Grant, parse};

    fn grant(text: &str) -> Grant {
        parse(text)
            .expect("fixture parses")
            .pop()
            .expect("one grant")
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
            Decision::ThreadClaimDisagreesWithParent,
            Decision::GrantIsNotAutoAccept("allow codex question".into()),
            Decision::BudgetSpent {
                grant: "allow codex question".into(),
                used: 4,
                max: 4,
            },
        ] {
            let s = d.explain();
            assert!(s.contains("stays pending"), "{s}");
        }
        let yes = Decision::Yes {
            grant: "allow codex question".into(),
            line: 1,
            used: 0,
            max: 4,
            thread: "parent".into(),
        };
        // `used` is what was already spent, so the human-facing count is +1.
        assert!(yes.explain().contains("1 of 4"), "{}", yes.explain());
    }

    fn loaded(claimed_thread: Option<&str>) -> crate::bundle::Loaded {
        use crate::manifest::*;
        let p = Peer {
            handle: "sndr".into(),
            key: "SNDRKEY".into(),
        };
        crate::bundle::Loaded {
            manifest: Manifest {
                v: 1,
                id: "0000000000000000".into(),
                created: "2026-10-17T00:00:00Z".into(),
                subject: "s".into(),
                from: p.clone(),
                to: vec!["recv".into()],
                agent: None,
                chain: vec![Hop {
                    by: p,
                    at: "2026-10-17T00:00:00Z".into(),
                    action: HopAction::Created,
                }],
                in_reply_to: Some("1111111111111111".into()),
                thread: claimed_thread.map(|t| t.to_string()),
                msg_type: MsgType::Answer,
                items: vec![],
            },
            trust: crate::trust::Trust::Known,
            dir: std::path::PathBuf::from("/nonexistent"),
            tampered: vec![],
            unwitnessed: false,
        }
    }

    fn setup() -> (crate::trust::Contacts, Authority) {
        let mut c = crate::trust::Contacts::default();
        c.keys.insert("SNDRKEY".into(), "sndr".into());
        let a = Authority {
            grants: parse("allow sndr answer auto-accept max-exchanges 1\n").unwrap(),
            present: true,
            error: None,
        };
        (c, a)
    }

    #[test]
    fn the_budget_is_keyed_on_the_parent_the_receiver_sent_not_the_senders_claim() {
        // The reviewer's attack, as the only test that catches it. The sender
        // answers a verified parent whose thread is `PARENT`, while claiming
        // to be in a thread of its own. Keyed on the claim, the budget reads
        // 0 and this is accepted; keyed on the parent, it reads 1 and spent.
        //
        // Reinstating the original bug left every shell check and every other
        // unit test green, which is why this one is written against `decide`
        // rather than against the counter it uses.
        let (c, a) = setup();
        let parent = crate::authority::Parent {
            id: "1111111111111111".into(),
            thread: "PARENT".into(),
        };
        let used = |t: &str| if t == "PARENT" { 1 } else { 0 };
        // A reply that keeps its parent's thread, with the budget spent.
        let d = decide(&c, &a, &loaded(Some("PARENT")), Some(parent.clone()), &used);
        assert!(
            matches!(
                d,
                Decision::BudgetSpent {
                    used: 1,
                    max: 1,
                    ..
                }
            ),
            "a spent budget was not spent: {d:?}"
        );
        // And one that claims a thread of its own is refused before the
        // budget is even consulted.
        let d = decide(&c, &a, &loaded(Some("MINTED")), Some(parent.clone()), &used);
        assert_eq!(
            d,
            Decision::ThreadClaimDisagreesWithParent,
            "a minted thread claim was not refused"
        );
        // Belt and braces: with the claim-check satisfied by an ABSENT claim,
        // the key is still the parent's, so the budget is still spent. This
        // is the assertion that fails if the key reverts to `m.thread`,
        // independently of the refusal above.
        let d = decide(&c, &a, &loaded(None), Some(parent), &used);
        assert!(
            matches!(d, Decision::BudgetSpent { .. }),
            "with no thread claimed, the budget was not keyed on the parent: {d:?}"
        );
    }

    #[test]
    fn a_reply_to_nothing_this_machine_sent_reaches_no_auto_accept_grant() {
        // `auto-accept` implies `in-reply-only`, so a `None` parent must not
        // reach a grant at all.
        let (c, a) = setup();
        let d = decide(&c, &a, &loaded(Some("x")), None, &|_| 0);
        assert_eq!(d, Decision::NoGrant);
    }

    #[test]
    fn perform_refuses_a_decision_that_is_not_an_acceptance() {
        // So no caller can reach the move by passing the wrong answer.
        let d = Decision::NoGrant;
        assert!(perform(std::path::Path::new("/nonexistent"), "deadbeefdeadbeef", &d).is_err());
    }
}
