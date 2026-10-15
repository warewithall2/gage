//! What the receiver's own user has pre-authorised.
//!
//! Every other verdict in ctx is a statement about what is *known*. This is
//! the only thing in the tool that tells an agent it may *act*, which is why
//! it is kept in its own file with its own rules.
//!
//! Three properties it must have, in order of how badly each would hurt:
//!
//! 1. **Nothing a sender can influence reaches this file.** It is local, the
//!    receiver's human writes it, and no command in ctx adds a line to it --
//!    see `ctx authority`, which only prints. A `ctx allow` subcommand would
//!    be a privilege escalation reachable by prompt injection: an agent that
//!    can be talked into running a command could be talked into granting
//!    itself the authority to obey the thing that talked it into it.
//!    The guard is partial and worth being honest about: it stops the obvious
//!    path, not the general one. Any agent with a shell and write access to
//!    the ctx home can append a line to this file directly -- as happened
//!    within the hour, when the grants used to run today's reviews were
//!    written by an agent rather than typed by the human. There is no local
//!    fix for that: a file the receiver's process can read, a process
//!    running as the receiver can write. What the missing subcommand does
//!    buy is that no *documented, reachable-by-asking* path exists, so an
//!    injected agent has to be told to write a file by hand, which is a
//!    conspicuous thing to find in a transcript.
//! 2. **A grant only ever follows a verified sender.** `lookup` refuses
//!    outright unless the verdict is `Trust::Known`. A grant on a key whose
//!    signature did not check out would be worse than no feature at all.
//! 3. **A malformed file grants nothing.** One unparsable line voids the
//!    whole file rather than the line, because the alternative is a typo in
//!    line 2 silently widening line 3 -- and the failure direction here is
//!    not symmetric. Too little authority asks a human a question; too much
//!    acts on a stranger's instruction.
//!
//! Deliberately absent in this first version: expiry. `docs/open-decisions.md`
//! worked out that expiry cannot use a clock -- for the same reason key
//! retirement cannot -- and "expires after N observed messages" is a strange
//! thing to ask a person to write. A file a human edits is already revocable
//! by editing it, so the feature waits for someone who actually wants it.

use crate::manifest::MsgType;
use std::fmt;

/// Who a grant is about. A key is exact; a name is resolved through your own
/// contacts, so it follows that contact across a rotation you accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Key(String),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub subject: Subject,
    /// `None` means the line said `any`, which has to be written out.
    pub msg_type: Option<MsgType>,
    /// Only applies to a message that answers something, so a grant cannot
    /// be used to open an unsolicited conversation.
    pub in_reply_only: bool,
    /// 1-based, so the frame can tell a reader exactly which line to go read.
    pub line: usize,
}

impl fmt::Display for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let who = match &self.subject {
            Subject::Key(k) => k.as_str(),
            Subject::Name(n) => n.as_str(),
        };
        write!(f, "allow {who} {}", self.msg_type.map_or("any", |t| t.label()))?;
        if self.in_reply_only {
            write!(f, " in-reply-only")?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Authority {
    pub grants: Vec<Grant>,
    /// The file is on disk. Distinct from having grants: "you have a file and
    /// nothing in it covers this" and "you have no file" are different
    /// things to tell a reader, and only the first means a human has thought
    /// about the question.
    pub present: bool,
    /// Why the file granted nothing, when it exists but failed to parse.
    pub error: Option<String>,
}

/// The reason a message got no grant. Carried rather than collapsed to a
/// bool so the frame can say something true in each case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// No authority file at all.
    NoFile,
    /// A file exists and nothing in it matches.
    NoMatch,
    /// A file exists and could not be read as grants.
    Unreadable,
    /// The sender is not `SENDER VERIFIED`, so no grant was even consulted.
    NotVerified,
}

pub fn path() -> std::path::PathBuf {
    crate::identity::home().join("authority")
}

impl Authority {
    pub fn load() -> Self {
        let Ok(text) = std::fs::read_to_string(path()) else {
            return Self::default();
        };
        match parse(&text) {
            Ok(grants) => Self { grants, present: true, error: None },
            Err(e) => Self { grants: Vec::new(), present: true, error: Some(e) },
        }
    }

    /// The grant covering this message, if any.
    ///
    /// `trust` is taken rather than recomputed so there is exactly one place
    /// the verdict is decided, and `contacts` is passed in for the same
    /// reason: this function must not be able to reach a different answer
    /// from the one printed two lines above it in the frame.
    pub fn lookup(
        &self,
        contacts: &crate::trust::Contacts,
        trust: crate::trust::Trust,
        key: &str,
        msg_type: MsgType,
        is_reply: bool,
    ) -> Result<&Grant, Denied> {
        // Property 2, and it comes first on purpose: no path through this
        // function reaches a grant without having passed this check.
        if trust != crate::trust::Trust::Known {
            return Err(Denied::NotVerified);
        }
        if let Some(_) = &self.error {
            return Err(Denied::Unreadable);
        }
        if !self.present {
            return Err(Denied::NoFile);
        }
        self.grants
            .iter()
            .find(|g| {
                let who = match &g.subject {
                    Subject::Key(k) => k == key,
                    // Resolved against the receiver's own contacts. A sender
                    // cannot put itself on that list.
                    Subject::Name(n) => contacts.name_for(key) == Some(n.as_str()),
                };
                let kind = g.msg_type.is_none_or(|t| t == msg_type);
                who && kind && (!g.in_reply_only || is_reply)
            })
            .ok_or(Denied::NoMatch)
    }
}

/// A key as `ctx whoami` prints it, versus a handle you chose. Keys are long
/// and base64; handles are short words. Guessing between them is only a
/// convenience, so the test is deliberately crude and the failure is benign:
/// a 20-character handle would be read as a key, match nothing, and grant
/// nothing.
fn looks_like_a_key(tok: &str) -> bool {
    tok.len() >= 20 && tok.chars().all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c))
}

pub fn parse(text: &str) -> Result<Vec<Grant>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let body = raw.split('#').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let mut tok = body.split_whitespace();
        let bad = |msg: &str| Err(format!("{}: line {line}: {msg}", path().display()));
        if tok.next() != Some("allow") {
            return bad("every line must start with `allow`");
        }
        let Some(who) = tok.next() else {
            return bad("`allow` needs a contact name or a key");
        };
        let Some(kind) = tok.next() else {
            return bad("`allow <who>` needs a message kind, or the word `any`");
        };
        let msg_type = if kind == "any" {
            None
        } else {
            match MsgType::parse(kind) {
                Some(t) => Some(t),
                // Not ignored. A grant for a kind that does not exist is
                // most likely a misremembered name for one that does, and
                // guessing which is not this function's business.
                None => return bad(&format!("unknown message kind `{kind}`")),
            }
        };
        let mut in_reply_only = false;
        for extra in tok {
            match extra {
                "in-reply-only" => in_reply_only = true,
                other => return bad(&format!("unknown modifier `{other}`")),
            }
        }
        out.push(Grant {
            subject: if looks_like_a_key(who) {
                Subject::Key(who.to_string())
            } else {
                Subject::Name(who.to_string())
            },
            msg_type,
            in_reply_only,
            line,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{Contacts, Trust};

    fn contacts() -> Contacts {
        let mut c = Contacts::default();
        c.keys.insert("CODEXKEY".into(), "codex".into());
        c.keys.insert("STRANGERKEY".into(), "mallory".into());
        c
    }

    fn authority(text: &str) -> Authority {
        Authority { grants: parse(text).expect("fixture parses"), present: true, error: None }
    }

    #[test]
    fn a_grant_covers_the_kind_and_the_key_it_names() {
        let a = authority("allow codex review-request\n");
        let c = contacts();
        assert!(a
            .lookup(&c, Trust::Known, "CODEXKEY", MsgType::ReviewRequest, false)
            .is_ok());
        // Same sender, different kind.
        assert_eq!(
            a.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Question, false),
            Err(Denied::NoMatch)
        );
        // Same kind, different sender.
        assert_eq!(
            a.lookup(&c, Trust::Known, "STRANGERKEY", MsgType::ReviewRequest, false),
            Err(Denied::NoMatch)
        );
    }

    #[test]
    fn no_verdict_short_of_verified_reaches_a_grant() {
        // The one that would hurt most to get wrong. A grant that followed an
        // unverifiable or rejected key would hand authority to whoever stole
        // or forged one, which is strictly worse than having no grants.
        let a = authority("allow codex any\n");
        let c = contacts();
        for t in [
            Trust::Unknown,
            Trust::Unverified,
            Trust::Retired,
            Trust::Revoked,
            Trust::Unwitnessed,
        ] {
            assert_eq!(
                a.lookup(&c, t, "CODEXKEY", MsgType::ReviewRequest, false),
                Err(Denied::NotVerified),
                "{t:?} reached a grant"
            );
        }
        assert!(a
            .lookup(&c, Trust::Known, "CODEXKEY", MsgType::ReviewRequest, false)
            .is_ok());
    }

    #[test]
    fn one_bad_line_voids_the_whole_file() {
        // Not just the line. A typo in one line must not change the meaning
        // of another, and the safe direction is to grant nothing.
        let text = "allow codex review-request\nallow codex reviewrequest\n";
        let e = parse(text).expect_err("second line is not a kind");
        assert!(e.contains("line 2"), "{e}");
        let a = Authority { grants: Vec::new(), present: true, error: Some(e) };
        assert_eq!(
            a.lookup(&contacts(), Trust::Known, "CODEXKEY", MsgType::ReviewRequest, false),
            Err(Denied::Unreadable)
        );
    }

    #[test]
    fn a_name_is_resolved_through_your_own_contacts_only() {
        // The sender writes a handle into its own manifest. If a grant could
        // be matched against that handle, anyone could claim to be codex.
        // So the name is looked up in the receiver's contacts, by key.
        let a = authority("allow codex any\n");
        let mut c = contacts();
        assert!(a.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Share, false).is_ok());
        // Rename the contact and the grant stops matching that key. The grant
        // follows your label, which is the thing you control.
        c.keys.insert("CODEXKEY".into(), "codex-old".into());
        assert_eq!(
            a.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Share, false),
            Err(Denied::NoMatch)
        );
    }

    #[test]
    fn in_reply_only_cannot_be_used_to_start_something() {
        let a = authority("allow codex question in-reply-only\n");
        let c = contacts();
        assert_eq!(
            a.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Question, false),
            Err(Denied::NoMatch)
        );
        assert!(a.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Question, true).is_ok());
    }

    #[test]
    fn an_absent_file_is_distinguishable_from_an_empty_one() {
        // Different things to tell a reader: one means nobody has considered
        // the question, the other means someone considered it and said no.
        let c = contacts();
        let missing = Authority::default();
        assert_eq!(
            missing.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Share, false),
            Err(Denied::NoFile)
        );
        let empty = authority("# nothing granted yet\n");
        assert_eq!(
            empty.lookup(&c, Trust::Known, "CODEXKEY", MsgType::Share, false),
            Err(Denied::NoMatch)
        );
    }

    #[test]
    fn a_key_is_accepted_in_place_of_a_name() {
        let a = authority("allow CODEXKEY0000000000000000 answer\n");
        let mut c = contacts();
        c.keys.insert("CODEXKEY0000000000000000".into(), "whatever".into());
        assert!(a
            .lookup(&c, Trust::Known, "CODEXKEY0000000000000000", MsgType::Answer, false)
            .is_ok());
    }

    #[test]
    fn comments_and_blank_lines_are_not_grants() {
        let g = parse("\n# allow mallory any\n  \nallow codex ack  # trailing\n").unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].line, 4);
        assert_eq!(g[0].msg_type, Some(MsgType::Ack));
    }

    #[test]
    fn a_line_that_is_not_a_grant_is_refused_rather_than_skipped() {
        for text in [
            "deny codex any\n",
            "allow\n",
            "allow codex\n",
            "allow codex any forever\n",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }
}
