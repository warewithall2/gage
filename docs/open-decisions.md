# Decisions waiting on the owner

Things found or designed that should not be changed unilaterally, with what
each one costs.

## 1. The bundle id does not cover every field

`Manifest::expected_id()` hashes item digests, author key, subject and
`created`. It does **not** cover `msg_type`, `thread`, `in_reply_to`, `to`, or
item kinds and paths. Those are all protected by the signature, so they cannot
be altered — but two manifests from the same author that differ only in those
fields share an id.

What that buys an attacker is suppression rather than forgery: read state,
announce-once, thread dedup and the `pending/` directory name are keyed on the
id, so one of the pair can hide the other. It requires the same author, two
messages in the same second, and identical digests and subject.

Closing it means changing the id formula, which invalidates the id of every
bundle already on disk — they would all read as tampered. So it needs either a
`FORMAT_VERSION` bump with the old formula grandfathered (and an attacker can
then choose the old version), or an accepted one-time break. **Format
decision, so it waits.** Found by the codex reviewer, round 3.

## 2. The offline root

See [offline-root.md](offline-root.md). Designed, not built. It changes what a
person must keep for the life of an identity, so it is a decision rather than
a patch. Its own designer says build the audit log first.

## 3. The audit log and the policy engine

Both reviewers independently said the same thing about these: do not guess the
schema. "Show me every instruction that crossed from this agent to that one
last quarter, with authorship and whether it was accepted" is the question an
enterprise buyer actually asks, and the right shape for the answer comes from
one design partner rather than from an implementer at 1am.

## 4. The crash gap between the cut and the contact write

`keychange --accept` and `retire` now write the retirement **first**, with a
cut of 0 that places nothing below it, then take the real cut and relax to it.
A crash in between leaves the key retired and over-strict: every bundle from
it reads as rejected or unrecorded until the command is re-run. That is the
safe direction, and the alternative — one journalled transaction across
`contacts.json` and `state.json` — is more machinery than the failure
justifies. Recorded so the choice is visible rather than accidental.
