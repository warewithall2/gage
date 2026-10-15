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

## 3. Per-hop signatures on a forwarded bundle

Only the LAST hop signs a bundle. `chain[0]` names the author, and a forwarder
writes that field, so a forwarder can name anyone -- including a key the
recipient trusts most -- attach a payload they wrote themselves, and sign it
as an ordinary forward. The muse reviewer found this.

What is fixed: `forward` now refuses to re-sign a bundle that does not verify,
revalidates item paths before copying (an absolute path there truncated the
forwarder's own identity key), and `open` no longer prints a forwarded
author's local name as though it were established -- it says plainly that only
the last hop signed and that the author is text the forwarder chose.

What is not fixed: there is no cryptographic provenance across hops. Doing it
properly means each hop signing what it received, which means carrying the
original signed manifest inside the forward rather than editing one manifest
along the way -- a nested envelope, like forwarding an email with the original
attached. That is a format change and a real design task, not a patch.

Until then the honest position is the one `open` now states: judge a forwarded
bundle on its sender, who signed it, and treat the author as a claim.

## 4. The audit log and the policy engine

Both reviewers independently said the same thing about these: do not guess the
schema. "Show me every instruction that crossed from this agent to that one
last quarter, with authorship and whether it was accepted" is the question an
enterprise buyer actually asks, and the right shape for the answer comes from
one design partner rather than from an implementer at 1am.

## 5. The crash gap between the cut and the contact write

`keychange --accept` and `retire` now write the retirement **first**, with a
cut of 0 that places nothing below it, then take the real cut and relax to it.
A crash in between leaves the key retired and over-strict: every bundle from
it reads as rejected or unrecorded until the command is re-run. That is the
safe direction, and the alternative — one journalled transaction across
`contacts.json` and `state.json` — is more machinery than the failure
justifies. Recorded so the choice is visible rather than accidental.

## 6. Receiver-side delegation: who may act on a request

Found by dogfooding the tool with the full ensemble on 15 October, written up
in [dogfood-2026-10-15.md](dogfood-2026-10-15.md). The short version: a
bundle cannot authorise its own fulfilment. Two of three agents read a signed
`review-request` from a verified contact, understood it, and declined to act,
because `ctx open` tells them the contents carry no authority. They were
right to. The third acted only because its out-of-band prompt said to.

So ctx can prove who wrote a request and cannot say whether it may be
carried out. Something else always has to, and today that something is a
human pasting a prompt — which is the gap between a verified message and
useful work, and signing does not close it.

`open` now at least states the kind of message and says plainly that
authority has to come from the receiver's own user. That is description, not
policy, and it is as far as this can go without a decision.

**The proposal.** Authority computed by the receiver from its own list,
exactly as trust already is. A local file the receiver's human writes, never
anything a sender can influence:

    allow <key> <msg_type> [in-thread-only] [expires <when>]

`ctx open` would then print, for a request that matches, that the receiver's
user has pre-authorised requests of this type from this key — and for one
that does not, what it prints today.

**Why it is a decision and not a patch:**

- It is the first thing in ctx that tells an agent it *may* act. Every other
  verdict is a statement about what is known. Getting the wording wrong here
  is worse than having no feature, because an agent that over-reads a grant
  is precisely the failure the tool exists to prevent.
- Expiry needs the observation counter, not a clock, for the same reason
  retirement does — and "expires after N observed messages" is a strange
  thing to ask a person to write.
- It overlaps the "not for" policy already on the roadmap, which runs on the
  *sending* side. One mechanism or two is an architecture choice.
- ASI07 names allowlisted delegation paths as a required mitigation, so this
  is also the item that makes the standards argument honest.

Not built. Needs the owner.
