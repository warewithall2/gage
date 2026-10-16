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

**Observed in the wild, 15 Oct.** Not a constructed case: sending the same
review-request to two reviewers one after the other produced two distinct
signed manifests -- different `to`, different signatures -- that share the id
`254c99c77115bfaf`, because they were built in the same second from the same
item and subject. It was harmless only because the two recipients have
separate ctx homes. One inbox holding both, or a relay keyed on the id, and
one would have suppressed the other. The two-messages-in-one-second condition
is not exotic; it is what a loop sending to a list does every time.

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

**Designed 15 Oct** by the grok reviewer, in
[nested-forward-design.md](nested-forward-design.md): exact prior bytes copied
to `prior/manifest.json` and `prior/manifest.sig`, hash-linked from the
signing hop, never re-serialised; verification walks the literal `prior/`
directory and fails closed at the step that checks the enclosed bytes against
the key those bytes name; two new labels so the author's unknown-ness does not
borrow the sender's trust line; bounded at 16 hops. Not built, and it should
land in the **same v2 cutover as decision 1** rather than as a second format
break. It also found that `seal` would silently flatten a nested bundle on a
relay round trip, which needs fixing either way.

## 4. The audit log and the policy engine

Both reviewers independently said the same thing about these: do not guess the
schema. Prismer's Signet has shipped a hash-chained receipt log and an
evidence-bundle export for handing records to an auditor
([prior-art.md](prior-art.md)); if this gets built, read that schema first
rather than inventing a third one. "Show me every instruction that crossed from this agent to that one
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

**Corrected 15 Oct.** "Until the command is re-run" was false, and the
reviewers caught it. After the first save the old key is gone from
`contacts.keys`, so a re-run found no live contact and exited with "you have
never accepted the old key" — leaving the contact retired at observation 0
permanently, with no command that fixed it. `keychange --accept` now detects
exactly that state, by the retired record's own `replaced_by` matching this
notice's destination, and resumes: it takes the real cut and installs the new
key. The choice above stands; the claim about it did not.

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

**Prior art, found 15 Oct.** Prismer's Signet already ships scoped delegation
tokens with narrowing-only permissions, TTLs and revocation — see
[prior-art.md](prior-art.md). Its grants authorise an *outbound tool call*,
checked by the server that executes it. The grant wanted here authorises
*acting on a received document*, and is read by the model rather than by an
admission check. Same primitive, opposite direction, and the wording problem
below is the part that does not transfer: nothing they publish has to be safe
against a payload arguing with it.

**Built 15 Oct**, as `src/authority.rs`, `~/.ctx/authority` and the
`authorised :` line in the frame. The decision was taken the conservative way
on every point that was open:

- No expiry. It cannot use a clock and the counter version is unwriteable by
  a human, so a file you edit is the revocation mechanism for now.
- No `in-thread-only`; `in-reply-only` instead, which is checkable from
  `in_reply_to` and cannot be used to open an unsolicited conversation.
- Grants are consulted only for `Trust::Known`, and only for message kinds
  that expect a reply.
- No subcommand writes a grant, for the injection reason above.
- One unparsable line voids the whole file.

The wording is the part still worth another pair of eyes: it is the only text
in ctx that tells an agent it may act, and over-reading it is precisely the
failure the tool exists to prevent. Sent for review rather than closed.

## 6a. Built 16 Oct: the hook that makes decision 6 live

`ctx watch --on-arrival <command>` is the first thing in ctx that acts on an
arrival with nobody watching, so it is the first place the grant model has a
consequence rather than a printed verdict. It fires only where
`Authority::lookup` already returns a grant, by the same call with the same
inputs the frame prints -- so a hook cannot run on an authority the reader
was not shown.

Three lines it does not cross, each because crossing it would have removed a
protection that exists elsewhere:

- it is not given the payload, because the accept gate is what holds contents
  back and a hook carrying them would have retired that gate for every
  granted arrival;
- it does not accept the bundle, so reading stays a separate recorded act;
- sender-chosen text reaches it only through the environment, flattened to
  one line, never interpolated into the command string.

What remains open in decision 6 is unchanged: the grant model itself is still
coarse (a key, a message kind, optionally in-reply-only) and has no expiry.
The hook makes that coarseness matter in practice, which is an argument for
settling 6 rather than a change to it.

## 7. The authority file has no real boundary

Raised by the codex reviewer, 15 October, reviewing decision 6 the day it was
built. The grant file is trusted exactly as far as the running agent cannot
modify it, and the running agent *can* modify it: any process that reads
`~/.ctx/authority` can write it. codex supplied the sequence -- a payload asks
the agent to append an `allow` line and reopen the request -- and it is not
hypothetical, because the grants used for that day's reviews were written by
an agent rather than typed by a human.

What is done: there is no `ctx allow` subcommand, so an injected agent has to
be told to hand-write a file, which is conspicuous in a transcript; `open`
tells the reader never to edit the file or add a grant because a message asked
it to; and the frame no longer claims the file is out of a sender's reach,
which it did for one morning.

All three are deterrents. None is an enforcement boundary, and codex said so
plainly: "If an agent can write the authority file, it can grant itself
authority... there is no wording-only fix."

**The options, none of them free:**

- **File permissions.** The agent runs as the same user, so this needs a
  second account or an ACL, and then `ctx open` -- running as the agent --
  must still read the file. Readable-not-writable by the agent's user is the
  shape. It makes ctx an install with a setup step, which it has never been.
- **A separate process the agent cannot write through.** A small daemon owning
  the grants, answering a socket, running as the human. This is the only
  option that actually enforces, and it is also the first server in a tool
  whose README says "no server".
- **Hardware or an out-of-band prompt.** Ask the human at grant time rather
  than trusting a file. Correct, and it breaks the unattended case the feature
  exists for.
- **Accept the deterrent and say so.** What is shipped. Honest, and it means
  the strongest claim ctx can make is that self-granting is visible, not that
  it is impossible.

Which one depends on whether the threat is an agent that has been injected
*and* has a shell. If it has a shell it can also read the inbox, send bundles
as this identity, and copy the signing key -- so a boundary around the grant
file alone may be guarding the smallest door in an open wall. That argument
cuts both ways and is exactly why it is the owner's call.

**Not built. Needs the owner.**

## 8. LAN discovery, and whether ctx announces itself

Asked for 15 Oct: make the second machine feel like LocalSend. Designed in
[lan-discovery-design.md](lan-discovery-design.md).

Most of it is uncontroversial -- the accept gate already is LocalSend's accept
prompt, and a LAN listener is the same small hand-rolled HTTP as the viewer
and the relay. Two things are not:

- **Discovery must not become identity.** LocalSend identifies a peer by a
  self-chosen device name, which anyone on the network can claim. That is
  fine for one expected file and not fine for instructions an agent may act
  on later under a grant. So discovery answers *where a key is reachable* and
  a one-time fingerprint pairing answers *whose key it is*. The pairing step
  is the difference and cannot be optimised away.
- **Announcing is presence, which this tool has deliberately never had.** The
  README says "no server, no presence, no accounts". Broadcasting a handle and
  a public key on every network the laptop joins is a real change to what
  leaves the machine, and the owner should decide it rather than find it in a
  changelog. Default off, explicit flag, and say plainly what is sent.

**Built 15 Oct**, as `src/lan.rs`, with the presence question answered the
narrow way: no standing announcement in any mode, `--announce` time-boxed and
off by default, the full list of what is broadcast printed before anything is
broadcast, and -- the part that does the work -- address resolution by a
*signed query* that is answered only when the asker's key is already on the
list. A stranger gets silence they cannot tell from an empty network, so
being reachable stopped requiring being visible.

**Reshaped 16 Oct**, on the owner's verdict that it was too much work, which
it was: the second machine took eleven steps and nine of them were the tool's
fault. `ctx lan` is now one foreground command that announces, discovers,
listens and receives; presence is bounded by the process rather than by a
flag, which is LocalSend's own answer and a clearer one. An identity names
itself from its own key when no name is given, and pairing became an upgrade
rather than a precondition -- an unpaired machine can send, and what arrives
is `SENDER NOT ON YOUR LIST` behind the accept gate that was always the
protection. The fingerprint argument survives where it belongs: as what a
*grant* should require before an agent acts unattended, not as a toll on
moving one file.

Two things remain the owner's, and both are smaller than the decision was:

- **`ctx listen` is a process holding a port**, which is the first thing in
  ctx that is true of. Its TCP side accepts a sealed envelope from anyone who
  reaches it, deliberately -- a first bundle from a new contact has to be able
  to arrive -- and that bundle lands unread in `pending/` under `SENDER NOT ON
  YOUR LIST`. The protection is the accept gate, not the port. Whether to
  narrow it to known senders is a real choice, and it costs the first contact.
- **A query reveals that somebody holding this key is looking for someone**,
  to anyone sniffing the segment at that moment. The key being sought is
  hashed with the query nonce so the pair of you is not on the wire, but the
  asker's key is in the clear because the signature is what makes answering
  safe at all. Hiding it needs a shared secret per contact, which is a
  different design.
