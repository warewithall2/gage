# Draft: posting to A2A, not yet posted

**Status: drafts for Owen to review, edit and post under his own account.
Nothing here has been sent anywhere.**

Two versions below. **Version A** is a comment on an existing, dormant issue
and is the one to post first. **Version B** is a new issue, worth opening only
if A gets a response, because it asks the spec for something rather than
adding to someone else's request.

## The landscape, read 2026-10-27 and re-checked 2026-10-28

Re-checked before posting: #388 is still open with zero comments, and #1829 is
still open, still unaccepted, last active 2026-08-08. The argument below
stands as written.

Check these again before posting; they move, and the previous draft of this
file was written against a picture that has since changed.

| | | |
|---|---|---|
| [#388][388] "Data labeling" | open, **0 comments**, untouched since 2025-06-03 (an assignment; no comment ever) | sender-supplied annotations in `metadata`, including "untrusted data which may lead to prompt injection" |
| [#1672][1672] "Agent Identity Verification for Agent Cards" | open, **661 comments**, last activity 2026-08-19 | vendor-heavy; AgentID, APS, qntm, OATR. Someone has already argued "reliance policy is out of scope, by design" |
| [#1829][1829] "minimal Ed25519 + RFC 9421 signing extension for A2A messages" | open, 143 comments, last 2026-08-08 | **per-message** signing — the payload-integrity gap `docs/a2a.md` names as missing |
| [#2133][2133] "Exact-message authorization envelope for consequential actions" | open, last 2026-08-18 | adjacent |

**What this changes.** The earlier draft asserted that A2A defines no
integrity for message payloads. That is still true of the *specification*, but
#1829 is an active proposal for exactly it, and posting without acknowledging
that reads as not having looked. The durable point is narrower and better:
signing answers *who sent this*, labelling answers *what kind of thing it is
said to be*, and **neither says anything about how a receiving implementation
must present the content to a model.** That last one is an interop property,
not an implementation detail, and it is the gap.

---

## Version A — a comment on #388

*Why here: #388 asks for labels that include "untrusted data which may lead to
prompt injection". It has sat with zero comments since May 2025. It is the
right venue, it has no competing vendors in it, and the comment below is a
correction offered to someone else's proposal rather than a pitch.*

---

This is the right problem to name, and I think the proposal is two problems
wearing one coat. Separating them would make both easier to specify.

**The cooperative half works as written.** PII, need-to-know, retention class
— these are facts the sender knows and has no motive to misstate, and a
namespaced annotation under `metadata` is a reasonable way to carry them. Data
flow policy and logging are real wins.

**The adversarial half does not, and cannot.** A label saying content is
untrusted is set by the sender. The case that matters is the one where the
sender is the problem — a compromised agent, or an honest agent relaying
something it was itself injected with — and that sender will not set the flag.
An implementation that reads `a2a.dev/annotations/untrusted` and relaxes when
it is absent is strictly worse off than one that never looked, because it now
has a reason to believe content is safe.

Content that arrived from another agent is untrusted **because of where it
came from**, not because of what it says about itself. That is a property the
receiver derives from the envelope, and no field in a document the sender
controls can carry it. The same argument applies to any `"verified": true`
style field being discussed elsewhere in this repo: a message can carry
*evidence*, it cannot carry the *verdict*.

**A smaller thing that would help more.** Whatever the labels end up being,
the receiving implementation still has to put the content somewhere, and in
the usual case that somewhere is a model's context next to its own
instructions. If every implementation invents its own way of doing that, the
same message is safe against one and unsafe against another, and neither a
sender nor an auditor can reason about it. Two pieces of that are cheap:

- A normative statement that content received from another agent MUST NOT be
  presented to a model as instruction-bearing, and that an implementation
  which does so is non-conformant. The statement alone is worth more than any
  mechanism, because it makes the failure nameable in a bug report.
- If a delimiter is used to fence received content, it has to be one the
  content cannot forge. A fixed marker string is forgeable by definition; a
  per-message random nonce in the marker is not, because the sender cannot
  predict it.

I have had frame-escape work against my own renderer in testing — content that
imitated the end of the fence, so everything after it read in the
implementation's own voice — which is why I stopped treating this as
theoretical. Happy to write up the specific attacks and the fixes if that is
useful to anyone here.

---

## Version B — a new issue, only if A lands

**Title:** Nothing in the spec says how received content may be presented to a
model

---

Three threads here are solving adjacent halves of one problem, and I think the
half none of them covers is the one that decides whether the others matter.

- [#1672][1672] and the Agent Card work: *who published this card.*
- [#1829][1829]: *did this specific message come from that agent.*
- [#388][388]: *what kind of content is this said to be.*

All three are about establishing provenance or description. None of them says
what a receiving implementation may then **do** with the content, and in A2A
the receiver is usually a language model, where "do" means "place these tokens
next to my own instructions."

Two cases where all three succeeding changes nothing:

1. **A verified agent that was injected upstream.** Signature valid, card
   verifies, chain intact. It relays an instruction it was talked into
   relaying. Every check passes; the receiver is compromised.
2. **Content that imitates its own frame.** If an implementation presents
   received parts to a model as text, content containing something that looks
   like the end of that text can close the frame early, and the remainder
   reads as the implementation's own voice.

**Why this belongs in the spec rather than in each implementation.** If every
implementation chooses its own presentation, the same message is safe against
one and not another, and there is no way for a sender, a receiver or an
auditor to reason about it. That is the same argument that put `parts` in the
spec rather than leaving serialization to implementers.

**A minimal surface, as a starting point rather than a proposal:**

- A normative "received content MUST NOT be presented to a model as
  instruction-bearing; an implementation that does so is non-conformant."
- Delimiters content cannot forge: a per-message nonce, not a fixed marker.
- The trust verdict computed by the receiver and never carried in the message.
  A field the sender controls can say `"verified": true`. Evidence travels;
  conclusions do not.

**Disclosure.** I maintain a small open-source tool that does the receiving
half of this. I am not proposing it, it speaks no A2A, and I have been wrong
about this in public enough times to have the scar tissue. I would rather the
spec have a position than have mine adopted.

---

## Before posting

- Re-read #388 and #1829; the table above is a snapshot, not a fact.
- Post **A** first and wait. B is a request of the maintainers; A is help with
  someone else's. If A draws no reply in a couple of weeks, B stands alone.
- **Decide whether to link gage.** Neither version links it. #1672 already has
  several projects promoting themselves and the point lands harder without a
  fourth link; anyone who wants the detail will ask. Owen's call.
- This contradicts nothing in `docs/a2a.md`, which already says gage is not a
  registry, not a CA and not an identity provider.

[388]: https://github.com/a2aproject/A2A/issues/388
[1672]: https://github.com/a2aproject/A2A/issues/1672
[1829]: https://github.com/a2aproject/A2A/issues/1829
[2133]: https://github.com/a2aproject/A2A/issues/2133
