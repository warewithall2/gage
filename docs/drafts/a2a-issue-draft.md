# Draft: an A2A issue, not yet posted

**Status: draft for Owen to review, edit and post under his own account.
Nothing here has been sent anywhere.**

## Why a new issue rather than a comment on #1672

[#1672 "Agent Identity Verification for Agent Cards"][1672] is open, but it is
not the neutral design thread a secondary source suggested. It is a vendor
proposal — AgentID (`getagentid.dev`), a centralized CA with a verification
endpoint — and its comment thread is three vendors converging on a pluggable
scheme: AgentID, `corpollc/qntm`, and `aeoess/agent-passport`. No A2A
maintainer appears in it. A comment from a fourth project would read as a
fourth pitch, and the point below is orthogonal to what they are arguing
about rather than a contribution to it.

(The "Agent Registry, issue #741" I was told about does not exist — that
number 404s. Check any issue number before citing it.)

## The draft

**Title:** Identity verification establishes who sent a message, not what the
receiver may do with it

---

The identity work in #1672 and the threads around it addresses a real gap:
today the Agent Card relies on transport-layer trust, and a receiving agent
has no protocol-level way to verify who it is talking to.

I want to name a second gap that is orthogonal to it, because I think it is
being assumed away rather than solved, and because it is the one that does
not get easier once identity verification lands.

**Verifying the sender does not make the content safe to read.**

A2A's receiving agent is, in the usual case, a language model. The content it
receives becomes tokens in its context, adjacent to its own instructions.
Authentication tells you a message's provenance. It tells you nothing about
whether acting on the content is safe, and the two are routinely conflated
because in human systems they are nearly the same thing — a signed letter
from a colleague is usually also a safe letter.

Two concrete cases where perfect identity verification changes nothing:

1. **A verified agent that has itself been injected upstream.** It signs
   correctly, its card verifies, its certificate chains. It relays an
   instruction it was talked into relaying. Every identity check passes and
   the receiver is compromised.
2. **Content that imitates the frame around it.** If a receiving
   implementation presents a received message to its model as text, then
   message content containing something that looks like the end of that text
   — a delimiter, a system-style line, a forged verdict — can close the frame
   early, and everything after it reads as the implementation's own voice. I
   have had this work in testing against my own renderer, which is why I
   stopped treating it as theoretical.

**Why this belongs in the spec rather than in each implementation.**

If every A2A implementation invents its own way of presenting received parts
to a model, then the same message is safe against one and not another, and
there is no way for a sender or an auditor to reason about it. Interop needs
agreement on how received content is delimited and labelled, not only on how
the sender is identified. That is the same argument that put message `parts`
in the spec rather than leaving serialization to implementers.

**A minimal surface, offered as a starting point rather than a proposal:**

- A normative statement that content received from another agent MUST NOT be
  presented to a model as instruction-bearing, and that an implementation
  which does so is non-conformant. This alone would be worth more than any
  mechanism, because it makes the failure nameable.
- Delimiters that content cannot forge. A fixed marker string is forgeable by
  definition; a per-message random nonce in the marker is not, since the
  sender cannot predict it.
- **The identity verdict computed by the receiver, never carried in the
  message.** This is a direct comment on the `verifiedIdentity` field shape
  in #1672: a field in a document the sender controls can say anything it
  likes, including `"verified": true`. Whatever the mechanism, the conclusion
  has to be derived by the receiver from the signature and its own policy, or
  the field is decorative. A card can carry the *evidence*; it cannot carry
  the *verdict*.

**Disclosure and what I am not asking for.** I maintain a small open-source
tool that does the receiving half of this, so I have been wrong about it in
public a few times and have the scar tissue to show for it. I am not
proposing it as the answer and it speaks no A2A. I would rather the spec have
a position on this than have my implementation's position adopted. If it is
useful I am happy to write up the specific attacks that worked against my own
frame and what the fixes were.

[1672]: https://github.com/a2aproject/A2A/issues/1672

---

## Before posting

- Read the current state of #1672; it moves.
- Decide whether to link gage at all. The draft deliberately does not link it:
  the thread already has three projects promoting themselves, and the point
  lands harder without a fourth link in it. A maintainer who wants the detail
  will ask.
- This contradicts nothing in `docs/a2a.md`, which already says gage is not a
  registry, not a CA and not an identity provider. It is the same position,
  said where the spec is being written.
