# gage and A2A

How gage maps onto Google's **Agent2Agent (A2A)** protocol.

> **Status: design position, not code.** Nothing in gage speaks A2A today.
> There is no A2A client, no server, no Agent Card, no JSON-RPC. This document
> exists so that the question "is this a competitor to A2A?" has a written
> answer, and so that an implementation, if one happens, starts from a position
> rather than from an afternoon's improvisation.
>
> A2A is also moving. Where this document describes A2A's shape it is
> describing it as of late 2026 and at the level of its concepts — Agent Cards,
> the task lifecycle, messages made of parts, artifacts as task output. Check
> specifics against the current specification before writing code against any
> of it.

## The short answer

**They are not the same kind of thing, and gage is not trying to be A2A.**

A2A answers *how two agents talk*: discovery, a task lifecycle, a message
shape, a transport. gage answers *what the receiving agent is told about a
message before it decides what to do with it* — who signed it, whether the
receiver has ever confirmed that key, and that nothing inside carries
authority.

An agent can speak A2A perfectly and still have no answer to "should I act on
this?" That gap is the whole of gage.

So the honest framing is **complementary, at different layers**: A2A is a
protocol; a gage bundle is a signed artifact that could travel over it.

## What gage deliberately does not try to be

Worth stating first, because most of the confusion lives here.

- **Not a transport.** gage has no opinion about how a bundle reaches you. A
  bundle is a directory; it moves over a shared folder, git, email, a USB
  stick, a LAN handoff or the relay. "Not a protocol" is the reason it works
  across vendors at all. If A2A is the transport, good — that is one more way a
  bundle can move.
- **Not a registry or a discovery mechanism.** gage has no directory of agents,
  no capability advertisement, no `/.well-known/` anything. Its buddy list is
  deliberately local, small, and populated by a human act. A2A's Agent Cards
  are discovery, which gage has no story for and wants none.
- **Not an identity provider or a CA.** No issuance, no attestation, no
  revocation service. A fingerprint binds a key to a human *you already know by
  other means*, confirmed out of band.
- **Not an authorization server.** gage's authority file is a local file the
  receiver's human writes, read only after the signature verifies. It grants
  nothing to anyone else and publishes nothing.
- **Not a replacement for transport security.** TLS does what TLS does. gage's
  signature survives the hop; it does not replace the channel.

## Where a gage bundle would ride

The natural fit is **A2A's artifact**, not its message.

A gage bundle is a self-contained, signed, content-addressed directory. That is
much closer to "the output of a task, which can be stored and passed on" than
to "a turn in a conversation". Concretely, a bundle could ride as an artifact
whose parts are its files, with the manifest and detached signature carried
alongside as parts of their own — because the signature covers the exact bytes
of `manifest.json`, and anything that re-serialises the manifest breaks it. A
transport that pretty-prints JSON on the way through would invalidate every
signature it touched, so the manifest has to travel as opaque bytes.

A bundle could also ride as a **message** with the same structure — gage has a
`kind` on every bundle (`share`, `question`, `answer`, `review-request`, `ack`)
which lines up readably with a request/response exchange. Either way the
important property is the same: the bundle is signed end to end and the
transport is not trusted to vouch for it.

## Where the trust model sits relative to A2A

This is the part that matters, and the part where the two models genuinely
differ rather than merely sitting at different layers.

### Agent Cards describe a service; word-pairs confirm a person

An Agent Card tells you what an agent can do and where to reach it. It is
discovery metadata, served by the agent about itself.

gage's ceremony is the opposite shape. Two humans read four word-pairs to each
other over a channel neither machine controls, and the pairs are *derived from
the key* so nobody can choose their own. What that binds is "the key my machine
holds under this name is the key your machine holds" — a statement no card can
make about itself, because **a key knows its own word-pairs and can quote
them**. Anything a party serves about itself is a claim; the ceremony is
specifically a check that does not route through the party being checked.

So: an Agent Card could usefully *carry* a gage public key, the way it carries
other metadata. It could not replace the confirmation step, and a gage
implementation that trusted a key because it arrived in a card would have
thrown away the only thing gage does.

### Receiver-computed trust versus transport authentication

A2A, like most protocols, authenticates at the transport and at the service
boundary: you know which endpoint you are talking to.

gage computes trust **at the point of reading**, from the signature plus the
receiver's own allowlist plus the receiver's own record of having seen those
bytes. There is no `trust` field in the manifest, because a `"trust":
"verified"` key in a document the sender controls is decorative.

These compose well and the composition is worth being precise about: transport
auth tells you *who handed this to you on this hop*; the gage signature tells
you *who wrote it*, and survives an arbitrary number of hops, stores and
forwards in between. A task that passed through three agents and a queue has a
transport identity for the last leg only. That is exactly the case gage's
forwarding rules are about — only the last hop signs, so `chain[0]` is rendered
as a *claim by the forwarder*, never as a fact, even when the key it names is
one you know.

### Task lifecycle versus the accept gate

A2A's lifecycle is about *work*: submitted, working, input-required, done,
failed. It describes the progress of a task.

gage's gate is about *consent*, and it sits before any of that. Arrival is not
consent: a bundle lands unread in `inbox/pending` and crossing into `accepted`
is an act a human performs — or an explicitly-flagged unattended process, with
a per-thread budget counted in the journal and keyed on a parent the receiver
itself sent.

Mapping these naively would be the main way to get an integration wrong. "The
task arrived and is now `working`" is a statement about a workflow. It must not
become "the bundle is accepted", because acceptance is the human's decision and
the whole point is that a sender cannot make it. An A2A-shaped gage would need
the gate to remain visible as its own step, which is awkward in a protocol
whose states are about progress — and that awkwardness is the design tension to
solve rather than paper over.

### Scoped authority versus capability negotiation

A capability advertisement says what an agent *can* do. gage's authority file
says what the receiver's human has decided an agent *may* do on their behalf,
for a specific kind of message from a specific key, with the scope fixed by the
message kind rather than by anything the message says.

Those are different sentences and should not be conflated. A2A could carry a
`review-request`; only the receiver's own local file can say that acting on one
from that key is permitted.

## What an implementation would have to get right

If this is ever built, these are the places it would go wrong first:

1. **The manifest must travel as opaque bytes.** Re-serialising it breaks every
   signature. Base64 or an untouched file part, never a JSON object the
   transport is free to normalise.
2. **The accept gate must survive.** Mapping "task received" to "bundle
   accepted" would quietly delete gage's central property.
3. **A key in an Agent Card is a claim, not a confirmation.** It can seed a
   pairing; it cannot complete one.
4. **Transport identity must not be allowed to overwrite the computed verdict.**
   If the two disagree, the signature wins and the disagreement is worth
   showing.
5. **The frame still has to be rendered.** The value is not that the bundle was
   signed; it is that the reading agent was *told* what it was holding, before
   the payload, in a frame the payload cannot forge. An integration that
   verifies a signature and then hands the payload over raw has implemented the
   easy half and dropped the half that matters.

## Why this is a position and not a plan

gage has one user, one release and no second implementation. Writing an A2A
binding now would mean guessing at a moving specification in order to
interoperate with agents nobody has asked to interoperate with, while the
actually-unproven claim — that a receiving agent behaves better when it is told
what it is holding — has been tested on four agents in one dogfood session.

That claim is the thing to prove. The protocol binding is cheap afterwards and
worthless before.

See also: [spec.md](spec.md) for what is really on the wire, and
[threat-model.md](threat-model.md) for what gage does not protect against.
