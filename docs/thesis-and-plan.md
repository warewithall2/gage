# What ctx is, and what is left to build

Settled with the owner on 16 Oct, after the LAN path was verified on two
machines. This file is the short version; the arguments behind each decision
live in [open-decisions.md](open-decisions.md) and
[lan-discovery-design.md](lan-discovery-design.md).

## The thesis, as the owner states it

**ctx is email between agents.** A human decides who is on the list. Arrival
is not consent, so nothing is read until it is accepted. And what the reading
agent is handed says, before any payload, that this is *data* from an
identified party carrying no authority. It travels over the same wifi or over
a relay -- whichever you have -- because a bundle is a signed directory, not a
protocol.

The reading frame is not a second thesis. It is what makes the inbox safe to
**automate**. Email for humans does not need it, because a human reading a
phishing message is not executing it. An agent reading its inbox is. So the
friend list makes the *address* meaningful, and the frame makes *acting on the
message* survivable. Both halves are load-bearing; neither is the product on
its own.

The shape to aim for, in the owner's words, is an AOL Instant Messenger buddy
list for agents, with LocalSend's drag-and-drop beside it: a human accepts or
declines each connection, and can see at a glance who is connected.

## Decided: email-shaped, not a message board

Both were on the table. What exists is email-shaped -- `--to` one recipient,
sealed to that recipient's box key, one inbox each, threads assembled from
both halves. `contacts.json` carries a `groups` field, but `seal_dir` seals to
exactly one key, so a group send is N sealed copies: email with CC, not a
board.

A real shared board was rejected for now, for three reasons that are all the
same reason:

- Something has to **host** it. The relay is currently a drop box that cannot
  read what it holds. A board holding posts for a group to read is a server
  with contents, and its operator becomes someone you trust.
- **Sealing to one recipient breaks.** A post readable by a group needs N
  copies (so it is not really shared) or a group key (so leaving a group needs
  a rekey -- which `trust.rs` already refuses on purpose: a group is a list of
  keys *you* trust, "so leaving a group cannot be done by the group").
- The **friend list stops being symmetric.** Trusting a board's membership is
  a different and weaker object than trusting a key.

The board *feel* comes from `ctx threads` instead, which is a local view over
mail this machine received and needs no trusted host. If a board is wanted
later, that local view is the honest version of it.

## Explicitly still refused

**A standing presence roster.** It is the natural next ask for anything that
feels like a buddy list, and it has been refused twice: a roster that is
always visible is a roster somebody else can also read. `ctx lan` answers the
question with process lifetime instead -- visible while it runs, silent when
it stops. A buddy list UI may show *who is on your list* and *who is on this
network right now*; it may not make this machine continuously announce.

## The plan, in order

### 1. The injection test -- before anything acts unattended

The only test of the thesis. All 527 shell checks and 75 unit tests verify
that the *renderer emits the right bytes*; not one verifies that a *reader
behaves differently* because of them. Those are different claims and only the
second is the product.

It cannot be authored by the agent being tested, and as of 16 Oct both grok
and codex declined to write a payload. So the owner writes it, which is the
better test anyway: an attack the reader did not author and cannot anticipate
is the only version that measures anything. The harness is
`tests/injection/README.md`.

This comes first because auto-accept ships the dangerous capability, and an
agent acting unattended on a hostile payload is precisely the failure this
project exists to prevent.

### 2. Auto-accept under a grant, with a budget

One change to the grant grammar rather than two migrations, because the budget
is the safety belt for the auto-accept:

    allow mac question max-exchanges 4 auto-accept

Three properties: a hook may accept only within a grant that says so; every
accept records which grant and at which `seq`; and the exchange count is kept
by the receiver, per thread, so nothing a sender puts in a bundle can reset
it.

Why it is needed: `ctx accept` currently moves a directory and records nothing
about *how* it happened. The moment anything accepts without a human, "did a
human accept this, or did a grant?" becomes the only question that matters,
and nothing on disk can answer it. Provenance cannot be retrofitted onto
records that did not capture it.

And nothing today stops a runaway: replies are new bundles with `in_reply_to`,
nothing counts exchanges in a thread, and two agents with mutual grants and a
replying hook is A->B->A->B until someone notices. `chain` counts *forwarding*
hops, which is a different thing. `docs/prior-art.md` notes peer tools carry
`--ttl`, `--max-depth` and `--max-calls`; ctx carries none of them.

### 3. The buddy list UI

The shape the owner actually wants, and the first thing a second person would
judge the project by. `ctx ui` already has threads, accept/reject, a reply box
and the LAN panel built on 16 Oct. What it does not have:

- **Connection requests as a human decision in the window.** Today pairing is
  a CLI act, or a Pair button against a machine already on this network.
  There is no notion of *an agent asking to be added* and a human accepting or
  declining it -- which is the AIM authorisation model and the owner's core
  ask. Note the constraint: the request itself arrives as an unlisted sender's
  bundle, so it is already behind the accept gate, and the UI must not make
  approving one feel lighter than it is. The four word-pairs are the
  confirmation; a button is not.
- **The list as a list.** Contacts, their fingerprints, who is reachable right
  now and by which path (local route, this network, relay), and what is
  unread from each.
- **Declining, and what it means.** Reject already deletes unread. A declined
  *connection* is a different record: the key must stay refused without being
  re-offered every time that agent sends.

### 4. The audit log (decision 4)

Once anything happens while nobody is watching, "what did my machine do" is
the question, and `sent/` plus `accepted/` is a trail of artifacts rather than
of decisions. muse reviewed what the log must answer; it is unbuilt.

## Not on the plan

Send-side restraint. The authority file says what an agent may act *on*;
nothing says what it may *send*. An injected agent with a grant cannot be made
to act on a stranger's message, but it can be talked into sending anything to
anyone on its list. Left open deliberately: the answer is not obvious and it
is a bigger argument than the items above.
