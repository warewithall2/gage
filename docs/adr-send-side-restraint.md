# ADR: restraint on the sending side

**Status: decided 22 Oct. Owner answered all three questions.**

1. **The MCP pairing flow stays end-to-end.** The contact list remains
   agent-writable, knowingly.
2. **Build the send journal.** Detection is accepted where prevention is not
   available locally.
3. **Keep refusing to overclaim.** No rate ceiling for the README.

The consequence of (1) is the important one and is stated here rather than
left to be rediscovered: **no recipient-side restraint will be built, because
none of them can mean anything.** An allowlist, a first-contact gate or a
"confirmed contacts only" rule is enforced against `trust::Contacts`, and an
agent can write that file itself in two tool calls. Shipping one would be
security theatre, and this project's whole claim is that it does not do that.
What the send journal buys is therefore the honest thing and the only thing:
**what left is answerable afterwards.** Nothing here stops it leaving.

Written because the gap was named in conversation as the largest one left, and
because the first thing an ADR should do is find out whether the gap is the
shape people assume.

It is not. The outbound path already refuses things. What it does not have is
any notion of *who* or *how much* — and underneath that sits a structural
problem that no amount of outbound policy fixes.

## What already exists, so that the gap is stated honestly

`outbound::send_bundle` is the single send path — the CLI, the viewer and
`gage mcp` all call it, deliberately, so that a second path cannot grow its
own weaker copy of these. Before a bundle is built it:

- **skips files whose names look like secrets** (`.env` and the rest of the
  deny list), and says which;
- **skips symlinks**, because a link's name says nothing about its target;
- **skips items over the per-item size limit**, and build/cache directories;
- **scans the contents** with `scrub::scan` and **refuses** — not warns — if
  anything matches. A warning on an outbound path arrives after the bundle
  exists, and for a remote recipient after it has gone.

And the MCP surface hardcodes `allow_secrets: false` and
`allow_findings: false`, so **an agent cannot override the scan**. A finding
is a reason for a human to go and look at the file, not a flag an agent can
set to make a refusal go away.

So "nothing governs what an agent sends" is false, and an ADR that opened
that way would be arguing against a straw man. Content restraint exists and
is fail-closed.

## The gap, stated exactly

Three things are unrestrained, and one of them is load-bearing.

**1. Recipient.** Nothing limits *who* a bundle goes to. Any contact on the
list, any number of them, no distinction between one you confirmed in person
last year and one added this morning. An agent that has been persuaded by
text it read can send your work to a legitimate, confirmed contact — which no
content scan will ever flag, because nothing about the bundle is wrong except
the intent behind it.

**2. Volume and rate.** Nothing limits how many bundles leave, or how fast. A
loop is a loop.

**3. Prose.** `scrub::scan` catches secret-*shaped* text: tokens, keys,
credentials, things with a grammar. It does not catch a design document, a
customer conversation, a salary figure in a sentence, or the whole source
tree. These are the things that actually hurt when they leave, and they are
unrestrained because they are indistinguishable, byte for byte, from the
material gage exists to carry. **A tool for sending work cannot tell sending
work from exfiltrating work by looking at the work.**

## The keystone: an agent can write the contact list

Every recipient-side restraint anyone would reach for — "only confirmed
contacts", "only contacts older than a week", "only this allowlist" — is
enforced against `trust::Contacts`. And an agent with `gage mcp` can **add a
contact without any human**:

`gage_pair_start` returns the four word-pairs in its own response.
`gage_pair_confirm` accepts those same pairs echoed back. A key knows its own
word-pairs, so the echo proves the pairs made a round trip, not that a human
read them off a second screen. Two tool calls, no human, new confirmed
contact.

This is not a bug and it is not news: it is written into the tool's own
description, and `docs/threat-model.md` says it in as many words — *"It is a
checkpoint, not a proof."* But its consequence for this ADR is decisive, and
has not been written down before:

> **The contact list cannot restrain the agent, because the agent can write
> the contact list.**

Any design that answers "who may I send to?" with "a confirmed contact" is
answering with a value the attacker controls. That has to be fixed first, or
everything built on top of it is decoration.

**Measured, not inferred.** Two fixture homes, `gage mcp` driven over stdio
against one of them, no human in the loop:

```
pair_start  ->  word_pairs: merry lilac · final hedgerow · tangy marsh · tall plumage
pair_confirm -> {"added":"totally-legit", ...}
```

and the victim's `contacts.json` afterwards:

```json
{ "keys": { "VMIALiaa2p11/7/EttlpMKZOEUMkZydKgG+5hh/dtxs=": "totally-legit" },
  "box_keys": { "VMIALiaa2p11/7/E...": "n1rMSuLsZPoO0/C+7Ls1t2OLZw0qIKUqrO7q9D5BZnI=" } }
```

Two calls. Confirmed contact, verify *and* encrypt. The reply even prints
"Check that with totally-legit over a channel that is not this one" — correct
advice, delivered to the only party who was never going to take it.

## What restraint cannot buy, said first

- **It cannot stop a determined local process.** Anything running as you can
  read the same files and open the same socket without going through gage at
  all. Outbound policy raises the cost of using *gage* to exfiltrate; it does
  not contain the machine. Claiming otherwise would be the same overclaim the
  journal chain is careful not to make.
- **It cannot tell intent from content.** See gap 3. Every policy here is a
  proxy for intent, and every proxy has false positives that will train
  someone to pass `--allow-*` by reflex. A refusal people learn to bypass is
  worse than no refusal, because it also produces a false sense of a gate.
- **It does not make the signature mean less.** Worth saying plainly, because
  it is the uncomfortable property: a bundle an injected agent sent is
  *correctly* signed, and arrives marked `SENDER VERIFIED`. gage makes
  compromised output **more** credible, not less. Restraint on the sending
  side is not a refinement of that problem; it is the only place the problem
  can be addressed at all, since the receiver cannot distinguish the two
  cases and should not pretend to.

## The options

### 0. Fix the keystone: a human-only path to the contact list

Not optional and not really an alternative to the others — a precondition for
any of them meaning anything. Make adding a contact something the agent can
*propose* and not *complete*: `gage_pair_confirm` stops writing to the list
and instead queues a pending request that a human releases from the CLI or the
viewer, where the word-pairs are shown next to a name and someone has to act.

Cost: the MCP pairing flow stops being end-to-end, which is a real
regression for the "my assistant sets this up for me" story that
`docs/mcp.md` leads with. Mitigation: the queue can be one keystroke to
release in the viewer, and the agent can be told exactly what it is waiting
for.

Against: it is a second confirmation surface, and the ceremony already has
one. Two gates that both half-work is a known way to get a gate nobody reads.

### 1. A send allowlist, independent of the contact list

A file only a human edits — `~/.ctx/send-policy.json` — naming who may
receive, and optionally what types. Not derived from `Contacts`, so option 0's
problem does not leak into it. Absent file means today's behaviour, so nothing
changes for anyone who does not opt in.

Cost: a second list to keep, and it will drift out of step with the buddy
list. Drift in a security control is how you get a control that is quietly
wrong.

### 2. A first-contact gate

Mechanical and cheap: the *first* bundle to a given key needs a human
release. Everything after is unrestrained. Rests on the observation that the
exfiltration case usually involves a recipient you have never sent to, while
the ordinary case is the handful of people you work with daily.

Cost: it does nothing about the "send it to a colleague who is also
compromised" case, and nothing about volume. It is a speed bump placed where
most of the traffic is not.

### 3. Rate and volume ceilings

N bundles per hour, M bytes per recipient per day, refuse past that and say
why. Catches the loop, catches the tree-walk, catches nothing deliberate and
slow.

Cost: the ceiling is a number someone has to pick with no data, and the first
legitimate bulk handoff turns it into a flag people pass by reflex. Worth
noting it is the only option here that would have caught a 1,000-bundle loop,
and the only one whose failure mode is loud rather than silent.

### 4. A send journal, and nothing else

Build no gate. Make what left *legible*: every send already journals, so
surface it — `gage sent --since`, a line in the viewer, a daily digest of who
received what. Detection rather than prevention, on the same reasoning the
anchoring ADR used for a rewrite: you cannot prevent it locally, so make it
undeniable afterwards.

Cost: it is honest and it is not protection. Someone will read "send journal"
as a control, which is the overclaim this project keeps refusing to make.

## What I would do, and why

*(Recorded as written before the decision above, which went the other way on
option 0. Left unedited: an ADR that quietly rewrites its recommendation to
match the outcome is a record of nothing.)*

**Option 0, then option 4, and nothing else yet.**

0 because every other option on this list is enforced against a value the
attacker can write, so it is not a choice between 0 and the rest — it is 0 or
nothing. And 4 because it is the only option whose cost is honest: it adds no
refusal anyone will learn to bypass, and it makes the question "what has my
agent sent?" answerable, which is the question an owner will actually ask
after an incident.

1, 2 and 3 are all defensible and all premature. Each one picks a number or a
list with no evidence about how people really use this, and each one's failure
mode is a human being trained to pass a flag. **There are zero external users.
Choosing a policy ceiling now would be choosing it from imagination.** The
right time is after the first tester, and the right input is what their
traffic actually looks like.

## The decision this needs from the owner

Three questions, and none of them is technical:

1. **Does the MCP pairing flow stay end-to-end?** Option 0 ends it. That flow
   is a selling point of `gage mcp`, and giving it up is a product decision,
   not an engineering one.
2. **Is detection acceptable where prevention is not available?** Option 4
   alone is the anchoring answer applied to sending. If "we log it" reads as
   insufficient, say so now and 1–3 come back on the table.
3. **Prevention, or honesty about its absence?** Everything above assumes the
   project keeps refusing to overclaim. A ceiling that catches loops would
   look better in a README than a send journal does, and would protect less.

## What the decision means in practice

- **Option 0 — not taken.** `gage_pair_confirm` keeps writing to the contact
  list. The threat model already says why that echo is a checkpoint and not a
  proof; what is new is that this ADR now also says what it *costs*, so nobody
  later builds a recipient control on top of it believing it holds.
- **Options 1, 2 and 3 — not taken, and not deferred.** They are ruled out by
  (1), not merely unscheduled. Reopening any of them requires reopening the
  pairing decision first.
- **Option 4 — built, 22 Oct.** `gage sent`, and a `Sent` event carrying the
  addressees, item count and byte count. Written in `outbound::send_bundle`,
  the single send path. The journal is locally rewritable like every other
  local file, so this inherits the limit the anchoring ADR states, and
  anchoring is what covers it.

  **One exclusion, found by the suite rather than by reasoning.**
  `gage anchor send` does not write a `Sent` line. An anchor publishes the
  digest of the journal's current head; journalling its own send moves that
  head the instant it is published, so two anchors can never name the same
  index again — and that repetition is exactly how `anchor record` detects a
  contradiction. Four checks went red and none of them was a flaky test. The
  exclusion is stated in `gage sent`'s own output rather than left as a hole
  where a careful reader would look, and what it gives up is bounded: an
  anchor carries a digest of this machine's own journal, no user content, to
  a contact already on the list.

Written 22 October 2026. Decided the same day.
