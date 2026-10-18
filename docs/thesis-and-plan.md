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

A real shared board was rejected for now, for three reasons. They are
related but they are **not one reason**, and none of them shows a board is
impossible -- each is a cost this project is not ready to pay. (An earlier
draft said "three reasons that are all the same reason", which a reviewer
correctly called compression that made the choice sound settled by argument
when it is settled by preference.)

- Something has to **host** it. The relay is currently a drop box that cannot
  read what it holds. The weaker, true version of this: hosting need not mean
  a readable host -- a board could store client-encrypted posts, or be
  self-hosted -- but every such design is more machinery than a drop box, and
  the simplest one that works is a server that can read.
- **Sealing to one recipient breaks.** A post readable by a group needs N
  copies or a group key. The rekey-on-leave cost is real but it is a cost of
  *one* group-key design, not a proof; and N sealed copies is a workable
  email-shaped answer, which is what this project already does. So this is a
  reason to prefer fan-out, not a reason a board cannot exist.
- The **unit of trust changes.** Trusting a board's membership is a different
  object from trusting a key, and a weaker one. An earlier draft called this
  "the friend list stops being symmetric", which a reviewer pointed out is not
  a loss at all: ctx's contact lists are *already* local and pairwise
  asymmetric -- my listing you implies nothing about your listing me -- so a
  board would break no symmetry that exists. The real cost is narrower: a
  board's membership is one object many parties share, and a key is an object
  each party holds an opinion about. This is the weakest of the three.

The board *feel* comes from `gage threads` instead, which is a local view over
mail this machine received and needs no trusted host.

That is a **different product, not a cheaper board**, and an earlier draft
called it "the honest version" of one, which a reviewer was right to reject as
substituting the thing that was built for the thing that was declined. A board
has shared membership, shared ordering and shared visibility; `gage threads`
has none of those -- it shows what this machine happens to hold, in the order
this machine observed it. If a shared board is ever wanted, it has to be
built, and these three costs are what it will cost.

## Explicitly still refused

**A standing presence roster.** It is the natural next ask for anything that
feels like a buddy list, and it has been refused twice: a roster that is
always visible is a roster somebody else can also read. `gage lan` answers the
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

### 2. Auto-accept under a grant, with a budget — **built 17 Oct**

One change to the grant grammar rather than two migrations, because the budget
is the safety belt for the auto-accept:

    allow mac question auto-accept max-exchanges 4

Two things in the plan as written turned out to be wrong, and the shipped
version differs:

- **"A hook may accept only within a grant that says so"** is not enforceable.
  A hook runs `gage accept` as a separate process; ctx cannot tell a hook's
  invocation from a human's. So the acceptance is in the tool, in `gage watch
  --auto-accept`, where the grant is consulted by the code that does the move.
  The hook is told `CTX_AUTO_ACCEPTED` and never needs to accept anything.
- **"The exchange count is kept by the receiver, per thread, so nothing a
  sender puts in a bundle can reset it"** had a hole in it: a thread id *is*
  something a sender puts in a bundle. Per-thread counting on its own means a
  fresh thread is a fresh budget. The fix is that `auto-accept` implies
  `in-reply-only`, checked against this machine's own `sent/`, so a thread can
  only be opened by the receiver. Writing that check also revealed that
  `in-reply-only` had never meant anything: it tested the sender's own
  `in_reply_to` field, so any string satisfied it.

The count lives in the journal rather than a counter file — the record of what
was done is already the record of how much was used — which is the payoff for
having built capture first.

Why it is needed: `gage accept` currently moves a directory and records nothing
about *how* it happened. The moment anything accepts without a human, "did a
human accept this, or did a grant?" becomes the only question that matters,
and nothing on disk can answer it. Provenance cannot be retrofitted onto
records that did not capture it.

And nothing today stops a runaway: replies are new bundles with `in_reply_to`,
nothing counts exchanges in a thread, and two agents with mutual grants and a
replying hook is A->B->A->B until someone notices. `chain` counts *forwarding*
hops, which is a different thing. `docs/prior-art.md` notes peer tools carry
`--ttl`, `--max-depth` and `--max-calls`; ctx carries none of them.

### 3. The buddy list UI -- **built 17 Oct**

Built as described below, with three corrections the plan did not anticipate:

- **The confirmation gate had to be inverted.** The plan said "the four
  word-pairs are the confirmation; a button is not", and my first build
  honoured the letter and missed the point: it printed the whole fingerprint
  on the card and asked the person to type one pair *from it*. The answer was
  on screen. The card now shows no fingerprint until a pair -- never pair 1,
  which is the visible label -- is typed correctly.
- **A contact added from a request is verify-only.** A manifest does not
  carry its sender's encryption key, which the plan had not considered. Said
  in the list rather than papered over.
- **Retired keys had to be excluded from requests**, not just declined ones.
  Offering "add this contact?" for a key the person deliberately took out of
  service invites undoing a rotation with a click.

The original text follows.



The shape the owner actually wants, and the first thing a second person would
judge the project by. `gage ui` already has threads, accept/reject, a reply box
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

### 4. The audit log (decision 4) -- **the capture half built 17 Oct**

Once anything happens while nobody is watching, "what did my machine do" is
the question, and `sent/` plus `accepted/` is a trail of artifacts rather than
of decisions.

`src/journal.rs` records four events with the verdict frozen at the event, and
auto-accept's exchange budget is counted from it rather than from a counter
file. The hash chain and `gage journal --verify` landed 17 Oct, with the limit
asserted in the suite rather than only described: a re-linked edit verifies
clean, and a check exists to say so.

Still unbuilt: a retention policy, and anchoring a digest somewhere this
machine does not control -- which is the only one of the three that would
survive the local-rewrite case, and therefore the one that matters most. muse's review of the
journal is explicit that a chain added later proves only that entries have not
changed since chaining began -- it would chain a forged pre-chain history just
as faithfully -- so this is worth doing while the log is still short.

### 5. Running where it claims to run

Added 17 Oct, after the suite was run on the MacBook for the first time and
reported six failures -- none of them a defect in ctx, and one of them a
*security property the suite was lying about*. The project's own thesis is
two machines; a test suite that only runs on one of them cannot tell you
whether the other is fine. Fixed, and the honest lesson is that the bug class
it exposed (a check that picks whichever bundle the filesystem lists first)
had been passing here by luck for weeks.

What this suggests next: the end-to-end viewer test runs only where playwright
and chromium happen to be, and nothing runs either suite automatically on
either machine. A `git pull && cargo test && attacks.sh` that runs on both and
tells you when it breaks is a small thing that would have caught all of the
above the day it was written.

## Not on the plan

Send-side restraint. The authority file says what an agent may act *on*;
nothing says what it may *send*. An injected agent with a grant cannot be made
to act on a stranger's message, but it can be talked into sending anything to
anyone on its list. Left open deliberately: the answer is not obvious and it
is a bigger argument than the items above.
