# ADR: anchoring the journal

**Status: option 3 built, 22 Oct.** `gage anchor send|record|list|check`.
The decision this rests on — *where an anchor goes* — was not a technical one,
so it was written up here first and settled by the owner, who chose mutual
anchoring between contacts. `docs/thesis-and-plan.md` lists anchoring as the one unbuilt piece of
decision 4 and says it is "the only one of the three that would survive the
local-rewrite case, and therefore the one that matters most".

## The problem, stated exactly

`gage journal --verify` catches a deleted line, an edited line, and a line
appended by something that does not chain. The README is already honest about
the limit:

> No chained line has been changed, removed or reordered — *unless whoever did
> it also recomputed every following link*, which anything running as you can
> do.

So the chain defends against a script quietly dropping the one line that
incriminates it. It does not defend against a process that rewrites the
journal and re-links it, and the attack suite asserts this directly: a
re-linked edit verifies clean.

That is not a flaw in the chain. **No log a process can rewrite can do
better.** The only way out is for a value derived from the journal to exist
somewhere the rewriting process cannot reach.

## What anchoring is

Periodically take the digest of the newest chained entry — the head — and put
it somewhere outside this machine's control, with the index it was at. Later,
re-derive the head and compare.

If the journal has been rewritten, its head no longer matches any anchor taken
after the rewritten entry, and the rewrite is detectable.

## What it does not buy, said first

Each of these is a claim someone will make for it, and each is false:

- **It does not make the pre-chain history honest.** Same limit as chaining
  itself: an anchor over a forged history anchors a forgery faithfully.
- **It does not prevent a rewrite.** It makes one detectable after the fact.
  Nothing local can prevent a local rewrite.
- **It does not make entries true.** It fixes them in time. A verdict that was
  wrong when it was written is a wrong verdict with a timestamp on it.
- **It only covers up to the last anchor.** Everything after the most recent
  anchor is still freely rewritable, so **the anchor interval *is* the size of
  the rewritable window.** This is the number that matters and the one a
  deployment has to choose deliberately.
- **An anchor nobody else can check is not an anchor.** If the anchor store is
  operated by the same party as the machine, it proves nothing against that
  party. Third-party verifiability is the whole property.

## The options

### 1. A gage-operated anchor service

Easiest, and — not incidentally — the natural paid surface. A machine POSTs
its head; the service returns a signed, timestamped receipt.

Against it: an anchor service run by the project whose logs it anchors is
exactly the "who verifies the verifier" problem. It would have to be
append-only and publicly readable, with its own heads published, to be worth
more than a second copy. That is a transparency log, which is a real system to
operate and not a weekend's work.

### 2. A public transparency log

Sigstore's Rekor and the Certificate Transparency ecosystem exist, are free,
are operated by third parties, and already solve "append-only, publicly
auditable, independently monitored".

Against it: it publishes a digest publicly and permanently. The digest leaks no
content, but **the timing and frequency of anchors leaks activity metadata** —
when this machine was busy, and how often it decides things. For a tool whose
users may be two people and a laptop, that is a real disclosure, and it cannot
be retracted. It also ties a local-first tool to an external service's
availability and policy.

### 3. Mutual anchoring between contacts — **recommended**

Peers exchange heads as ordinary gage bundles. My head, signed by me, lands in
your journal's store; yours lands in mine. To rewrite my journal undetectably I
now have to reach into every machine that holds one of my heads.

Why this one:

- **It needs no new infrastructure, no service, and no account.** It works
  offline, self-hosted, and on a LAN with no relay.
- **It is the existing trust model, reused.** A head from a confirmed contact
  arrives signed, through the same frame, with the same verdict machinery. No
  new trusted party is introduced, which is the thing every other option does.
- **It degrades honestly.** With no peers you have no anchors and the command
  says so, rather than implying a guarantee that is not there.
- It is the one option that makes a paid service *optional* rather than
  load-bearing, which is the version that can be said out loud.

Against it: no absolute time — an anchor proves ordering relative to a peer's
journal, not a wall-clock date. And it is only as good as the peers: two
machines owned by one person anchoring each other prove very little, and the
command must not pretend otherwise.

### 4. A public git repository

Cheap, third-party timestamped, auditable, and a commit history is already an
append-only log. A plausible layer on top of (3) for someone who wants absolute
time without running anything. Same metadata disclosure as (2).

## Recommendation, and what was built

**Build (3), then allow (4) and (2) as optional additions.** (3) is built;
(2) and (4) are not, and nothing in the implementation assumes a service, so
either could be added later without changing what an anchor is.

### What (3) turned out to buy, which is narrower than first written

The design below said `gage journal --verify --anchors` would check stored
anchors against the chain. Writing it made the asymmetry obvious and the
shipped command set is different: **holding an anchor for Bob does not let
this machine audit Bob**, because checking `(n, digest)` against Bob's
journal requires Bob's journal, which is his to send.

What it does buy, with no extra protocol and no second round trip, is that a
**new** anchor is checked against the anchors already held for the same peer.
Two things are then evidence: the same index re-published with a different
digest, and a head that goes backwards. The first is exactly the re-linked
rewrite that `--verify` cannot catch, and the attack suite now drives that
case end to end — edit the last entry in place, watch `--verify` still pass,
watch the anchor catch it.

`gage anchor check <n> <digest>` is the other half, for the direction that
needs a human: somebody reads you an anchor they hold for you, and this says
whether your journal still says the same thing there.

**What is deliberately not done:** nothing refuses mail, drops a contact or
changes a verdict on this evidence. A sender who can trigger local
consequences by making a claim about his own journal is a lever, not a log.

 Do not build (1)
first: an anchor service operated by this project is the weakest version of the
property and the easiest to mistake for the strongest, and committing to it
early would make the honest options look like fallbacks.

## What (3) looks like concretely

- `journal::head() -> Option<(u64, String)>` — index and digest of the newest
  chained entry. Reuses the existing verify walk; no new hashing rules.
- A bundle `kind` of its own, carrying only `{index, digest, taken_at}`. No
  content, no handles, no subject — the journal's own "nothing the sender
  wrote" rule applies with full force, since this is a record read later by a
  human or a model.
- `gage journal anchor --to <contact>` sends one. `gage watch` stores an
  arriving one under `anchors/<their key>/` after the ordinary verdict —
  an anchor from an unconfirmed key is refused like anything else.
- `gage journal --verify --anchors` walks the chain and, for each stored
  anchor, checks that the entry at that index still hashes to that digest.
  It reports three outcomes and distinguishes them: **matched**, **diverged**
  (a rewrite, loudly), and **unanchored** (entries after the newest anchor,
  which is the rewritable window, reported as a count so it is visible).
- The reverse direction is the same command on their machine. Nothing is
  asymmetric and nothing is a service.

## The honest summary line

Anchoring moves the journal from "tamper-evident against a careless process"
to "tamper-evident against a determined local one, as far back as the last
anchor". It is a real improvement and a bounded one, and the bound should be
printed every time the command runs.
