# Reviews, and what was done with each finding

Kept because of a failure on 16 Oct: a reviewer's four findings came back, three
were fixed, and the fourth sat missed for a day. That is a tracking failure, not
a transport one -- no amount of routing reviews through ctx would have caught it,
and a list that says which findings are closed would have.

So: one file per review, verbatim, plus the disposition of every finding. A
finding is closed when it is fixed, or when it is declined **in writing with a
reason**. Nothing is closed by being forgotten.

| Review | Findings | Fixed | Declined | Open |
|---|---|---|---|---|
| [2026-10-16 codex](2026-10-16-codex.md) | 7 | 7 | 0 | 0 |
| [2026-10-17 muse](2026-10-17-muse.md) | 10 | 10 | 0 | 0 |
| [2026-10-17 muse, on the journal](2026-10-17-muse-journal.md) | 7 | 7 | 0 | 0 |
| [2026-10-17 muse, on auto-accept](2026-10-17-muse-autoaccept.md) | 5 claims, 2 broken | 2 | 1 | 0 |
| [2026-10-17 muse, on the buddy list](2026-10-17-muse-buddylist.md) | 7 claims, 5 broken | 5 | 2 | 0 |
| [2026-10-18 muse, pre-public](2026-10-18-muse-ensemble.md) | 5 claims, 4 broken | 11 | 0 | 0 |
| [2026-10-18 codex, pre-public](2026-10-18-codex-ensemble.md) | 1 confirmed + 3 graded | 2 | 0 | 0 |
| 2026-10-18 grok, relay threat model | 4 ranked gaps | 3 | 0 | 1 |

### 2026-10-18, the first three-reviewer run

All three were given the same surface before it went public. They did not
overlap the way I expected.

**muse** found the one that mattered most and that neither other reviewer
raised: the fingerprint people confirm covered only the signing key, while
the token they exchange carries a signing key *and* an encryption key. An
attacker substituting only the second half passes the word-pair comparison
perfectly and then receives every sealed message. That defeated the ceremony
the whole product rests on.

**grok** found the relay's unbounded request-head read -- one connection,
no credentials, grows a buffer until the cgroup kills the process, and
`Restart=on-failure` makes it a crash loop. It also noticed the viewer had
been given exactly that cap months earlier and the relay never was.

**codex** found the absence of any mailbox cap, and traced why it bites:
every registration rewrote a growing owners map under the global lock.

Three reviewers, three different top findings, no duplicates among them. The
overlap was in the second tier -- muse and grok independently caught the
uncounted refusal threads and the per-read timeout being useless against a
slow drip.

**Declined:** grok's inode-exhaustion estimate. The mechanism is real --
`dir_bytes` measures apparent size, so a million one-byte envelopes consume
inodes while barely touching the byte caps -- but the mailbox cap plus the
per-mailbox message cap now bound the file count to roughly a million at the
defaults, and the figures given were explicitly estimates rather than
measurements. Worth revisiting with a measured filesystem rather than acted
on from arithmetic.

## 2026-10-16, codex, on the day's five changes

1. **Label suppression was sender-triggerable.** A handle equal to
   `words::label(key)` got the quiet note, and a label is 16 bits -- grindable
   in ~65,000 tries -- so a sender can arrange its own label and claim it. Live
   on the owner's own setup, where two key labels are also the names two
   machines go by. *Fixed:* the note is withheld whenever the claimed handle is
   a name on this list at all, live, retired or a group.
2. **"A grant already covers the message" overstated freshness.** *Fixed:* now
   "a grant matched at the moment of the poll", with the limits written out.
3. **"The hook never receives the payload" sat beside passing the subject**,
   which is sender-written message content; and the env guarantee cannot stop a
   hook doing `eval "$CTX_SUBJECT"`. *Fixed:* narrowed to "never receives the
   bundle's items", both limits stated.
4. **"Announced first, then hooks" was presented as the only safe direction.**
   *Fixed:* named as an at-most-once policy, with the trade it makes and what
   adding a "hook completed" state would buy.
5. **Requiring `Origin` narrows the loopback API beyond browsers.** *Fixed:*
   the contract is now stated in `ui.rs` -- the mutating routes are for the page
   only, and the CLI is the supported programmatic interface.
6. **"Three reasons that are all the same reason" compressed distinct
   tradeoffs.** *Fixed:* unpicked in `thesis-and-plan.md`, including that
   hosting need not mean a readable host.
7. **"Strong evidence about the renderer" was miscalibrated**, since the
   renderer's bytes were already unit-tested. *Fixed:* the result file now
   calls it a case report about the reader.

A note on dispatch, which is a finding about the process rather than the code:
grok produced nothing on this round because `grok-ask review` runs with tools
disabled, and the request assumed repo access. A reviewer without the repo needs
the diffs inline; one with it needs the question. Sending the same request to
both wasted the round.

## 2026-10-17, muse, on the same five changes plus the day's fixes

The strongest review the project has had, and it found three bugs codex did
not -- including one that made a central claim false.

1. **A hook could fire on an authority the reader was never shown.**
   `authority_block` printed only for reply-expecting kinds, while
   `--on-arrival` fires on any grant, `allow mac share` included. So the
   sentence "a hook can never fire on an authority the reader was not shown"
   was simply false on exactly the kind where the frame said nothing.
   *Fixed:* a matched grant is now shown on every kind. The suppression that
   codex argued for is kept only for the NO case, which was the half of the
   reasoning that was sound.
2. **`announced.json` trimmed the wrong end.** It was a `BTreeSet`, so
   bounding it kept the lexicographically largest 2000 ids -- and ids are hex,
   so the ones dropped first began `0`. A dropped id is announced again, and
   with `--on-arrival` it is *acted on* again. Pre-existing; the comment said
   "the oldest ids stop mattering", which was true of the intent and false of
   the code. *Fixed:* a list in insertion order, trimmed at the front, old
   format still loading.
3. **The name check missed other keys' labels.** `is_a_name_you_use` looked at
   chosen names only, so a sender could grind a 16-bit label collision with a
   key the reader already holds and still get "nothing is in conflict". Live
   on a two-machine setup, where machines go by their labels. *Fixed:* other
   keys' labels count, case- and whitespace-insensitively.
4. **"It does not accept the bundle" described this code, not the world** --
   the hook gets `CTX_BUNDLE_ID` and can accept it itself. *Fixed:* narrowed
   to what ctx guarantees, with the observation that a hook crossing the gate
   deliberately is the point of an agent loop.
5. **"Sender text is data, never command" is hook-dependent.** *Fixed:*
   restated as "ctx does not interpolate it", with `eval`, unquoted expansion,
   option injection and environment inheritance by children all named.
6. **"The mutating routes are for this page only" overstates it** -- there is
   no per-page secret, so any local process can send both headers. *Fixed:*
   the property is now "no cross-site page can reach these routes", and the
   note says plainly that against a local process this is not a boundary and
   was never meant to be.
7. **"A handle the sender typed still gets the loud warning" is false** -- the
   code cannot tell typed from derived. *Fixed* in the result file.
8. **Two unit tests claimed to pin a distinction they never exercised**, only
   asserting `label(key) != "mac"`. *Fixed:* four tests that call the real
   predicate, including the collision case and the own-label case.
9. **The board's symmetry argument was the weakest** -- ctx's contact lists
   are already pairwise asymmetric, so a board breaks no symmetry that exists;
   and calling `ctx threads` "the honest version" of a board substitutes the
   thing that was built for the thing that was declined. *Fixed:* both.
10. **The injection result still over-credited causation.** Nothing isolates
    the nonce from the frame, the reader's training, standing workspace
    instructions, or the priming of having written the scaffold; and a false
    positive was described as a defence that "works". *Fixed:* downgraded to
    "consistent with", with the missing controls named.

Dispatch notes, both failures of mine rather than of the reviewers:

- **grok has file access and I broke its run twice.** First by sending a
  repo-shaped request while assuming it had none, then -- having fixed that --
  by editing the very files it was reading. Its output says so: "the files
  shifted while I was reading them". A review and a rewrite of the same tree
  cannot run at once.
- **muse needs no sandbox to review.** It had been idle since 15 Oct because
  it runs without bwrap and anything it executed needed hand approval. A
  review executes nothing: `muse exec --disable-shell --disable-write
  --disable-web-tools` has nothing to approve and nothing to escape. The
  blocker never applied to the job.

## 2026-10-17, muse, on the journal -- caught before it shipped

Sent twenty minutes after the journal was written, with the code inline and no
repo access, because a review and a rewrite of the same tree cannot run at
once. It opened with "no claim survives exactly as written", and it was right.

1. **Dedup compared the wrong two things.** The seen-set was built from
   entries' `bundle` field -- a manifest id -- and tested against *directory
   names*. They usually coincide, because delivery names a directory after the
   id, and "usually" is not a property. *Fixed:* keyed on the manifest id read
   from the bundle.
2. **No dedup within a sweep.** One bundle present in both `pending` and
   `accepted` got two entries in a single pass. *Fixed:* the set is updated as
   it goes, and a check puts the bundle in both stages.
3. **A bundle whose manifest will not parse was retried for ever**, and left
   no entry at all -- while the comment claimed it was "attempted once per name
   and cannot spin". Those are the arrivals most worth recording. *Fixed:* a
   parse failure writes a minimal entry built from bytes this machine hashed
   itself, keyed so it cannot spin.
4. **An already-accepted bundle is not an arrival.** Scanning `accepted` means
   its first entry is written after acceptance, against later contacts.
   *Fixed:* written and marked `backfilled`, and the event renamed `observed`,
   because `at` is when a scan ran rather than when anything was placed.
5. **Sender-controlled values did reach the journal.** The module doc called
   `thread` "the one sender-chosen value in an entry"; `bundle` is `m.id`,
   which the signer writes -- the witness comment in the same file says so --
   and the keys come off the wire too. *Fixed:* every one validated, hex and
   bounded or replaced by a hash of itself, with tests for terminal escapes
   and confusables.
6. **`seq` did not order anything.** `record` only *read* `LocalState::seq`,
   so every entry in a sweep shared a value while the field's comment claimed
   it "gives order even when clocks lie". *Fixed:* an `n` allocated while
   holding the journal lock, with the append and the `fsync` under that same
   lock -- previously there was no lock and no durability at all.
7. **Two claims were too broad.** A later hash chain cannot make pre-chain
   entries tamper-evident; it would chain a forged history faithfully. And a
   differing verdict is not proof of a key change -- an entry freezes an
   outcome, not its evidentiary basis. *Fixed:* both, where they were written.

The lesson is the ordering. This review arrived before the journal was
committed, which is the only reason none of it shipped. Every earlier review
this week arrived after.
