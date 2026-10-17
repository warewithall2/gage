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
