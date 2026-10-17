# 2026-10-17, muse, on auto-accept

Dispatched after the first commit (`2dee015`) and before the change reached the
second machine. Five claims were put to it by name; it broke two and qualified
two more.

## Disposition

1. **Sender-refill: FAIL.** The budget was keyed on `m.thread`, which the
   sender writes *independently of* `in_reply_to`, so one granted sender could
   answer the same verified parent under `aa`, then `bb`, then `cc`, and
   collect a full budget each time. `answers_something_i_sent` validated the
   parent and then threw away everything it learned, returning a bool.
   *Fixed:* it returns the parent, and the budget is keyed on the parent's own
   thread read from this machine's `sent/`. A reply claiming a thread that
   disagrees with its parent is refused outright as well.
2. **Journal-is-the-budget: FAIL**, in three separate ways.
   *Fixed:* the record is written before the move (so a failure leaves the
   bundle pending, not accepted-and-uncounted); the count is retaken inside
   the journal lock (two watchers each read `used = 0` against `max = 1`); a
   journal failure latches auto-accept off for the run, where it used to print
   and carry on; and an unparsable line declines rather than counting past it,
   because `read` skips bad lines, which fails open for a counter.
   Two of these -- the ordering and the lock -- were found independently while
   the review was running; the latch and the parse check were not.
3. **Acceptance-is-not-permission-to-act: only narrowly true.** True of the
   acceptance, false of `--auto-accept --on-arrival` together, where the
   accept is deliberately ordered before the hook. *Fixed:* the README now
   says which of the two the claim covers.
4. **Half-written grant cannot read as unbounded: holds.** Notes that
   `max-exchanges 18446744073709551615` is effectively unbounded but is a
   fully written grant, which is a fair reading. *No change.*
5. **Nothing sender-written reaches the journal unvalidated: not
   established.** Correct, and a dispatch error rather than a defect: the
   helpers that do the validating (`safe_id`, `safe_key`, `clean_thread`) were
   not in the excerpt sent. They are tested in `journal::validation_tests`.
   *Declined as a code change; the lesson is about what to include.*

The reviewer's own instruction was followed: "do not send this to the second
machine yet."

---

Top finding: do not send this to the second machine yet. Claims 1 and 2 fail in the supplied code, by construction. Claim 3 is only true for `perform` in isolation. Claim 4 holds for the cases shown. Claim 5 is not established by the excerpts.

## 1. Sender-refill: FAIL

The reply check and the budget key are different sender-controlled values, with nothing tying them together.

`consider` reduces the parent to a boolean, then budgets on `m.thread`:

```rust
let is_reply = crate::authority::answers_something_i_sent(home, m);
```

```rust
let thread = crate::journal::clean_thread(m.thread.as_deref());
let used = crate::journal::auto_accepts_in_thread(thread.as_ref());
```

`answers_something_i_sent` validates `m.in_reply_to` against `sent/`, then discards everything it learned about that parent. It never returns the parent's id or thread, and `consider` never checks `m.thread` against the parent manifest's thread.

Attack, using only a legitimate verified sender:

1. Receive one genuine message from this machine, id `P`.
2. Send reply 1 with `in_reply_to: P`, `thread: T1` — accepted, budget for `T1` is 1.
3. Send reply 2 with `in_reply_to: P`, `thread: T2` — `in-reply-only` passes again, `auto_accepts_in_thread(T2)` is `0`, accepted.
4. Repeat with `T3`, `T4`, … Each gets a fresh `max_exchanges` budget.

The reuse of the same parent also is not limited: the check is existence in `sent/`, not “this parent has not already been answered in this thread.” Your own doc comment concedes the related gap:

> “What it still does not establish: that the reply came from the party the parent was addressed *to*.”

That means a granted sender who learns any receiver-sent id can attach replies to that conversation, even one addressed elsewhere.

Fix direction: make `answers_something_i_sent` return the verified parent identity, derive the budget key from the parent found in `sent/` (its id or its thread), and reject a bundle whose `m.thread` does not match that parent's thread. Counting a sender-written string cannot be the root of the budget.

## 2. Journal-is-the-budget / failed write fails acceptance: FAIL

`perform` moves first and journals second:

```rust
crate::routes::restage(&from, &dest)?;
```

```rust
crate::journal::record_with_auto(
    crate::journal::Event::Accepted,
    &dest,
    ...
)?;
```

The `?` on the journal write only propagates an error after `restage` has already succeeded. There is no move-back, no quarantine, and no deletion of `dest`. So a failed journal write produces exactly the forbidden state: bundle in `accepted/`, no budget line.

The watcher then does not do what the comment in `perform` claims. `perform` says:

> “So it is reported loudly, and the caller stops auto-accepting for this run.”

But the caller only prints:

```rust
Err(e) => {
    eprintln!("  {short}: could not auto-accept: {e}");
}
```

It does not clear `auto_accept`, break, or disable the feature. The outer `loop` continues, and the next arrival is auto-accepted under the same failing journal — again moved first, again uncounted. “Disk full” becomes an unbounded, uncounted accept path for as long as it lasts.

Two more budget-integrity holes in the same claim:

`read_unlocked` silently drops bad lines:

```rust
.filter_map(|l| serde_json::from_str::<Entry>(l).ok())
```

That is defensible for history display. For a budget counter it fails open: a torn or corrupt `Accepted`/`auto` line stops counting.

And the check is not atomic with the record. `consider` computes `used`, stores it in `Decision::Yes`, and `perform` deliberately does not re-decide:

> “Takes the decision rather than re-deciding, so there is no path where the move happens under one answer and the record is written under another.”

Two concurrent `ctx watch --auto-accept` processes can both read `used = max - 1`, both return `Yes`, both move, and both append stale `used` — overspending the budget. No cross-process budget lock is shown; the journal append lock described in `Entry.n` serialises lines, not the read-count-then-append sequence.

Fix direction: reserve the budget in the journal under the journal lock before the destination becomes visible as accepted, re-count inside that lock, count the reservation even if the later move fails, and make a journal failure disable auto-accept for the run and leave the bundle pending.

## 3. Acceptance-is-not-permission-to-act: only narrowly true

For `autoaccept::perform` alone, the visible code does only `create_dir_all`, `restage`, and `record_with_auto`. No `ctx open`, no model handoff, no command execution is shown there.

But that is not the whole feature as wired in `ctx watch`. The loop deliberately orders auto-accept before the arrival hook:

> “Before the hook, and after the announcement… a hook written for an unattended loop wants to find the bundle accepted rather than race the watcher for it.”

```rust
if let Some(cmd) = &on_arrival {
```

So `ctx watch --auto-accept --on-arrival …` is an end-to-end unattended pipeline in one process, and acceptance is the step staged specifically so the next step can act on it. The honest claim is: “`perform` itself does not open or run anything.” The broader claim that nothing opens or runs anything after acceptance is false for the combined watcher configuration, even though the hook is separately human-configured.

## 4. Half-written grant reading as unbounded: holds

This one survives the supplied code. `parse` refuses the exact failure mode:

```rust
if max_exchanges.is_none() {
    return bad(
        "`auto-accept` needs `max-exchanges N`: unbounded unattended \
         acceptance is not something to grant by omission",
    );
}
```

It also refuses `any` with `auto-accept`, and refuses `max-exchanges 0`. A parse error voids the file through `Authority::load`:

```rust
Err(e) => Self { grants: Vec::new(), present: true, error: Some(e) },
```

and `lookup` returns `Denied::Unreadable` before consulting grants. The belt-and-braces check in `consider` is also present:

```rust
let Some(max) = g.max_exchanges else {
    return Decision::GrantIsNotAutoAccept(rendered);
};
```

Caveat, not a counterexample: a human who writes `max-exchanges 18446744073709551615` has written an effectively unbounded grant, but that is a fully written grant, not a half-written one.

## 5. Nothing sender-written reaches the journal unvalidated: not established

The visible code mostly delegates the claim to helpers whose bodies are not in the excerpt:

```rust
bundle: safe_id(&m.id),
from_key: safe_key(&m.from.key),
thread: clean_thread(m.thread.as_deref()),
```

and the unattended path does not even call `entry_for` directly:

```rust
crate::journal::record_with_auto(
    crate::journal::Event::Accepted,
    &dest,
    Some(crate::journal::Auto { ... }),
)?;
```

`record_with_auto`, `clean_thread`, `safe_id`, and `safe_key` are not shown, so “validated” is asserted by naming, not demonstrated. That matters because the budget itself consumes one of those sender-written values: even if `clean_thread` validates syntax, a sender can supply an unlimited supply of distinct, well-formed thread strings — which is precisely the Claim 1 bypass. Validation of form is not validation of budget semantics.

If those helpers are sound, the narrow syntactic version of this claim may hold. On the inline code supplied for a pre-shipment review, it should be marked unverified, not passed.

## Bottom line

Blockers before this goes to another machine:

1. Bind the budget to the verified parent in `sent/`, not to `m.thread`.
2. Make the journal reservation precede acceptance, atomically under a lock, and stop auto-accepting for the run on journal failure.
3. Reword Claim 3 to cover only `perform`, or explicitly exclude `--on-arrival` from the “nothing runs” claim.

Claims 1 and 2 are not edge cases; they are reachable by an ordinary granted sender and by an ordinary disk-full during the exact unattended mode this feature introduces.
