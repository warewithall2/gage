No claim survives exactly as written. Ranked by decision impact:

### 1. “Arrived” entries are not necessarily arrival verdicts, first observations, or unique

> “Each entry stores the trust verdict AS COMPUTED AT THAT EVENT.”

> “Entries for 'arrived' are written from `routes::observe_inbox`, which is where the inbox is scanned.”

`record_arrivals` scans both pending and accepted directories, then computes `l.trust.label()` when it happens to scan. A bundle accepted before its first scan can therefore receive an `Arrived` entry after acceptance, using the contacts state at scan time—not arrival time.

Deduplication is also broken as shown:

- `seen` contains prior entries’ manifest IDs, `e.bundle`.
- It is compared against directory names.
- It is not updated after appending during the sweep.

If directory `d-a` contains manifest ID `x`, it is recorded again on every scan. If that ID equals another bundle’s directory name, the other bundle can be suppressed. The same bundle present under pending and accepted can be appended twice in one sweep.

**Decision change:** do not treat this journal as an arrival-verdict record until entries distinguish `first_observed` from backfill and deduplicate on a stable bundle identity.

### 2. Sender-controlled text does reach the journal

> “The thread id is the one sender-chosen value and is admitted only if it is hex and <=64 chars.”

That is false. `entry_for` copies these sender-supplied values without the sanitisation applied to `thread`:

- `bundle: m.id.clone()`
- `from_key: m.from.key.clone()`
- `author_key` from `m.chain`

The witness comment itself concedes the problem:

> “it is keyed on the manifest rather than the bundle id because the id is a field the signer chooses.”

JSON encoding prevents literal newline forgery, but decoded IDs and keys can still carry terminal escapes, misleading Unicode, excessive length, or path-like values into whatever displays or consumes the journal.

**Decision change:** Claim 2 cannot be used as a safety guarantee until every sender-derived field receives canonical validation, not just `thread`.

### 3. `seq` does not provide the claimed ordering, and appends are not durable evidence

> “The local observation counter, which gives order even when clocks lie.”

As shown, `record` merely loads `LocalState::load().seq`. It does not allocate or advance a sequence value. Every arrival recorded in one `record_arrivals` sweep can therefore share the same `seq`.

`append` also performs only `write_all`: no locking, atomic sequence allocation, `sync_all`, or protection against torn final lines appears in the excerpt. Concurrent processes can interleave both sequence allocation and appends; an OS crash can lose the allegedly frozen record.

**Decision change:** the journal cannot settle ordering disputes until sequence allocation and appending are one atomic, durable operation.

### 4. Capture-first still loses precisely the hostile arrivals

> “a bundle whose manifest will not parse is still only attempted once per name and cannot spin.”

That comment is wrong across scans. `record` returns an error before appending when reading or loading the manifest fails. No journal entry is created, `seen` never learns the directory name, and every later scan retries it.

Thus malformed or adversarial bundles—the arrivals most worth recording—leave no permanent capture. The supplied code also shows no call sites proving exactly one entry for `accepted`, `rejected`, or `opened`.

**Decision change:** capture is incomplete; parse failures need a safe fallback entry based on raw bytes and local identity rather than trusted manifest fields.

### 5. A later hash chain cannot retroactively make existing entries tamper-evident

> “a chain can be laid over entries that already exist”

A chain started later proves only that entries were unchanged after chaining began. It cannot distinguish the original pre-chain history from entries that were modified, deleted, reordered, or fabricated beforehand; it would faithfully chain the forged history.

**Decision change:** capture-first is reasonable, but do not describe the later chain as recovering tamper evidence for the pre-chain period unless an externally anchored digest of the current journal is preserved now.

### 6. The witness claim is broader than the shown computation

> “It answers ‘is this the same bytes’ without holding the bytes”

The code hashes only `from.key` and the manifest bytes. That identifies the same bundle bytes only if the manifest cryptographically commits to every other bundle component and loading verifies that commitment; neither fact is established by the excerpt.

**Decision change:** treat `witness` as a manifest witness unless payload binding is demonstrated.

## Sound parts

- Claim 1’s premise is sound: recomputing a verdict after key changes can produce a different result from the verdict computed at the relevant event.
- Claim 2’s narrow `clean_thread` statement is sound: non-hex, empty, or over-64-character thread values are replaced by `Thread::Other`.
- Claim 3’s core ordering is sound: recording verdicts now is preferable to waiting for a perfect integrity mechanism, subject to the capture and retroactive-evidence limits above.
r as history accumulates.

### 6. A differing later verdict is not necessarily evidence of a key change

> “a later entry carrying a different verdict for the same bundle is not a contradiction, it is the record of a key having changed underneath.”

Other explanations remain open in this design: duplicate or backfilled `Arrived` entries, verdicts computed after acceptance, parser/load differences, local tampering, contact edits, or a ctx upgrade changing label semantics or verdict policy.

The entry stores only the verdict label plus key strings. It does not store the contacts revision, key epoch/status inputs, policy/code version, or reason needed to audit why that label was produced. It freezes an outcome, not its evidentiary basis.

### 7. First observation is defensible, but it should not be called placement arrival

> “nothing tells this machine when a bundle was placed in its inbox, so noticing is the only arrival it can honestly date.”

The narrow epistemic point is sound: sender-supplied or filesystem times are not trustworthy placement evidence. But the implementation's `at` is when a scan happened to run, not necessarily close to placement; a bundle can also be placed and removed between scans and never be observed. Naming the event `Observed` — with a distinct backfill case — would state the guarantee the code can actually keep.

## What survives

Claim 1's motivating premise is sound in one line: recomputing a verdict after contacts or keys change does not recover the historical verdict.

Claim 3's priority is sound in one line: an unrecorded arrival verdict generally cannot be reconstructed later, assuming no separate contacts history.

Claim 4's core is sound in one line: first local observation is the only arrival time ctx can honestly assert from its own knowledge.
