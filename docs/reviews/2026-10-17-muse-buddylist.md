# 2026-10-17, muse, on the buddy list

Dispatched after the first commit (`0b29752`) and before it reached the second
machine. Seven claims put to it by name; it broke five and narrowed two. Its
top finding was a **functional** bug, not a security one, and the reason it
found it and my tests did not is worth recording: my checks drove the HTTP API
directly, and the bug was in the page's client-side state. The page's
JavaScript has no real test coverage and that gap is still open.

## Disposition

1. **The confirmation gate: FAIL, three ways.**
   * `budReveal` cleared `ACONF` on success and `budConnect` then sent
     `ACONF`, so the server's own check rejected every add and the Add button
     was **dead**. *Fixed:* the confirmed pair is kept in `REVEAL` and resent.
   * A sender knows all four pairs of its own key, so it can write the asked-for
     pair into the message that created the request; typing it from there
     satisfies the box and proves nothing, and the server cannot tell the
     sources apart. *Fixed, as far as it can be:* the gate now says exactly
     this, in the gate. There is no technical fix -- ctx cannot see the other
     channel -- so the claim was narrowed instead.
   * The refused list carried the full fingerprint, and a key can be
     un-refused back into a request, so the answer was on screen by another
     route. *Fixed:* no fingerprints in the refused list.
   * *Declined:* an attempt counter or lockout. The caller is local and can
     run `ctx add`, so a limit here is not a boundary against code, only
     against a human -- and a lockout on a local viewer is a way to lock
     yourself out of your own contacts.
2. **"No request type": holds on the wire, failed in the UI.** The heading
   "Asking to connect" put words in the sender's mouth. *Fixed:* the section
   is "Not on your list", with a line saying a message is not a request.
   More seriously, the entry was inserted unconditionally with signature
   validity as a side tag, so a forged or tampered bundle produced a card for
   a key its sender does not hold. *Fixed:* those mint nothing.
3. **Record not block: core holds, "every surface" overstated.** *Fixed:* the
   Refuse button explains before the click, and `still_arriving` -- which went
   false once everything was read, implying delivery had stopped -- is now a
   count of what is held.
4. **"Nothing sender-written is stored": FAIL as worded.** The stored map key
   comes from a manifest and was checked by `b64_decode_ok` alone, with no
   length bound, so arbitrary base64 of any size could be persisted into
   `contacts.json`. *Fixed:* `is_a_key` bounds and validates it on the read
   path too. And "derived and cannot be chosen" was wrong about the label:
   grinding gives you a chosen one, as this project's own comments say.
   *Reworded.*
5. **"Never reaches a grant": FAIL as an absolute.** `ctx add` removes the
   decline, by design. *Reworded* to "not while declined, and only reversed by
   a deliberate add".
6. **"Not a presence roster": FAIL for the LAN path.** A per-contact
   "announced itself 3s ago" on a list refreshing every 2.5 seconds is a
   presence roster whatever the comment says. *Fixed:* three booleans, no
   ages. `relay` was local capability dressed as reachability -- renamed
   `can_leave_mail`. `routed` keyed by display name: the observation is right,
   the suggested fix is **declined**, because verifying it against the key
   means opening another agent's `identity.key` -- private material -- to
   learn a public half, and because sending resolves by name too. Renamed
   `routed_by_name`.
7. **"Nothing unvalidated reaches the page": FAIL.** `first_seen` was
   `manifest.created`, a date the sender writes. *Fixed:* it comes from the
   journal's own first observation, which is what the journal was built for.
   Unverified keys reaching the page is finding 2. The entity-escaping
   analysis is correct -- `&#39;` is decoded before the inline handler's JS is
   parsed -- and is now safe by enforcement rather than by assumption.

## What the mutation run then found in my own tests

Each fix was reverted individually. Four were caught. Two were not:

* **My regression pin for the dead button did not fire.** It asserted
  `INDEX.contains("pair:ACONF")` against the whole page, and `budConnect`'s
  ternary written without spaces -- `?REVEAL.pair:ACONF` -- contains that
  exact substring. The assertion was satisfied by the line it was not about.
  Same class as the check that once passed because the newest id happened to
  sort last. *Fixed:* both halves are scoped to their own function, and the
  pin now fails when mutated.
* **Removing `is_a_key` breaks nothing in the shell suite**, because every key
  the CLI can produce is well formed and reaching the filter needs a manifest
  no command here can build. Said so in both the suite and the test, and the
  predicate has its own unit test.

618 checks, 104 unit tests.

---

Top finding: Claim 1 has a functional blocker in the shipped UI flow, before its security limits are considered. Several other claims hold only in a narrower form than stated.

## 1. Confirmation gate — fails

The reveal flow clears the value the add flow needs:

- In `budReveal`: `ACONF='';`
- The add call resends it: `function budConnect(k){ budPost('/api/connect',{key:k,name:ANAME,confirm:ACONF}); }`
- The server rejects a mismatch: `if typed != *want {`

After reveal, the UI replaces the pair input with the name input (`}else if(open&&shown){`), so the human cannot retype it. As written, the page-driven add cannot succeed.

Even ignoring that:

- The check is stateless and unlimited. `connect_from_ui` has no attempt counter, lockout, expiry, or reveal token. The page itself states the search space: `"one matching pair is 16 bits, and a key can be ground out to produce a chosen one."` Any script able to call the loopback API can iterate the pair space; the code comment already concedes local callers are not a boundary (`the caller is local and could call ctx add directly`).
- The sender knows all four pairs of its own key, because they are derived from that key: `let pairs = crate::words::pairs(&key, 4);`. A sender can therefore put the asked pair inside the very bundle that created the request, or in a follow-up message. Typing it proves the person read attacker-supplied text somewhere, not that they compared against a legitimate second machine. The server cannot distinguish those sources.
- The same page previously displayed the full fingerprint for that key if it was in the refused list (`"fingerprint": crate::words::fingerprint(k)` in `refused`), and offers `Un-refuse`. After un-refusing, the key can reappear as a request with the fingerprint now withheld — but the person has already seen it on this screen.

Narrower true claim: a correct answer shows the person obtained the pair from somewhere other than the current request card. It does not show which source, and the UI path is broken by the `ACONF` clearing.

## 2. “No request type” — wire claim holds, UI claim fails

No dedicated wire type is used: requests are synthesized from any bundle by an unlisted key:

```rust
if !contacts.knows(&k)
    && !contacts.declined.contains_key(&k)
    && !contacts.retired.contains_key(&k)
```

But the UI then manufactures the trust-ask semantics the wire avoided. The section is headed `Asking to connect`, with an `Add to my list` button, regardless of whether the sender ever asked for anything. Any ordinary note becomes a connection request.

Worse, the request entry is created before the signature result matters. The entry is inserted unconditionally (`let e = askers.entry(k).or_insert(...)`), and signature validity only sets a flag:

```rust
if !matches!(l.trust, crate::trust::Trust::Unverified) && l.tampered.is_empty() {
    e.2 = true;
}
```

So an unverified or tampered bundle still produces a labelled request for `m.from.key`, with `signature did not check` as a side tag. In the supplied code, nothing in `buddies_json` checks that the sender actually holds that key before minting the request.

## 3. Declining is a record, not a block — core holds, “every surface” overstates

The main surfaces quoted do say this correctly:

- CLI: `"its bundles still arrive and still need accepting"`
- Frame: `"decision is a record here, not a block: this bundle"`
- Page: `"Refusing records a decision. It does not block anything"`
- Handler: `"refused. Its bundles still arrive; you are not asked again"`

But “every surface” is too strong. The verdict label itself — `"SENDER REFUSED BEFORE (signature valid, and you declined this key rather than adding it)"` — does not say delivery continues, and the initial `Refuse` button in the request card carries no explanation before the click; the explanation arrives in the success message afterwards.

Also, `still_arriving` is `waiting.contains_key(k) || unread.contains_key(k)`. Once all current bundles are read and accepted, the tag disappears, although future bundles still arrive. That risks the exact misreading the text tries to prevent.

The delivery claim itself is not fully provable from the excerpts: `Contacts::verdict` is named in the file header but its body is not included, so I cannot verify no other path treats `Declined` more harshly than `Unknown`.

## 4. Nothing sender-written is stored — fails as worded

The struct fields are clean:

```rust
pub struct Declined {
    pub at: String,
    pub seq: u64,
}
```

But the record is the map entry, and the map key is stored too:

```rust
self.declined.insert(
    pubkey.to_string(),
    Declined { at: crate::bundle::now_rfc3339(), seq },
);
```

In the request flow that `pubkey` came from the sender’s manifest (`let k = m.from.key.clone();`). The only check on this path is syntactic: `if !crate::bundle::b64_decode_ok(pubkey)`. No length, canonical-encoding, or valid-point check is shown.

“Derived and cannot be chosen” is also contradicted by the code’s own comment elsewhere: `"A label is one word-pair, 16 bits, grindable in about 65,000 tries, so a sender can arrange its own label to collide..."`. A sender cannot pick an arbitrary label, but it can grind keys until it gets a chosen one. Derived is not unchoosable when key generation is free.

Accurate claim: the `Declined` value holds only a local timestamp and local seq. The stored key is sender-supplied, base64-checked only, and its label is grindable.

## 5. Declined can never reach an authority grant — fails as an absolute

The intended reversal is built into the shared add path:

```rust
if let Some(d) = c.declined.remove(&sign) {
```

preceded by the comment `"An explicit add is a later decision than a decline, so it overrides it"`. So a declined key can reach the list — and whatever authority being `Known` confers — through `add_contact`, which the header says is shared by `ctx add`, `ctx pair`, and the viewer’s pair button.

The `pair_from_ui` body is not in the excerpts, so there is no way to verify every grant-shaped path passes through a declined check before calling `add_contact`. What the code proves is the narrower statement: while the entry sits in `declined`, `knows()` is false and the frame says `"Nothing here is authorised"`. “Never” is false; “not while declined, and only reversed by an explicit add” is the defensible version.

## 6. Reachability is not a presence roster — fails for LAN

For buddies, the server emits a live-ish per-person LAN age:

```rust
"lan": near.get(key).copied(),
```

rendered as `` `announced itself ${r.lan}s ago` `` with an on/off dot, and the page refreshes continuously: `budLoad();setInterval(budLoad,2500);`. A list of named contacts, each with a current “announcing now / Xs ago” indicator refreshed every 2.5 seconds, is a presence roster for the LAN path, whatever the intent. The comment `"Reachability is per path and never a presence roster"` states a goal the rendering does not achieve.

Two further per-path problems:

- `relay` is not evidence about the recipient: `"relay": relay.is_some() && contacts.box_keys.contains_key(key)`. It is on for every sealable contact whenever this machine is joined to a relay. The tooltip (`'mail can be left for them; whether they collect it is not known'`) is honest, but the underlying flag is local capability, not reachability of that person.
- `routed` is keyed by chosen display name, not by key: `"routed": routes.local.contains_key(name)`. Renaming a contact, or a name collision in local routes, changes the answer for the same key.

Whether LAN announcements are authenticated cannot be checked from the excerpts — `read_nearby`’s body is not shown — so presence-spoofing by a LAN attacker announcing a contact’s `sign` key is an open question, not a proven hole.

## 7. Nothing sender-written reaches record or page unvalidated — fails

Three concrete gaps in the shown code:

1. **Sender timestamp rendered without validation.** `buddies_json` takes `m.created.clone()` as `first_seen`, keeps the lexicographically smallest (`if m.created < e.0`), and emits it to the page. No format, length, or range check appears on this path. HTML escaping (`esc(q.first_seen)`) prevents tag injection in that spot; it is not validation, and a sender controls the displayed “first seen” date.

2. **Unverified keys reach the page surface.** As under Claim 2, a request card — label, asked pair, verdict — is built for keys from `Unverified`/tampered bundles. The validation helpers quoted at the end (`safe_key`, `safe_id`, `clean_thread`) are never called in `buddies_json`; if `routes::list` enforces a key grammar upstream, that proof is not in the supplied code, and the claim as demonstrated rests on it.

3. **Wrong-context escaping for keys in handlers.** Keys are interpolated into JavaScript string literals inside HTML attributes:

```js
onclick="askOpen('${esc(q.key)}')"
```

`esc` converts `'` to `&#39;`, but the HTML parser decodes that entity when reading the attribute, so the inline handler’s JavaScript sees a literal `'`. If a manifest key can contain a quote, this breaks out of the JS string. Base64 keys cannot — which means safety here depends entirely on an upstream key-format guarantee that the request path itself does not enforce (only `b64_decode_ok` in the mutation handlers, nothing in the read path shown).

On storage, see Claim 4: the declined map key is accepted on `b64_decode_ok` alone, with no length or canonical-form check shown, so arbitrary base64-shaped strings can be persisted into `contacts.json` via `decline_from_ui`.

## Summary

| Claim | Verdict |
|---|---|
| 1. Gate is not theatre | Fails — UI flow broken by `ACONF` clearing; unlimited 16-bit oracle; sender can supply the answer |
| 2. No request type | Holds on the wire; fails in UI semantics; unverified bundles mint requests |
| 3. Record, not block | Core holds; “every surface” overstates; `still_arriving` can mislead |
| 4. Nothing sender-written stored | Fails — stored map key is sender-supplied; label is grindable per the code’s own comment |
| 5. Never reaches authority | Fails as absolute — `add_contact` removes the decline and adds; pair path not shown |
| 6. Not a presence roster | Fails for LAN — per-contact recency dots refreshed every 2.5s; `relay`/`routed` are not per-key evidence |
| 7. Nothing unvalidated reaches page/record | Fails — unvalidated `first_seen`, unverified askers, entity-escaping used in a JS-string context |

Unverifiable from the excerpts, and worth supplying before this ships: `Contacts::verdict`, `pair_from_ui`, `routes::list`, `lan::read_nearby`, and `words::label`/`pairs`. Claims 3, 5, and 7 each depend on at least one of those bodies.
