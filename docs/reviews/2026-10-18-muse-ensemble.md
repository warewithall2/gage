Top finding: Claim 2 fails in a way that breaks the whole verification story — the fingerprint authenticates only half the shared key material, so a channel attacker can be silently substituted as the encryption recipient while every word matches.

## Claim 1 — “cannot destroy an existing identity”: not established, fails as written

The guard is a load-success test, not an existence test:

```rust
Err(_) => {
    let id = identity::Identity::create_named(name.as_deref())?;
```

`Err(_)` discards the reason. A missing identity, a corrupt identity, an unreadable identity, a permissions failure, and a version/format mismatch all take the same “create a new one” path. If `create_named` overwrites, the existing identity is destroyed by exactly the command that claims it never does that. If `create_named` refuses because a file exists, the user is stranded with a misleading failure — but that refusal lives in a function that is not shown, so the shown code does not implement the claim; it assumes it.

Two concurrent `ctx connect` runs also both observe the load failure and race into creation; the snippet has no lock or atomic create.

The reassuring line is only printed on the path that was already safe:

```rust
println!("you already have an identity, so this kept it.");
```

Verdict: **unsupported as stated; fail-open on any load error other than (presumably) absence.**

## Claim 2 — share line safe over any channel: **fails**

The shared token carries two keys:

```rust
let token = format!("{}.{}", id.public_b64(), id.box_public_b64());
```

The out-of-band check authenticates only one of them:

```rust
println!("    {}", words::fingerprint(&id.public_b64()));
```

`words::fingerprint` is computed over `id.public_b64()` — the signing key. The box key (`box_public_b64`) is not covered by the word-pairs at all.

Attack: an attacker who can touch the channel the line travels over (the exact threat the word-pairs exist for) leaves the first half untouched and replaces the second half with their own box key. The recipient adds the entry, compares word-pairs, hears an exact match — because the signing key really is the sender’s — and then seals envelopes to the attacker. The attacker decrypts, reseals to the real box key, and relays. Both parties did the confirmation correctly and it proved nothing about who can read the mail.

That alone falsifies “the word-pair confirmation is what makes it safe.” The confirmation makes *half* of it safe.

Secondary problems:

- “Safe to send over any channel” is still overbroad even with both keys covered. The line is a long-lived public identifier plus the `to_box` capability the relay accepts mail for. Anyone who sees it learns who corresponds with whom and can address that mailbox (see Claim 4 mailbox stuffing).
- The instructions order the user to add the other party first and compare afterwards: “Ask them for theirs, and run it. Then one thing is left…”. Nothing shown makes the added key unusable, or even marked unverified, until the comparison happens. If `ctx add` grants `SENDER VERIFIED` on arrival, the ceremony is retroactive decoration.
- The snippet never shows `ctx add` displaying a fingerprint at all, nor the entropy/`words` construction. The ceremony’s other half is asserted, not evidenced.

Verdict: **fails; the MITM it advertises protection against survives with a one-field edit.**

## Claim 3 — replay closed, genuine resend arrives: **fails**

Fail-open witness lookup:

```rust
let seen_before = std::fs::read(tmp.join("manifest.json"))
    .ok()
    .map(|bytes| bundle::witness_of(&loaded.manifest.from.key, &bytes))
    .and_then(|w| state::LocalState::load().witnessed(&w))
    .is_some();
```

Any failure — manifest unreadable in the extracted copy, local state unloadable/corrupt — collapses to `seen_before == false` and the replay is staged. The protection that matters most on a damaged machine is the one that silently disables itself.

Other holes:

- The witness covers only manifest bytes: `sha256(from.key || 0x1f || manifest bytes)`. Anything outside `manifest.json` is outside the witness, and any semantically identical but byte-different manifest (re-serialization, field order) is a different witness unless the signature scheme happens to make that impossible — not shown.
- “Already seen” really means “already witnessed,” and the snippet does not show when witnessing is recorded. A bundle that was pulled and rejected, or seen but never accepted/opened, is restageable indefinitely unless that path records the witness. The `dest.exists()` branch covers only “still pending.”
- The check is in the pull path only. The same envelope arriving by file or `ctx lan` does not pass through this code, so “an envelope already seen cannot be re-staged” is broader than the mechanism.
- The check-then-stage sequence is not atomic in anything shown; two pulls of the same envelope race before either records a witness or creates `dest`.
- The “genuine resend” half is redefined, not satisfied. The refusal message admits it:

```rust
println!("    If they meant to send it again, ask them to send it again:");
```

A literal resend — retransmitting the same envelope, which is what retry logic and at-least-once delivery do — is exactly what gets refused. It only “arrives” if the sender composes a *new* message. The comment’s justification (`different created at minimum`) also assumes the resend path regenerates the manifest and that `created` has enough granularity that a fast regeneration differs; neither is shown.

Verdict: **fails in both directions: replays enter on any state/read error, and true retransmission is refused.**

## Claim 4 — relay safe to expose publicly: **fails**

Several good mechanisms exist. They do not add up to the claim.

**Timeouts are per-operation, not per-request.** The comment is honest and damning:

```rust
/// How long a client may take over any single read or write.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
```

A client that sends one byte every 19 seconds never trips a *single-read* timeout. Sixty-four such connections hold every worker slot indefinitely at near-zero cost. The bounded-concurrency cap then becomes the denial-of-service: a small, patient attacker occupies all of it, and legitimate clients get the busy path. No total request deadline, no per-address connection cap is shown.

**The refusal path is unbounded thread creation.** At saturation:

```rust
std::thread::spawn(move || {
    let _ = reply(s, "503 Service Unavailable", r#"{"error":"relay busy, retry"}"#);
});
```

with the comment conceding these threads are “deliberately not counted against the cap.” A connection flood therefore spawns threads without bound — bounded workers, unbounded refusal machinery, same host.

**Worker slots leak on panic.** Slots are counted with a manual increment/decrement, not RAII:

```rust
live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
...
if let Err(e) = handle(s) {
    eprintln!("relay: {e}");
}
live2.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
```

If `handle` panics — and it contains `STATE.lock().unwrap()` and `.as_ref().unwrap()` — the decrement never runs. Panics also poison the global mutex, making subsequent `STATE.lock().unwrap()` calls panic, cascading: enough panics and `live` is stuck at 64 forever, a permanent outage until restart. `BodyReservation` was carefully made panic-safe; the connection counter was not, and it is the scarcer resource.

**Rate limiting is mis-keyed and state-unbounded.**

```rust
let ip = peer.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| peer.to_string());
```

For IPv6 peer strings this cuts at the last colon, i.e. inside the address: distinct IPv6 clients collapse into shared buckets while an attacker rotating within a /64 gets a fresh bucket per address. Every new “address” inserts into `st.rate`, and `retain` only drops entries older than 60s — within a window the map (and the O(n) `retain` scan on every request) grows with attacker-controlled distinct IPs. Behind any proxy or NAT, conversely, everyone shares one bucket and one attacker exhausts it for all. And in the code shown, `over_rate` and `BodyReservation::take` are never called — `handle`’s body is not given, and `do_send(stream, body)` receives the body already fully read. Protections that exist as definitions are credited as protections in force; the call sites that would prove it are absent.

**Quotas bound disk, not availability — and the open send path weaponizes them.** `/send` is deliberately unauthenticated, and the refusal leaks nothing but also prevents nothing:

```rust
if dir_bytes(&box_dir) + incoming > st.limits.mailbox_bytes {
    return reply(stream, "507 Insufficient Storage", r#"{"error":"mailbox is full"}"#);
```

Anyone holding a victim’s share line (Claim 2 says: post it anywhere) can fill that victim’s mailbox with garbage envelopes — `do_send` performs no envelope validation before `std::fs::write` — after which genuine senders are refused. The per-mailbox bound caps the bytes; the attack needs only enough to reach it. The total store cap has the same shape globally, and nothing shown limits how many mailboxes one party can register. Additionally, each send walks the whole store (`read_dir` + `dir_bytes` per mailbox) while holding the global state lock across the filesystem scans and the reply, so every request serializes the relay behind an O(store) walk — an amplification the code comments even flag as letterbox-thinking.

`BodyReservation::take` also does `cur + n` before rejecting, which overflows if an attacker-controlled declared length can approach `usize::MAX`; whether a prior `MAX_BODY` check prevents that is — again — in the unshown `handle`.

Verdict: **fails. Slow-drip exhaustion, unbounded refusal threads, panic slot-leaks with mutex poisoning, broken IPv6 rate keys, and quota-stuffing by design are each sufficient; together they are not a public-internet posture.**

## Claim 5 — TLS verification is real, scheme alone decides: **partly holds in `post`, fails as stated**

The core is genuinely sound in `remote::post`: `webpki_roots` roots, a `ServerName` built from the address host, no custom/dangerous verifier. For a lowercase `https://` address reaching `post`, verification appears real (modulo the doc/code mismatch: the header comment says “system roots,” the code uses baked-in `webpki_roots` — private-CA relays will fail, predictably pushing users toward the plaintext form).

But “the scheme in the address is the only thing that decides it” does not survive the code:

- **The decision is made twice, inconsistently.** `target` trims and then tests `strip_prefix("https://")`, case-sensitively. `ctx connect` separately tests `!addr.starts_with("https://")` on the untrimmed original for its warning. `HTTPS://…`, leading whitespace, etc. classify differently in the two places. `target`’s comment claims “a single place that decides what an address means”; the connect flow is a second decider.
- **The warning comes after the sensitive act.** In `Cmd::Connect`, `register_with_proof(addr, &id, &body)?` runs *before* the `https` note is printed. On a plaintext address, the keys have already been sent to an unverified, impersonable endpoint before the user is told the connection is unverified. “Said here… because this is the moment the choice is made” — it is said after the choice took effect.
- **Registration itself is unverifiable from what’s shown.** The most security-sensitive first contact goes through `register_with_proof`, whose transport is not in the evidence. Claim 5 is proven, at best, for `post`.
- **Truncated TLS responses are accepted.** The client deliberately swallows truncation:

```rust
Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
```

on the stated theory that “the response has its own Content-Length and the body below is checked.” The body below is not checked against any Content-Length — the code splits on `\r\n\r\n` and returns `rest`. A network attacker who cannot forge a certificate can still cut a connection and have a partial body under a `200` status line accepted as the relay’s answer. Verification of the channel does not extend to completeness of what arrived on it.
- Status acceptance is `status.contains(" 200")`, host parsing accepts no rejection of userinfo/path/query in the address, and anything that is not exactly lowercase `https://` — including a bare `relay.example.com` a stranger will naturally type — silently means plaintext on port 7788. Fail-closed in several malformed cases, yes; “the scheme decides it” as a comprehensible user-facing rule, no.

Verdict: **the rustls wiring for well-formed `https://` addresses in `post` looks real; the claim as stated — scheme alone decides, everywhere including registration — fails.**

## Summary

| Claim | Verdict |
|---|---|
| 1. Identity cannot be destroyed | Unsupported; fail-open on any load error |
| 2. Share line safe anywhere | **Fails** — box key outside the fingerprint |
| 3. Replay closed / resend arrives | Fails both directions |
| 4. Relay publicly safe | Fails — multiple independent DoS paths |
| 5. TLS real, scheme decides | Core sound in `post`; claim overbroad, truncation accepted |

Nothing here needs exotic attackers. The Claim 2 substitution and the Claim 4 slow-drip are each a few lines of client code, and both operate against users who follow the printed instructions exactly.
