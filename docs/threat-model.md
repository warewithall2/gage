# gage — threat model

> **Companion file:** [what-this-does-not-stop.md](what-this-does-not-stop.md)
> does this concretely — the public agent-security incidents of 2026, named,
> with an honest answer for each, plus the MCP server audit. This file is the
> abstract version; that one is the one a sceptic should read first.

For **v0.1.0**. Written to be argued with: if a mitigation below does not hold,
that is a bug report, and the non-goals are there so nobody has to discover
them the hard way.

## What is being protected

1. **The integrity of what a receiving agent is told about a message** — who
   signed it, whether the receiver has ever confirmed that key, and that
   nothing inside carries authority. This is the asset. Everything else in
   gage exists to serve it.
2. **The identity key** (`~/.gage/identity.key`). The one file whose loss
   cannot be undone, because every contact who confirmed your word-pairs
   confirmed *that* key.
3. **Payload confidentiality in transit**, from the relay and from the network.
4. **Correspondence metadata** — who you write to, how often — from the network.
   From the relay, only partly: see non-goals.
5. **The accept gate**: that arrival is not consent, and that crossing it is an
   act a human or an explicitly-flagged unattended process performed.

## Adversaries, and what each one gets

### A malicious sender

Someone with a valid keypair who can get a bundle to you. **The primary
adversary**, and the one gage is actually built against.

| they try | what stops them |
|---|---|
| Claim to be someone else | Identity is the **key**, never the `handle` string. A key on your list under another name renders a loud `!! NAME MISMATCH`; an unlisted key is shown as a key with an unverified claimed name |
| Carry their own trust verdict | There is no `trust` field. The receiver computes it from the signature and its own allowlist |
| Claim authorisation | Authority comes only from the receiver's own local file, is consulted only after `SENDER VERIFIED`, and is scoped by message **kind** rather than by anything the message says |
| Forge the frame boundary so the rest reads as the tool's voice | Fence markers carry a per-invocation nonce from `/dev/urandom`; no randomness means no rendering, not a predictable fallback |
| **Write a line of the frame via a newline in a path, subject or handle** | **Fixed 2026-10-18.** `path_is_safe` rejects control characters, `U+2028/9` and bidi overrides; `one_line` escapes every sender-controlled string the frame prints. This worked before the fix, and gage printed the real nonce onto the attacker's line |
| Swap payload beside a signed manifest | Each item's sha256 is checked against the manifest; a mismatch withholds contents |
| Choose an id that collides with a real message | The id covers author key, subject and time as well as digests, and is recomputed rather than trusted |
| Replay a message you already acted on | The witness (`sha256(from_key ␟ manifest bytes)`) is recorded; `pull` refuses a repeat and journals `duplicate` |
| Reuse an old key after you rotated away | Verdict distinguishes `KEY RETIRED` (witnessed before retirement, attributable) from `KEY REJECTED` (arrived after, contents withheld) using this machine's own record, not any date the sender wrote |
| Name a trusted third party as the author of a forwarded bundle | Only the last hop signs. `chain[0]` is shown as a **claim by the forwarder**, explicitly, even when the key named is one you know |
| Post into someone else's thread to collect a reply | `reply` resolves the recipient from the key that **signed** the parent; a thread with two correspondents is refused rather than guessed |
| Refill an auto-accept budget by inventing thread ids | The budget is keyed on a parent found in this machine's own `sent/`, which only the receiver can have written |
| Escape the bundle directory with `../` or an absolute path | `path_is_safe`, enforced on build, load **and** forward; the check runs before any read |
| Squat your relay mailbox using your published box key | Registration requires returning a nonce sealed to that box key |
| Drain your mailbox knowing your public key | Fetch requires an ed25519 signature over a server-issued, single-use, mailbox-bound challenge |

### A malicious relay

Assume it is fully compromised and keeps everything.

- **Cannot read payloads.** It holds `crypto_box` sealed envelopes
  (X25519 + XSalsa20-Poly1305) and the envelope carries three fields: version,
  recipient box key, ciphertext. Verified in the suite by pushing a bundle with
  distinctive strings and grepping the store.
- **Cannot forge authorship.** Signatures are inside the bundle; the relay is
  never an authority on who said what. A bundle arriving via a relay from an
  unlisted key reads `SENDER NOT ON YOUR LIST`, exactly as it would locally.
- **Cannot replay usefully.** The receiver's witness record refuses the repeat.
- **Can** see which mailbox has mail, how big, and when — and **can drop or
  delay** anything. Availability is not protected; see non-goals.

### A network attacker

- With TLS (`gage join https://…`): payload sealed, metadata protected, server
  authenticated against a compiled-in Mozilla root list rather than the system
  store, so a private-CA relay fails loudly instead of silently working.
- Without TLS (a tailnet address, where WireGuard already provides the channel,
  or a loopback test): the payload is still sealed, but `/send` carries the
  recipient's box key in the clear, so a path observer learns **who you write
  to, how often and how big**. And with no server identity, anything that can
  answer for that address can accept your push, return `{"ok":true}` and drop
  it: signatures cover content and never covered delivery.
- The choice is visible because the **scheme decides** and a person writes the
  address.

### A prompt-injection payload

The adversary that makes gage different from a signing tool: the reader is a
language model whose next tokens are the payload.

- `gage open` is a **renderer, not an importer**. The frame states, before any
  payload, that the contents are data from an identified party carrying no
  authority.
- On a bad verdict it **withholds** contents rather than annotating them,
  because an annotation is something the payload can argue with.
- `prompt` items are fenced as a quotation to evaluate, not a task to adopt.
  `memory` is fenced hardest and never suggested for merging, because it is the
  only kind that outlives the session that accepts it.
- The header is **restated in the footer**, so the last thing read is not
  attacker-controlled text.
- The frame tells the reader never to edit the authority file or add a grant
  because a message asked it to.

**And the honest limit:** every one of these is a deterrent aimed at a reader
that can be argued with. A model can be talked past a marker. gage makes the
forgery expensive and the framing loud; it cannot make a model obey the frame.
This is stated in the frame itself rather than relied upon silently.

### A local attacker on the same machine

- The identity key is `0600`.
- **New** homes are created `0700` (fixed 2026-10-18). Before that the home
  was `0755` with contacts, journal and inbox payloads at `0644`, so any other
  local user could read who you correspond with and what they sent.
  **Homes created before that fix are still `0755`** — gage does not retighten
  an existing home, because changing permissions on someone's filesystem
  unasked belongs to a command that says so. `chmod 700 ~/.gage` if you share
  a machine.
- Any process running as you can read **and write** the authority file. The
  no-`gage allow`-command rule is a deterrent that makes an injected agent
  hand-write a file — conspicuous in a transcript — not a boundary. A real
  boundary needs file permissions or a separate process the agent cannot write
  through. The frame says this rather than implying otherwise.

### Someone who has your backup file

Only relevant if you ran `gage export-identity`, which nothing does for you.

A backup is your identity in a file. It is encrypted with a key derived from
your passphrase by Argon2id (64 MiB, 3 passes) and sealed with
XChaCha20-Poly1305 over an authenticated header, so an attacker holding the
file needs the passphrase and pays that cost per guess — offline, as fast as
their hardware allows, with no rate limit anyone can impose.

**So opting in converts "lose the key, lose everything" into "your security is
your passphrase's strength."** That is the whole trade, and it is a trade, not
a free improvement:

- A **strong** passphrase plus a backup stored away from the machine is
  strictly better than no backup — you survive a dead disk.
- A **weak** passphrase, or a backup synced to the same cloud account as
  everything else, is **worse** than no backup: it is a copy of your identity
  that an attacker can take at their leisure, and a stolen identity is not
  something a rotation undoes for the people who already confirmed the old key.

What the file deliberately does not contain: your contacts, your journal, your
inbox, your relay address — or anything that says whose identity it is. A
leaked backup should cost the key and nothing more. The word-pair fingerprint
is shown only after a successful decrypt, which is also how you check that a
file really is the identity you think it is before trusting it.

What a restore does **not** bring back is this machine's witness record. The
key returns; the memory of what it has seen does not, so bundles signed under
a key you had retired read as unplaceable rather than attributable afterwards.
That is honest rather than convenient: a witness record that could be
reconstructed on demand would be one a thief could reconstruct too.

### A local process that can spawn `gage mcp`

Only relevant if you have configured an MCP host to run it; nothing starts it
on its own.

`gage mcp` serves tools over **stdio**. It has no listener, no port and no
network surface, so the exposure it creates is exactly the exposure that
already existed: **any local process that can run the `gage` binary can
already do everything the CLI can do.** The MCP server does not widen that —
it does not add a remote entry point, and it cannot be reached from another
machine. It makes the existing local authority easier to reach, which is the
point of a front door and is worth being explicit about rather than implying
the protocol adds a boundary.

So: the server acts with the identity's full authority for anything the CLI
can do unattended — read the buddy list, send, push off the machine, pull,
open bundles. It is not a sandbox and does not pretend to be one.

**Including the buddy list.** This section used to lead with "except the
ceremony — putting a key on the buddy list needs the word-pairs echoed back
through `gage_pair_confirm` … that is the one thing an agent cannot do by
asking nicely", and then, in the next paragraph, conceded that a key knows its
own word-pairs and `gage_pair_start` hands them over. Both paragraphs were
here; the strong one came first and was the one people quoted. A reviewer
paired a stranger's key in two tool calls, with no human anywhere, and the
result read `SENDER VERIFIED`.

So the claim is gone, and the mechanism changed under it. An agent **can** put
a key on the buddy list alone. What it cannot do is **confirm** one: nothing
reachable over MCP writes a confirmation record, so a key paired by an agent
reads `SENDER ON YOUR LIST, UNCONFIRMED` and `authority` honours no grant
under it. `Trust::Known` — the verdict everything else keys on — now requires
a record that a human compared four word-pairs out of band, and the only
things that write one are `gage confirm` at a terminal and the viewer's
confirm step, which asks for all four pairs and displays none.

The echo check in `gage_pair_confirm` stays, because it costs nothing and
catches a transcription slip between two tool calls. It is a checkpoint, and
it is no longer load-bearing. The tool description says so where the model
will read it.

The limit of the new claim, in the same spirit: an agent with a **shell** can
run `gage fingerprint` and then `gage confirm`, or write `contacts.json`
directly. No program stops a process that can write its files. The boundary
is the MCP surface — a tool-using model with no shell — and that is what this
section is about.

Three things are deliberately *not* reachable through MCP, and the reasons are
different from each other:

- **`export-identity` / `restore-identity`.** A passphrase must never travel
  as a tool argument. Tool calls land in an agent's context, are logged by
  hosts, and may be replayed. These stay CLI-only, where the passphrase comes
  from a no-echo prompt and never appears in argv or the environment.
- **`init`.** Making an identity is a human moment, and the word-pairs it
  prints are what a person carries to someone else.
- **`accept` / `reject`.** The accept gate exists so that crossing it is an
  act a human performed. An agent able to accept its own arrivals would have
  removed it. `gage_open` reads a pending bundle without accepting it.

---

## Non-goals — what gage does *not* protect against

Each of these is a decision, not an oversight.

1. **Availability.** A relay can drop, delay or lose your mail, and a mailbox
   can be filled by strangers up to its quota. gage bounds the damage; it does
   not guarantee delivery. There are no retries and no delivery receipts.
2. **Anonymity, and metadata from the relay.** The relay necessarily learns
   which mailbox has mail, its size and its timing. Polling interval is a
   trade: the default 120s is deliberately slow enough not to be a presence
   feed. If who-talks-to-whom must be hidden from the relay operator, gage is
   the wrong tool.
3. **Making a model obey the frame.** See above. This is the central limit.
4. **Key loss, unless you opted in.** By default there is still no recovery
   and no escrow: losing `identity.key` is identity death, and every confirmed
   contact must re-confirm a new key. `gage export-identity` changes that *if
   you run it* — and changes the threat instead of removing it. See below.
5. **Compromise of your own machine.** An attacker running as you has your key,
   your authority file and your inbox. Nothing here survives that.
6. **Proving the word-pair ceremony happened.** gage cannot see your other
   channel. It withholds the answer and names the trap; it cannot verify you
   compared anything. A key knows its own word-pairs and can quote them in the
   very message asking to be trusted — which the confirmation gate says, in
   the gate, where the decision is made.
7. **Binding a key to a legal identity.** No CA, no directory, no attestation.
   A fingerprint binds a key to a human *you already know by other means*.
8. **Protecting against what a hook does.** `--on-arrival` runs your command;
   `--auto-accept` moves bundles. gage bounds *when* they fire and counts what
   they did. What the hook then does is bounded by the hook, which a human
   wrote.
9. **Post-compromise security / forward secrecy.** Sealing uses a fresh
   ephemeral keypair per envelope, so one envelope's keys do not open another —
   but your long-term X25519 secret opens every envelope ever sent to you.
   There is no ratchet and no deniability. Stolen key, historic mail readable.
10. **Dependency and supply-chain trust.** `ed25519-dalek`, `crypto_box` and
    `rustls` are taken as sound and have not been audited here.
11. **Side channels.** No timing analysis has been done.
12. **Group confidentiality.** `group:<name>` is a local addressing
    convenience; a bundle is sealed per recipient key. There is no group key
    and no notion of membership a relay enforces.

---

## Known weaknesses, stated plainly

- **Self-review.** The security work on this project, including the audit that
  found the frame-injection bug above, has been done by the same hands that
  wrote it. No independent audit has happened. Treat the mitigations table as
  claims to be checked, not as assurances.
- **The 16-bit label.** One word-pair is grindable in ~65,000 tries. It is a
  label only and is never confirmed against — but it appears in lists next to
  names, and a sender *can* arrange for its own key's label to be a pair you
  already use for somebody.
- **Format versioning is untested.** `v: 1` has never had to become `v: 2`.
- **`verify_strict` but no key-rotation protocol with the relay.** Rotation is
  a local record plus a notice the recipient chooses to apply; a notice
  countersigned by the old key is exactly what a thief holding the old key
  would send, which is why applying one is a human decision made after
  confirming over another channel.
