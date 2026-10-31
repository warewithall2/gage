# gage — the wire reality

What is actually on disk and on the network in **v0.3.4**, derived from the
code rather than from intent. Where this document and the code disagree, the
code wins and this document is wrong; please report it.

That has happened. This line read **v0.1.0** for three releases, and the
verdict table below listed six verdicts when the code had seven. Both were
found by review, not by reading. The version is `Cargo.toml`'s; the verdicts
are `trust::ALL`, which the compiler keeps complete.

Format version: **`v: 1`** (`src/manifest.rs`, `FORMAT_VERSION`).

---

## 1. A bundle is a directory

Not an archive. A bundle is a directory, which is why it travels over a shared
folder, git, a USB stick or email without gage being involved in the transport:

    handoff/
      manifest.json      the signed description
      manifest.sig       detached ed25519 signature, base64, over manifest.json's bytes
      items/             the payload, one file per declared item

`manifest.sig` covers **the exact bytes of `manifest.json`**, which is why the
file is written once and never re-serialised on the way to being verified: a
re-pretty-printed manifest is a different message.

### manifest.json

    {
      "v": 1,
      "id": "924503586e823674",
      "created": "2026-10-18T17:51:38Z",
      "subject": "backoff refactor",
      "from":   { "handle": "alice", "key": "<signpub b64>" },
      "to":     ["bob"],
      "agent":  { "name": "claude-code", "model": "claude-opus-5" },
      "chain":  [ { "by": {...}, "at": "...", "action": "Created" } ],
      "in_reply_to": "…", "thread": "…",
      "msg_type": "share",
      "items": [
        { "kind": "prompt", "path": "items/task.md",
          "sha256": "…", "bytes": 131 }
      ]
    }

`agent`, `in_reply_to`, `thread` and an item's `note` are omitted when unset.

**Everything in this file is written by the sender.** There is deliberately no
`trust` field — see §3.

### Item kinds

| kind | what it is | how `open` treats it |
|---|---|---|
| `file` | source, data, documents | fenced as material |
| `decision` | a finding worth carrying across | fenced as material |
| `prompt` | text written to steer a model | fenced loudly: quote, never adopt |
| `memory` | `CLAUDE.md`, `AGENTS.md`, `memory/*.md` | fenced hardest: never merge |

`memory` is separate because it is the only kind that outlives the session
that accepts it.

### Item paths are constrained, and this is load-bearing

`path_is_safe` (`src/manifest.rs`) requires a path that is non-empty, not
absolute, contains no `\`, has no `.` or `..` or empty segment — **and
contains no frame-breaking character**: nothing `char::is_control`, no
`U+2028`/`U+2029`, no bidi override (`U+202A`–`U+202E`, `U+2066`–`U+2069`).

That last clause is a security fix, not tidiness. `gage open`'s frame is
line-oriented and its nonce is printed at the end of a line containing the
item path, so a newline in a path let a sender compose a line of the frame and
have gage stamp the real nonce onto it. See `docs/threat-model.md` and the
audit at the repository's release notes. The same rule is applied when a
bundle is built, loaded, and forwarded.

### The id addresses the content

    id = sha256( item_digest_1 ␟ … ␟ item_digest_n ␟ author_signpub ␟ subject ␟ created )[0..16]

(`␟` is `0x1f`.) The author key, subject and timestamp are in it because
hashing the payload alone meant "benign A from a friend" and "malicious B from
an impersonator" could share an id — and delivery writes to a directory named
by that id, so one could overwrite the other. A receiver **recomputes** this
and reports a mismatch rather than trusting the field.

A bundle with no `chain` has no author to compute the id from, and is rejected
rather than exempted.

---

## 2. What a receiver checks

`bundle::load` (`src/bundle.rs`), in order:

1. `manifest.sig` verifies over `manifest.json`'s bytes, using
   `ed25519-dalek`'s **`verify_strict`** (which rejects small-order keys).
2. The id recomputes to the id claimed.
3. For each item: the path is safe, no path is declared twice, and the file's
   sha256 matches the manifest.
4. This machine's own **witness** record is consulted (§5).

Any failure in 2 or 3 renders the bundle as *"PAYLOAD DOES NOT MATCH THE
SIGNED MANIFEST"* with **contents withheld**. A signed manifest beside swapped
files does not pass.

---

## 3. Trust is computed by the receiver, never carried

There is no trust field in the manifest, because a `"trust": "verified"` key in
a document the sender controls is decorative.

The verdict is a function of (signature validity, the receiver's own contact
list, the receiver's own witness record):

| verdict | meaning |
|---|---|
| `SENDER VERIFIED` | signature valid, key is on your list, **and a human recorded confirming its word-pairs** |
| `SENDER ON YOUR LIST, UNCONFIRMED` | signature valid and the key is on your list, but nothing here records anybody comparing it — or what was confirmed no longer covers the key on file |
| `SENDER NOT ON YOUR LIST` | signature valid, you have never accepted this key |
| `SENDER REFUSED BEFORE` | signature valid, and you declined this key rather than adding it |
| `SENDER UNVERIFIABLE` | signature missing or invalid |
| `SENDER KEY RETIRED` | signature valid; you saw this bundle *before* you retired that key, so it is still attributable |
| `SENDER KEY REJECTED` | signature valid, but it reached you *after* you retired that key — contents withheld, non-zero exit |
| `ARRIVAL UNRECORDED` | signature valid under a retired key, and no record of this bundle reaching you either side of the retirement — contents withheld |

These eight are distinct states and none is a shorter way of saying another
(asserted by a test, because the viewer classifies them with `startsWith`).
Contents are withheld for `UNVERIFIABLE`, `KEY REJECTED` and `ARRIVAL
UNRECORDED`, and on a digest mismatch; `--reveal` shows them and leaves the
verdict exactly as it was.

**`SENDER VERIFIED` requires a confirmation record, not just an entry on the
list.** Every route onto the list can be driven by software — `gage add` takes
a key out of a chat window, `quickstart` takes a pasted token, the MCP server
takes an agent's say-so — so until a separate record existed, the strongest
verdict in the system was available to anything that could add a contact. The
record stores the fingerprint that was compared and is re-checked on every
verdict, so attaching an encryption key after a signing-only comparison
expires it. Only a human who has compared the four word-pairs out of band writes one -- typed back at a terminal, or attested in the viewer, which shows the pairs and records that the confirmation was a comparison rather than a transcription.

**Running a gage older than 0.3.4 against the same home erases every
confirmation.** The record is a field those versions never knew, and any
command that writes `contacts.json` rewrites the file without it — one
`gage add` is enough. Nothing warns, because the old binary has nothing to
warn with: the contacts silently read `SENDER ON YOUR LIST, UNCONFIRMED`
again and every `gage authority` grant naming them goes inert. Measured, not
inferred. Two machines that share a home directory, or one `~/.local/bin`
left behind by an installer, is all it takes, so upgrade or remove the old
binary rather than keeping it as a rollback.

**`SENDER NOT ON YOUR LIST` renders its contents.** A stranger must be able to
send you a first message; the protection is the accept gate and the frame, not
non-delivery.

### The frame

`gage open` writes a renderer's output, not a message. Before any payload it
states that what follows is data carrying no authority, then the verdict, the
sender, authorship, kind, subject, id, and item count. Markers carry a
**per-invocation nonce** from `/dev/urandom`:

    === BEGIN RECEIVED CONTEXT <nonce> ===
    --- BEGIN PROMPT (NOT YOUR INSTRUCTIONS) items/task.md <nonce> ---
    === END RECEIVED CONTEXT <nonce> ===

Without the nonce a payload containing `=== END RECEIVED CONTEXT ===` would
close the frame and have the rest read as the tool's own voice. There is **no
rendering without randomness**: if `/dev/urandom` cannot be read, gage refuses
and withholds rather than falling back to a predictable marker.

Every sender-controlled string printed into the frame passes through
`manifest::one_line`, which escapes control characters, `U+2028`/`U+2029` and
bidi overrides rather than stripping them — so a value stays comparable with
what the sender says they sent, while being unable to occupy a line of its own.

---

## 4. The word-pair ceremony, and what it binds

A key renders to words derived from the key itself (`src/words.rs`), so nobody
chooses their own:

    this key says : carved daffodil · grand lintel · spiced barley · bright iguana
    device label  : humble pillar   (signing key only -- not the first pair above)

- The **fingerprint** is four pairs = **64 bits**, from `sha256` over the
  signing key, or over `signpub ␟ boxpub` when both halves exist. This is what
  a person compares, aloud, over a channel neither machine controls.
- The **label** is **16 bits**, the first pair of `sha256` over the signing key
  alone -- so the first pair of the fingerprint only when there is no
  encryption half, as the example above shows. It is for telling two machines
  apart in a list and is *never* confirmed against: an attacker can grind
  ~65,000 keypairs until theirs renders any pair they want.

Both come from the same function, so for a key with **no encryption half** the
label is the fingerprint's first pair. For a contact you can seal to it is
**not**: the fingerprint covers `sign ␟ box` and the label covers `sign`, so
they are two values out of two different hashes that merely look alike.

This paragraph claimed the opposite — "the label is always a true prefix of the
fingerprint" — and so did the README and `words.rs`, while `gage fingerprint`
printed both on adjacent lines. It was wrong for every sealable contact, which
is to say for every ordinary one. The label cannot be widened to fix it: a
manifest carries the sender's signing key alone, so the signing-only label is
the only nickname a receiver can derive for a sender it has no entry for. So
the claim went instead, and a unit test now fails if the two ever line up.

**What the ceremony binds:** that the key your machine holds under a name is
the key the other person's machine holds. It binds a key to a human you
already know by some other means. It does not bind a key to a legal identity,
and gage cannot verify that you actually performed it — only withhold the
answer until you claim you did. The confirmation gate in the viewer says so
explicitly, because a key knows its own word-pairs and can quote them in the
very message asking to be trusted.

Covering both halves matters: confirming the signing key alone would let an
attacker substitute the encryption key and still pass the comparison. A bundle
does not carry its sender's encryption key, so a connection request offers only
the signing half — and the viewer labels such a contact verify-only rather than
promising sealing that would silently fail.

---

## 5. Witness records, and replay

A sealed envelope is a file, and anyone who can reach the relay — including the
relay — can hand the same one over twice. A replayed instruction is a real
instruction that was already carried out.

    witness = sha256( from_signpub ␟ manifest_bytes )

This identifies *this manifest*, not merely this id, so a sender resending in
good faith is unaffected (a new message has a new `created`, so a new witness).
`gage pull` refuses a bundle whose witness it has already recorded and writes a
`duplicate` journal entry — the one event in the log that records something the
machine declined to do.

The witness is also what places a bundle either side of a key retirement,
using this machine's own record rather than any date the sender wrote.

---

## 6. Authority: scoped, receiver-owned, bounded

`~/.gage/authority` is a file the human writes. **No gage command writes it**,
deliberately: a `gage allow` would be reachable by prompt injection, letting an
agent that was talked into running it grant itself permission to obey whatever
talked it into it.

    allow codex review-request
    allow dana question in-reply-only
    allow <signpub> any                      # any message KIND, not any action
    allow sndr answer auto-accept max-exchanges 4

Rules enforced by `src/authority.rs`:

1. A grant is consulted **only** after `SENDER VERIFIED`. Any other verdict and
   no grant is read at all — including `SENDER ON YOUR LIST, UNCONFIRMED`,
   which is where a key an agent added by itself lands. A grant on a key
   nobody ever checked is the same mistake as a grant on a bad signature, one
   step further back.

   Grants are matched by **name**, and a name is yours to re-use, so
   `trust::add_contact` refuses to put a key under a name you retired a
   different key under unless you pass `--reinstate`. Without that, retiring
   `alice` and adding somebody else as `alice` handed them everything `alice`
   was allowed to do, silently.
2. A **malformed file grants nothing** — one unusable line voids the whole
   file, because the other direction lets a typo on line 2 widen line 3.
3. The scope comes from the message **kind**, via `MsgType::granted_scope`,
   never from the message: `question` → *"answer it, in a reply"*;
   `review-request` → *"read what this bundle encloses and report findings on
   it"*. `share`, `answer` and `ack` have no scope and cannot be granted one.
   Editing files, running commands, committing, pushing, sending anything,
   messaging third parties and touching secrets are listed as never covered,
   whatever the payload asks.
4. The rendered grant line carries the frame's nonce. That raises the bar
   against a copied static string; it does not make a grant unforgeable,
   because the reader is a model that can be argued past a marker, and the
   frame says so rather than leaning on it.

**Expiry** is deliberately absent: it cannot use a clock for the same reason
key retirement cannot, and "expires after N observed messages" is a strange
thing to ask a person to write. A file you edit is already revocable by
editing it.

### Unattended acceptance

`gage watch --auto-accept` needs four conditions at once: the watcher was
started with the flag; a grant says `auto-accept` (which cannot be written
without `max-exchanges N`, and never against `any`); the bundle answers
something this machine sent; and the thread's budget is unspent.

The budget is **per thread, keyed on the parent found in this machine's own
`sent/`** — not on the sender-written `thread` field, because a granted sender
could otherwise answer the same parent under three different thread ids and
collect a full budget each time. The journal entry *is* the budget; there is no
counter file, and the count is retaken inside the journal lock because counting
and then appending is a race two watchers can both win.

---

## 7. Sealing, and the relay protocol

Nothing reaches a relay unsealed.

    gage seal ./handoff --to dana --out handoff.gageb
    gage unseal handoff.gageb                    # receive into inbox/pending
    gage unseal handoff.gageb --out ./incoming   # inspect, recording nothing

`unseal` with no `--out` stages the bundle through `stage_envelope`, the same
function `gage pull` uses, so a handed-over file clears the same gates and
earns the same arrival record as relay mail. With `--out` it writes the files
and records nothing; see §4 on why only delivery may write a witness.

A sealed box is `crypto_box` (**X25519 + XSalsa20-Poly1305**) to the
recipient's public key with a fresh ephemeral keypair. The envelope has three
fields and no more:

    { "v": 1, "to_box": "<recipient X25519 pub, b64>", "ct": "<ciphertext, b64>" }

So a relay learns **a recipient key, a size and a time** — not the subject, the
filenames, the sender, or the payload. Authorship is proved by the signature
*inside* the bundle instead, which is why the transport can be anonymous and
the relay never becomes an authority on who said what.

### Endpoints

All `POST` with JSON bodies, except where noted (`src/relay.rs`):

| endpoint | purpose |
|---|---|
| `/register` | bind a mailbox to a signing key, proving possession of the box secret |
| `/send` | hand over a sealed envelope for a mailbox. **No authentication** |
| `/challenge` | get a random nonce for a mailbox |
| `/fetch` | collect, with an ed25519 signature over that nonce |
| `GET /health` | `{"ok":true}` |
| `GET /` | a human-readable page |

**Registration** seals a random nonce to the claimed box key and commits the
binding only when the caller returns that nonce. Without this, a squatter could
register someone else's published box key against their own signing key, and
first-registration-wins would lock the owner out permanently. Pending claims
are keyed by the pair, so a squatter blocks nobody. First registration of a
mailbox wins; rebinding to a different signing key is refused.

**Fetching** requires proof of key *possession*, not a key name — anyone who
has seen a `gage whoami` line knows your public key. A challenge is consumed on
first use, bound to one mailbox, and expires after 600s.

**`/send` takes no authentication on purpose**, because a stranger must be able
to send you a first message. The bound is quotas instead: bytes and envelopes
per mailbox, a whole-store cap as the backstop, and a per-address request rate.
A full mailbox is refused with *"mailbox is full"* and nothing about who filled
it — a letterbox does not report its senders to whoever knocks. The recipient
can still collect what did arrive.

### Receipt names

A stored envelope is named:

    <unix-millis>-<sha256(envelope)[0..12]>.gageb

This is **a storage name and a receipt string, nothing more**. The collecting
client takes a bundle's real id from its signed manifest, never from this
filename — which is why the writer could be renamed from `.ctxb` to `.gageb`
safely. The fetch path lists a mailbox **without filtering on extension**, so
envelopes stored under the older name still collect; adding a filter there
would strand them silently.

### Transport security

    gage join https://relay.example.com    # certificate verified
    gage join 100.64.0.1:7788              # no TLS: a tailnet or loopback test

The scheme decides, and the address is written by a person, so the choice is
visible rather than defaulted. The payload is sealed either way; TLS protects
the **metadata** (`/send` carries the recipient's box key in the clear, so the
path learns who you write to, how often and how big) and gives the server an
identity, without which anything that can answer for that address can accept
your push, return `{"ok":true}` and drop it. Verification uses a compiled-in
copy of Mozilla's root list, not the system store, so a relay behind a private
CA fails loudly rather than silently working.

---

## 7a. Identity backup (unreleased)

Opt-in, and on master rather than in v0.1.0. Nothing creates one unless a
person runs the command.

    gage export-identity --out <file>     # prompts for a passphrase, twice
    gage restore-identity <file>          # prompts once, prints the fingerprint

The file is JSON with a readable header and one encrypted field:

    {
      "fmt": "gage-identity-backup",
      "v": 1,
      "kdf":    { "name": "argon2id", "m": 65536, "t": 3, "p": 1,
                  "salt": "<b64, 16 bytes, fresh per export>" },
      "cipher": { "name": "xchacha20poly1305",
                  "nonce": "<b64, 24 bytes, fresh per export>" },
      "ct": "<b64 ciphertext>"
    }

- **KDF:** Argon2id, 64 MiB / 3 passes / 1 lane, with the parameters in the
  file so they can be raised later without orphaning old backups.
- **AEAD:** XChaCha20-Poly1305, with the serialised header as associated data.
  Every header field today also feeds key derivation or is refused by name, so
  the AAD is not what makes an edit fail; it authenticates the header as a
  whole, so a field added later cannot end up unauthenticated.
- **Plaintext:** `{ "v": 1, "handle": …, "identity_key": … }`, where
  `identity_key` is the **exact bytes of `identity.key`** — which already holds
  both keypairs and the retired-key records. Retired records are in scope
  because `KEY RETIRED` versus `KEY REJECTED` depends on knowing what was
  retired and when.
- **Not in the file:** contacts, journal, inbox, sent, state, relay address —
  and nothing identifying. No handle, fingerprint or label outside the
  ciphertext, because a backup should not announce whose it is.
- The file is written `0600` via a temp file and rename, and export refuses to
  overwrite an existing file.

**Restore semantics.** Into a home with no identity by default; an occupied
home is refused with both fingerprints printed and nothing written. `--replace`
additionally requires typing the word `replace`, and moves the existing key
aside rather than deleting it. The fingerprint of the backup's contents is
computed and shown **before** anything is written. A wrong passphrase and an
altered file are one event to Poly1305 and produce one message and no
side effects. An unknown `fmt` or `v` is refused by name rather than parsed
hopefully.

A restore brings back the key, not the witness record: see
`docs/threat-model.md`. Design rationale and the options not taken are in
`docs/adr-identity-recovery.md`.

---

## 8. Format versioning

`v` is `1` everywhere — one integer on the manifest and one on the envelope.
There is no negotiation and no range: a reader that does not understand a
version should refuse rather than guess.

Honest statement of where this stands: **v0.1.0 has not yet had to change a
format, so the versioning has never been exercised.** The fields that exist are
tolerant in one specific direction — `agent`, `in_reply_to`, `thread` and
`note` are `#[serde(default)]` and omitted when absent, and `msg_type` defaults
— so adding an optional field is possible without a version bump. Anything that
changes the meaning of a signed field would need `v: 2` and an explicit
decision about what a `v: 1` reader does, and that decision has not been made.

---

## Where the code surprised me

Written while deriving this document, and worth saying rather than smoothing
over:

- **`.gageb` is not a bundle format.** The name reads like one, and this
  document originally described it as the sealed-bundle file extension. It is
  only the relay's *stored envelope* filename, plus whatever you happen to pass
  to `seal --out`. Nothing parses it, and `seal`/`unseal` impose no extension
  at all.
- **An unlisted sender's contents are rendered.** Reasonable on reflection —
  the accept gate and the frame are the protection, not non-delivery — but the
  prose around "behind the accept gate" reads as though more is withheld than
  is.
- **The manifest id covers the author key, subject and timestamp**, not just
  the payload digests, despite the doc comment on the field saying "sha256 over
  the item digests, so the same payload gets the same id regardless of who
  sends it or when." The comment is stale; the code and the reason for it (id
  collisions overwriting a pending bundle) are right.
