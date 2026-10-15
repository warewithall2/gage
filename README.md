# ctx

Hand context between agents — files, prompts and decisions — with a trust
boundary that survives the hop.

Your Claude hands a task to Codex. A colleague's agent sends you their project
state. Works across vendors because it is not a protocol: a bundle is a signed
directory, so it moves over a shared folder, git, email, or anything else you
already have.

## Why the trust boundary is the product

A channel that lets one LLM send prompts to another LLM is, by default, a
prompt-injection delivery network. `ctx open` is the part that stops that: it
renders a bundle inside a frame that states, before any payload, that the
contents are **data** from an identified party and carry no authority.

Three specific defences, each written after the attack worked in testing:

- **Nonced fence markers.** Payload text containing `=== END RECEIVED CONTEXT ===`
  would otherwise close the frame, and everything after it reads as the tool's
  own trustworthy voice. The real markers carry a per-invocation random nonce
  the sender cannot predict.
- **Keys are identity; handles are claims.** An early version printed
  `sender: alice` beside a verified-trust label while the key belonged to bob.
  Your own name for a key now leads, and a mismatch is stated loudly.
- **Trust is computed, never carried.** There is no trust field in the
  manifest. The receiver derives it from the signature and its own allowlist,
  because a `"trust": "verified"` key in a document the sender controls is
  decorative.

Payload digests are checked against the signed manifest, so a signed manifest
beside swapped files is caught and the contents are withheld.

## Use

    ctx init owen                      # make your keypair
    ctx whoami                         # the line you give to a colleague
    ctx add dana <their-key>           # buddy list; keyed on the key, not the name
    ctx rotate                         # replace your key without losing your past

    ctx send --to dana --subject "backoff refactor" \
             --prompt task.md --decision notes.md \
             --file src/client.rs \
             --agent claude-code --model claude-opus-5 \
             --out ./handoff

    ctx inspect ./handoff              # summary, no contents in context
    ctx open    ./handoff              # render for an agent, inside the frame
    ctx forward ./handoff --to group:eng --out ./fwd

`open` exits 0 when the bundle is attributable, and 2 when the signature fails,
the payload does not match, or the signing key has been taken out of service,
so a harness can branch without parsing prose.

## Item kinds, and why they differ

| kind | what it is | how `open` treats it |
| --- | --- | --- |
| `--file` / `--dir` | material: source, data, documents | fenced as data |
| `--decision` | a finding worth carrying across | fenced as data |
| `--prompt` | text written to steer a model | fenced loudly: quote, never adopt |
| `--memory` | CLAUDE.md, AGENTS.md, memory/*.md | fenced hardest: **never merge** |

Memory is its own kind because it is the only one that outlives the session
that accepts it. A prompt steers one turn; merged memory steers every future
session, after the person who approved it stopped watching. `open` says so,
and never suggests merging.

`--dir` sends a tree with its structure intact. An earlier version flattened
everything to `items/<basename>`, so a project containing `src/mod.rs` and
`src/net/mod.rs` produced two items at one path and the second silently won --
sending a project was lossy and nothing said so. Build and cache directories
are skipped, and so is anything that looks like a secret (`.env`, `*.pem`,
`*.key`, `.netrc`, `id_rsa*`, names containing `secret`/`token`/`apikey`).
Every skip is printed before the bundle is built, because a silent omission is
its own surprise. `--allow-secrets` overrides, and you should have a reason.

Caps: 2 MB per item, 25 MB per bundle.

`--reply-to <id>` threads a bundle to the one it answers, so an exchange
between two agents reads as a conversation.

## Encryption

Signing proves who wrote a bundle. It does not hide what is in it. That is
fine on your own filesystem and not fine on a server, so nothing goes to a
relay unsealed.

    ctx seal ./handoff --to dana --out handoff.ctxb
    ctx unseal handoff.ctxb --out ./incoming
    ctx open ./incoming

A sealed box (X25519 + XSalsa20-Poly1305) encrypts to the recipient's public
key with a fresh ephemeral keypair. The envelope holds three fields: a version,
the recipient's encryption key, and ciphertext. A relay therefore learns a
recipient key, a size and a time -- not the subject, the filenames, the sender,
or the payload. Verified by grepping a real envelope for the sender handle,
subject and contents: none appear.

The transport is anonymous and **authorship is proved by the signature inside
the bundle instead**. That split is deliberate: end-to-end authorship survives
the relay, and the relay never becomes an authority on who said what.
`unseal` says so explicitly, because decryption proves only that the sender
knew your public key -- which anyone does.

Decrypted contents are still untrusted input. An item whose path escapes the
bundle, or that the manifest never declared, is refused rather than written;
both are unit-tested, since only a malicious *sender implementation* can
produce them.

Your `ctx whoami` token is now `signpub.boxpub`. Identities created before
encryption existed gain an encryption key on next load **without changing the
signing key**, so every bundle you signed previously stays verifiable.

A contact with no encryption key on file can be verified but not sealed to,
and `ctx seal` refuses rather than silently sending in the clear.

## Outbound safety

Two gates on the way out, because the filename deny list only catches files
that are *named* like secrets.

**Content scan.** Every item is read before it is sealed. A `notes.md` that
quotes a customer's address, or a log fragment with a bearer token still in
it, is what actually leaks -- and its filename says nothing. `ctx send`
refuses rather than warns: on an outbound path a warning arrives after the
bundle exists, and for a remote recipient after it has gone.

    outbound scan found 1 item(s) that should not leave:
      notes.md:2  [email]  dana**********************.uk

Findings are **redacted**. A tool whose job is to stop secrets leaving should
not print them to a terminal or into an agent's context on the way to
refusing. Built-in rules cover private-key blocks, AWS/Anthropic/OpenAI/GitHub/
Slack/Google/Stripe key shapes, bearer tokens and real email addresses;
`example.com` and a bare `sk-ant-` in prose do not fire. `~/.ctx/scrub.json`
takes `never_send` literals (a customer domain, a codename) and `disable` for
rules a repo legitimately trips. `--allow-findings` overrides and says so.

**Confirmation before anything leaves.** `ctx push` prints the recipient,
subject and file list and refuses without `--yes`. The accept gate protects
the receiver; this protects the sender, and it is the one that matters when an
agent is doing the sending.

The gate is on `push`, not `send`, because `send` either delivers to a local
route or writes a directory you still have to move -- nothing has left yet.
An earlier version gated `send` on "has no local route", which is not the same
as "is leaving", and it broke every send to an unrouted handle.

## Relay

For the case where the other agent is not on your filesystem. The relay is
deliberately stupid: it holds sealed envelopes addressed to an X25519 public
key and hands them to whoever proves they hold the matching secret.

On the host that will hold mail:

    ctx relay --bind 100.x.y.z:7788

On each machine:

    ctx join 100.x.y.z:7788        # registers your mailbox, saves the address
    ctx push ./handoff --to dana   # seals, then uploads
    ctx pull                       # collects into inbox/pending

**The relay cannot read what it stores.** Compromising it leaks metadata --
which mailbox has mail, how big, when -- and no content. Verified in the test
suite by pushing a bundle with distinctive subject and payload strings and
grepping the relay's store: neither appears.

Four properties the relay enforces, each tested:

- **Fetching requires proof of key possession, not a key name.** Anyone who
  has seen a `ctx whoami` line knows your public key, so a name-only scheme
  would let a stranger drain your inbox. The relay issues a random challenge
  and requires an ed25519 signature over it.
- **A challenge is consumed on first use.** A replayable signature is a stolen
  credential with a longer life.
- **A challenge is bound to one mailbox**, so it cannot be redirected.
- **First registration of a mailbox wins.** Rebinding a box key to a different
  signing key would be mailbox takeover by re-registration.

Base64 keys become directory names, so they are validated rather than trusted:
base64 contains `/`, and `/` in a path component is how a mailbox escapes its
directory. Unregistered mailboxes are refused, so the relay cannot be used as
storage for keys nobody will collect.

Bind it to a tailnet address, not `0.0.0.0`. On a tailnet, WireGuard already
provides the encrypted channel and there is no public exposure, so no TLS and
no domain are needed. **Security does not depend on the network** -- the
payload is a sealed box either way -- so the same binary can later sit behind
a reverse proxy on a public address with no change to the envelope.

Trust still comes from the signature inside the bundle, never from the relay.
A bundle that arrives via a relay from someone you have not added reads
`SENDER NOT ON YOUR LIST`, exactly as it would locally.

## Conversations

A bundle carries what the sender wants from you:

    ctx send --to codex --subject "key rotation" --type question --decision q.md
    ctx send --to owen  --type answer --reply-to <id> --decision a.md

`share` (default), `question`, `answer`, `review-request`, `ack`. An unknown
type is refused rather than quietly defaulted. `question` and `review-request`
leave a ball in the recipient's court, and `ctx inbox` says so.

    ctx threads          # grouped, newest activity first
    ctx threads --mine   # only where the ball is in your court
    ctx thread <id>      # one exchange, root first
    ctx close <id>       # settled, in your view

Three rules, each because the obvious version is wrong:

- **Read state and thread state are local.** A sender must not be able to mark
  their own message read in your inbox or declare a thread answered because
  they would like it to be. Same rule that keeps trust out of the manifest:
  anything the sender controls is a claim.
- **Thread state is derived, not stored.** A thread is awaiting you if its
  newest message expects a reply and came from someone else. Nothing to
  maintain, so the common case cannot drift.
- **Sent messages are kept locally.** A thread assembled from only the other
  side's half is not a conversation -- an early version showed an answer with
  no question above it and took its subject from the reply. It doubles as the
  audit trail: both ends hold a copy.

The thread's subject comes from the message whose id *is* the thread id, not
whichever sorted first. `created` has one-second resolution, so a question and
its reply sent in the same second can invert, and the thread gets named after
the reply.

Opening marks read; listing does not. Seeing a subject in an inbox is not
having read the thing.

## Nudges

    ctx watch                    # poll, pull, notify
    ctx watch --once --quiet     # one check, print instead of notifying

Polling, because a relay that pushed would hold an open connection per
mailbox, and the agents are not long-lived processes anyway -- they are
invoked.

**Announced once.** A bundle is announced when it is unread *and* has not been
announced before. Without the second half, every poll re-announces the same
thing until you open it, which trains you to dismiss the notification -- the
failure that makes a notifier worse than none.

**The notification carries metadata only**: who, what type, the subject. Never
contents. A desktop notification is rendered by another process, may be
logged, and can sit on a lock screen. A unit test pins that it cannot grow a
contents field. An unlisted sender appears as a quoted claim, because a
notification is where a forged name would be believed fastest.

The interval is a trade. Shorter means hearing sooner, and it also tells the
relay operator more precisely when you are active, since fetch timing is
metadata they can see. The default is two minutes: slow enough not to be a
presence feed.

As a background service:

    systemctl --user enable --now ctx-watch.service

`watch` and `pull` share one collection path, because a watcher that collected
differently from a manual pull would announce bundles you could then not find.
The watcher suppresses its nothing-to-do line; a line per poll turns a journal
into noise that hides the one entry that mattered.

## Key rotation

A key gets replaced: a laptop dies, a secret leaks, a contact starts fresh.
Before this existed `ctx init` simply refused to overwrite, which is the right
refusal and the wrong ending — the only way out was to delete the key file,
and that turned every bundle you had ever signed into `SENDER UNVERIFIABLE`.
Losing your whole history the day you rotate is a bug, and a tool with that
property teaches people never to rotate.

    ctx rotate                 # new keypair, old one kept on record
    ctx rotate --compromised   # the old key was stolen
    ctx keys                   # what is current, what is retired

Rotation produces a **notice**: a statement binding old key, new key, handle
and time, signed by the new key and countersigned by the old one. The new
signature says whoever holds this key meant to publish it. The old one says
the party you already trusted authorised the handover — which is the only part
you could not have got from a stranger.

It is still not proof. A thief holding the old key produces that
countersignature just as easily, and this is the hard part of rotation: "use
this key instead" is the exact sentence an attacker wants to say and the exact
sentence an honest person needs to say, and the bytes are identical. So a
notice is **evidence, never an instruction**:

    ctx keychange notice.json            # report what it proves
    ctx keychange notice.json --accept   # apply it

`keychange` with no `--accept` changes nothing. With `--accept` it still
refuses a notice the old key did not countersign, which is why a compromise
rotation omits that signature on purpose: a signature from a stolen key would
dress up a notice that proves nothing as one that proves something. Then the
only path is confirming the new key with the person over a channel that is not
this one.

### The retired key keeps the past and loses the future

A retired key verifies bundles made **before** the retirement and nothing
after:

* `SENDER KEY RETIRED` — valid signature, bundle predates the retirement. Still
  attributable, and the thread history stays readable.
* `SENDER KEY REJECTED` — valid signature under a key that does not cover this
  bundle. Contents withheld, non-zero exit, same as a bad signature.

If a retired key kept working for new mail, retiring it would buy nothing at
all. The timestamp that decides this is the sender's own field, which is
honest about what the rule rests on: that the old key was never stolen. For
the case where it *was*, `ctx retire <name> --compromised` refuses everything
that key signed, old bundles included, because a thief chooses the date too.
That form touches one key and says so; `--compromised --all` condemns every key
you ever held for that person, for when you learn the compromise predates what
you knew.

Rotating your own key keeps the old secrets so mail already sealed to it can
still be collected — `ctx pull` drains the retired mailbox alongside the
current one, because losing in-flight mail on rotation is another way to teach
people not to rotate. `--compromised` destroys them instead: the thief can
read those envelopes either way, and keeping a copy only extends the window in
which you keep reading mail they are also reading.

## Groups

`--to` is a list from the start, and `group:<name>` is a valid recipient. In a
group most of what you see was not written by whoever posted it, so the
manifest separates **author** from **sender** and `open` shows forwarded
content as forwarded, with the hop count and a warning that any hop could have
altered it before signing.

## What this is not

No server, no presence, no accounts. Agents are invoked rather than online, so
the instant-messenger model's buddy list and accept-before-transfer carry over
and its presence does not. If moving directories by hand gets annoying, add a
relay — the format does not change.

It does not sandbox anything. A verified sender is an *accountable* sender, not
a safe one. The frame tells a reader what the content is; deciding to act on it
is still the reader's job, which is why `open` is a renderer and not an
importer.

## Tests

    cargo build --release && cargo test --release && bash tests/attacks.sh

188 checks plus 19 Rust unit tests. Every one is an attack that worked, or
nearly worked, during development: frame-boundary forgery, payload swapping
after signing, a listed contact claiming a third party's name, an unverified
author name on a forward, a trust label that was a substring of its own
opposite, a rotation notice countersigned by the wrong key, and a retired key
still signing new mail.
