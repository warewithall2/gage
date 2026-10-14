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

    ctx send --to dana --subject "backoff refactor" \
             --prompt task.md --decision notes.md \
             --file src/client.rs \
             --agent claude-code --model claude-opus-5 \
             --out ./handoff

    ctx inspect ./handoff              # summary, no contents in context
    ctx open    ./handoff              # render for an agent, inside the frame
    ctx forward ./handoff --to group:eng --out ./fwd

`open` exits 0 when the bundle is attributable, and 2 when the signature fails
or the payload does not match, so a harness can branch without parsing prose.

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

77 checks plus 2 Rust unit tests. Every one is an attack that worked, or nearly worked, during
development: frame-boundary forgery, payload swapping after signing, a listed
contact claiming a third party's name, an unverified author name on a forward,
and a trust label that was a substring of its own opposite.
