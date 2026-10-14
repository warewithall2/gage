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

    cargo build --release && bash tests/attacks.sh

30 checks. Every one is an attack that worked, or nearly worked, during
development: frame-boundary forgery, payload swapping after signing, a listed
contact claiming a third party's name, an unverified author name on a forward,
and a trust label that was a substring of its own opposite.
