# ctx

Hand context between agents — files, prompts and decisions — with a trust
boundary that survives the hop.

Your Claude hands a task to Codex. A colleague's agent sends you their project
state. Works across vendors because it is not a protocol: a bundle is a signed
directory, so it moves over a shared folder, git, email, or anything else you
already have.

## The receiving agent's half of the trust boundary

Signing what an agent *does* is well covered by other work — receipts over
tool calls, verified at the server that executes them. See
[docs/prior-art.md](docs/prior-art.md). ctx is the other end: what the agent
*reading* a message is told about it, in the seconds before it decides what to
do.

That matters because the reader is different. A receipt's verdict is read by a
program at an admission check, which cannot be talked out of its conclusion. A
bundle's verdict is read by a language model whose next tokens are the payload
itself, and which can. A channel that lets one LLM send prompts to another is,
by default, a prompt-injection delivery network.

So `ctx open` is a renderer, not an importer. It puts the bundle inside a frame
that states, before any payload, that the contents are **data** from an
identified party and carry no authority — and on a bad verdict it withholds
the contents rather than annotating them, because an annotation is something
the payload can argue with.

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

## Authority: the one thing that says you may act

Everything above is about what is *known*. None of it says whether an agent
may do what a message asks — and it cannot, because a bundle cannot authorise
its own fulfilment, however well signed. That gap is real and was measured:
[dogfooding this across four agents](docs/dogfood-2026-10-15.md) had two of
them read a verified request from a verified contact and decline, correctly,
for want of authority.

So authority is computed by the receiver from its own list, exactly as trust
is. `~/.ctx/authority` is a file **your human writes**:

    # no ctx command writes this file; edit it yourself
    allow codex review-request
    allow dana question in-reply-only
    allow <a-public-key> any          # any message KIND, not any action

`ctx authority` prints what is granted. There is deliberately **no command
that writes a grant** — a `ctx allow` would be reachable by prompt injection,
letting an agent talked into running it grant itself permission to obey
whatever talked it into it. Edit the file yourself.

That guard is a deterrent, not a boundary, and the frame now says so. Any
process that can read this file can also write it, so an agent with a shell
can add its own grant — which is exactly how the grants for the 15 October
reviews got written. Removing the documented command means an injected agent
has to be told to hand-write a file, which is conspicuous in a transcript; it
does not make the file unwritable. A real boundary needs file permissions or
a separate process the agent cannot write through. `open` therefore tells the
reader never to edit the file, or add a grant, because a message asked it to.

Three rules, in the order they would hurt to get wrong:

- **A grant only ever follows `SENDER VERIFIED`.** Any other verdict and no
  grant is consulted at all. A grant that followed a forged or stolen key
  would be worse than having no feature.
- **A malformed file grants nothing.** One unusable line voids the whole file,
  because the other direction lets a typo on line 2 widen line 3 — and the
  failure directions are not symmetric. Too little authority asks a human a
  question; too much acts on a stranger's instruction.
- **A grant is for a kind of message, and the frame names the one act it
  permits.** The scope comes from the kind, in `MsgType::granted_scope` — a
  `review-request` permits reading what the bundle encloses and reporting
  findings, and nothing else. The first version said "you may act on what this
  message asks, within what it asks", which handed the boundary to the
  payload; both reviewers caught it independently. Editing files, running
  commands, committing, pushing, sending anything, messaging a third party and
  touching secrets or keys are listed as never covered, whatever the payload
  asks.
- **The grant line carries the frame's nonce**, so a payload cannot write a
  complete one. That raises the bar against a copied static string. It does
  not make a positive grant unimitable, because the reader is a model that can
  be argued into ignoring a marker, and the frame says as much rather than
  leaning on it.

No expiry yet, on purpose — it cannot use a clock, for the same reason
[key retirement cannot](#the-retired-key-keeps-the-past-and-loses-the-future),
and "expires after N observed messages" is a strange thing to ask a person to
write. A file you edit is already revocable by editing it.

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
    ctx reply   <id> --text "..."      # answer a thread, recipient inferred
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

The scan reads bytes rather than text, and scans long lines in overlapping
windows. Both of those are fixes: it used to read with `read_to_string` and
skip anything that was not valid UTF-8, so appending one invalid byte to a
file made the whole scan ignore it, and a line over 4000 bytes was skipped
rather than truncated, so padding a line hid whatever was on it. A scan that
can be switched off by the thing it is scanning is decoration.

Findings are redacted to a fixed shape that reveals neither the tail nor the
length -- the first version showed four leading characters, three trailing
ones, and a star count that was the exact length, which for a short token is
most of it, printed on the way to refusing.

Symlinks are refused and reported, never followed. The deny list matches a
file **name**, and a link's name says nothing about its target: `notes.md ->
~/.ssh/id_rsa` passed every check and shipped the key, and the content scan
did not save it either, because a `.env`-shaped target is neither a PEM block
nor a vendor key pattern. `--allow-secrets` does not override this -- it is an
override for files whose names you can see, and the whole problem with a link
is that you cannot. A linked directory passed as `--dir` is an error rather
than a skip, since walking it would collect a tree from somewhere nobody named.


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

Registration proves possession of the box **secret**, not just knowledge of
the box key. That key is what you hand out in a `ctx whoami` line, so a relay
that took the claim at face value could have its mailboxes squatted: register
someone else's box key against your own signing key before they get there,
and first-registration-wins locks the owner out permanently -- they can never
fetch, and mail pushed to them lands where the squatter can collect and delete
it. Sealed, so never readable, but gone, with the sender believing it arrived.

So the relay seals a random nonce to the claimed box key and commits the
binding only when the caller sends that nonce back. A squatter gets a sealed
nonce they cannot open and a pending claim that blocks nobody, since pending
claims are keyed by the pair rather than the mailbox.


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

## Replying

    ctx reply <thread-or-message-id> --text "Full jitter, cap 30s."

The id can be a thread or a single message, and a unique prefix is enough.
A thread with **two correspondents** is refused rather than guessed, and that
refusal is the fix for a real attack: `thread` is a field the sender writes,
so anyone who had seen one message of a conversation could post into it,
become "the newest message that is not yours", and collect the reply meant for
someone else. Naming a message instead of a thread is unambiguous, and while
you hold the thread's root, naming the thread *is* naming that message. A
message whose claim to a thread cannot be checked against anything held
locally is shown as a claim, in the list, in `ctx thread` and in the viewer.

Everything else is worked out: the recipient comes from the **key that signed
the message being answered**, never from its `from.handle` or its `to` list,
both of which the sender writes. The type defaults to `answer` when the parent
expected a reply and `share` when it did not, and the subject is the thread's
own, not re-prefixed twice.

`--text` is written to a file and sent like any other item, so a reply typed
in a hurry goes through the same outbound scan as a file. A prefix matching
two messages is refused rather than resolved to one of them: a reply landing
in the wrong conversation with nothing in the output saying so is worse than
an error. Replying to your own message says that, instead of reporting that
your own key is not on your list.

## The viewer

    ctx ui            # http://127.0.0.1:7777

The request head is bounded and the socket has a timeout. `read_line` has no
size limit of its own, so a client that sent bytes and never a newline made
the viewer allocate until it died, and one that connected and said nothing
blocked it forever -- which on a single-threaded server is the whole viewer,
and any local process could do either.

Two panes: conversations on the left, the thread on the right, with a
composer at the bottom. Loopback only, never `0.0.0.0`: an inbox viewer on a
laptop has no business being reachable from the network it happens to be on.

It never renders payload contents. A page that pastes a stranger's prompt into
a browser is a different risk surface, and `ctx open` is where content is read,
inside its frame. What the page shows instead is the verdict, the warnings and
the file list, with the **verdict at the weight of a headline** rather than a
caption, because it is the product and a redesign that buried it would be a
regression.

Each correspondent gets a monogram coloured from their **key**, so two contacts
both calling themselves `codex` look different before you read a word. It is an
aid and never a verdict; the verdict is always spelled out beside it.

A reply written here is delivered to a **local route** only. Anything leaving
the machine still goes through `ctx push`, where you see the list first, because
a button in a web page is not that confirmation. Every mutating request must
carry a custom header and may not name a cross-site `Origin` or
`Sec-Fetch-Site`: a page on the open internet can POST to `127.0.0.1` with a
plain form, and without those checks any site you happened to visit could accept
bundles in your inbox or send a reply in your name. A form cannot set a custom
header, and a fetch that sets one has to pass a preflight this server does not
answer.

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

A retired key covers bundles that were **here before the retirement** and
nothing after:

* `SENDER KEY RETIRED` — valid signature, bundle predates the retirement. Still
  attributable, and the thread history stays readable.
* `SENDER KEY REJECTED` — valid signature under a key that does not cover this
  bundle. Contents withheld, non-zero exit, same as a bad signature.

If a retired key kept working for new mail, retiring it would buy nothing at
all. So the question is what decides, and it took three attempts to stop
answering it with a timestamp.

The first version read the manifest's `created`, which is a field the
**signer** writes: a key stolen before an ordinary rotation could sign
something new, date it before the cutoff, and be read as attributable. The
second recorded a local arrival time instead, which was right in spirit and
wrong twice over — the record was keyed on the bundle id, which the signer
also chooses, so a thief could reuse an id this machine had already stamped
and inherit its record; and the comparison was lexical over RFC3339, which
accepted `""`, `"…12:00:00.9Z"` and `"…T01:00:00-14:00"` (really 15:00Z,
three hours *after* a noon cutoff) as earlier than noon.

What decides now is a **local observation counter**. Every path that is about
to show a verdict first records what it can see in the inbox, keyed on
`sha256(sender key ‖ the exact bytes the signature covers)`, against a
counter that only increases. A retirement takes a cut of that counter.
A bundle witnessed below the cut was here first; one witnessed above it was
not. No timestamp enters the decision, so there is nothing in it for a sender
to aim at, and the boundary case is a real tie rather than an attacker's
choice.

Three verdicts come out of it, and the third exists because conflating it
with the second would be a lie:

* `SENDER KEY RETIRED` — you saw this before you retired the key.
* `SENDER KEY REJECTED` — it reached you afterwards.
* `ARRIVAL UNRECORDED` — there is no record either way. Contents withheld,
  like a rejection, but it is not one: the ordinary cause is mail sealed
  before the rotation and collected from a relay after it, or a directory
  handed over on a stick. Telling someone that is a rejection would tell them
  a colleague is attacking them.

For a key that was actually stolen, `ctx retire <name> --compromised` refuses
everything it signed, old bundles included, consulting no date at all. That
form touches one key and says so; `--compromised --all` condemns every key you
ever held for that person, for when you learn the compromise predates what you
knew.

The same rule applies to the cutoff itself. `keychange --accept` takes the cut
from **your** counter at the moment you accept, and keeps the notice's own
date as `claimed_at`: a record, never a verdict. Whoever wrote the notice
chose that date, and adopting it let them put the retirement anywhere they
liked.

### The countersignature says less than it looks like

An earlier version omitted the old key's countersignature from a
`--compromised` notice, reasoning that a thief could produce it so it proved
nothing. Both reviewers argued that inverted the signal, and they were right.
Possession is the one bit a stranger cannot fake — anyone can send a notice
with no countersignature; only the key holder can send one with it. Worse, the
thief's best move was an ordinary `reason: "rotated"` notice, countersigned
and therefore the one a receiver would apply, while the honest victim's
unsigned compromise notice was the one it refused.

Notices are now always countersigned, signed before `--compromised` destroys
the secrets, and the receiver is told exactly what that buys:

    old key signed: yes -- this proves control of the old key, and
                    nothing about WHO holds it. If that key was
                    stolen, the thief can produce this signature too.

Rotating your own key keeps the old secrets so mail already sealed to it can
still be collected — `ctx pull` drains the retired mailbox alongside the
current one, because losing in-flight mail on rotation is another way to teach
people not to rotate. `--compromised` destroys them instead: the thief can
read those envelopes either way, and keeping a copy only extends the window in
which you keep reading mail they are also reading.

## Groups

`--to` is a list from the start, and `group:<name>` is a valid recipient. In a
group most of what you see was not written by whoever posted it, so the
manifest separates **author** from **sender**.

Only the **last hop signs**, which is the honest and uncomfortable part: a
forwarder writes `chain[0]`, so they can name anyone as the author, including
someone you trust. `open` says that in those words rather than printing a
known author's name as though it were established, and `forward` refuses to
re-sign a bundle that does not verify — otherwise a forwarder could launder a
broken bundle into one that checks out cleanly for the next recipient.
Cryptographic provenance across hops needs each hop to sign what it received,
which is a format change; see [docs/open-decisions.md](docs/open-decisions.md).

## What this is not

No server, no presence, no accounts. Agents are invoked rather than online, so
the instant-messenger model's buddy list and accept-before-transfer carry over
and its presence does not. If moving directories by hand gets annoying, add a
relay — the format does not change.

It does not sandbox anything. A verified sender is an *accountable* sender, not
a safe one. The frame tells a reader what the content is; deciding to act on it
is still the reader's job, which is why `open` is a renderer and not an
importer.

It is not an audit layer over an agent's own actions, and not a receipt format
for tool calls. Those exist and are further along; the comparison, and what
each side can and cannot prove, is in [docs/prior-art.md](docs/prior-art.md).

A bundle still cannot authorise its own fulfilment, however well signed —
proven by [dogfooding it](docs/dogfood-2026-10-15.md) across four agents, two
of which read a verified request from a verified contact and rightly declined.
What closes that gap is a grant the *receiver's* human wrote, never anything
in the message. See [Authority](#authority-the-one-thing-that-says-you-may-act).

## Tests

    cargo build --release && cargo test --release && bash tests/attacks.sh

392 checks plus 58 Rust unit tests. Every one is an attack that worked, or
nearly worked, during development: frame-boundary forgery, payload swapping
after signing, a listed contact claiming a third party's name, an unverified
author name on a forward, a trust label that was a substring of its own
opposite, a rotation notice countersigned by the wrong key, a retired key
still signing new mail, a cross-site POST to the viewer, a bundle grafted onto
someone else's thread to collect the reply, a retired key backdating its way
past its own retirement, a reused bundle id inheriting another document's
arrival record, two processes overwriting each other's state, a mailbox
squatted by quoting a public key, a symlink smuggling out a file nobody named,
a chosen bundle id suppressing a real message, an id
shaped like a path escaping the inbox, a witness pre-seeded with a junk
signature and claimed later with a real one, a bundle with no provenance chain
borrowing another message's id, a revocation that left the old key trusted
while it was being written, a secret hidden from the outbound scan by one
invalid byte, and an envelope that unpacked half of itself before refusing.
