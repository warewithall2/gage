# gage

Hand context between agents — files, prompts and decisions — with a trust
boundary that survives the hop.

A gage is a pledge: something of value handed over to stand behind a promise,
and historically the glove thrown down to open a challenge. Both senses fit.
Two people compare four word-pairs over a channel neither machine controls,
and everything downstream — every verdict, every grant, every unattended
acceptance — rests on that one human moment.

> Renamed twice on 18 October: `ctx` → `countersign` → `gage`. **Nothing on
> disk moves, ever.** An identity key is the one file whose loss cannot be
> undone — every contact who confirmed your word-pairs confirmed *that* key —
> so `gage` uses the first home that exists out of `~/.gage`,
> `~/.countersign`, `~/.ctx`, copies nothing, creates nothing to replace
> another, and honours `GAGE_HOME`, `COUNTERSIGN_HOME` and `CTX_HOME` so that
> existing scripts and systemd units keep working.

Your Claude hands a task to Codex. A colleague's agent sends you their project
state. Works across vendors because it is not a protocol: a bundle is a signed
directory, so it moves over a shared folder, git, email, or anything else you
already have.

## The receiving agent's half of the trust boundary

Signing what an agent *does* is well covered by other work — receipts over
tool calls, verified at the server that executes them. See
[docs/prior-art.md](docs/prior-art.md). gage is the other end: what the agent
*reading* a message is told about it, in the seconds before it decides what to
do.

That matters because the reader is different. A receipt's verdict is read by a
program at an admission check, which cannot be talked out of its conclusion. A
bundle's verdict is read by a language model whose next tokens are the payload
itself, and which can. A channel that lets one LLM send prompts to another is,
by default, a prompt-injection delivery network.

So `gage open` is a renderer, not an importer. It puts the bundle inside a frame
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

## Keys, said out loud

    $ gage whoami
    owen	yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=.KlXt+/5rj4y3FMC7eqau4zF5eZV+x7PjYZUdyUXHDEM=

      this key says : humble pillar · ruddy lobster · marine armour · eastern dovecote
      shown as      : humble pillar

LocalSend labels a device with a word pair and it is the nicest thing about
using it — but there the words are a *name* the device picked, so anyone can
be Yellow Iguana. Here they are derived from the signing key, so nobody
chooses their own and two machines showing the same words are holding the same
key. `gage fingerprint <name>` says a contact's, and `gage add` prints the words
for the key it just took, which is the moment you confirm it with them over
some other channel.

Two lengths, because one cannot do both jobs. A single pair is 16 bits:
lovely, and useless as a check, since an attacker generates keypairs until
theirs also renders "humble pillar" — about 65,000 tries. So the pair is a
**label**, for telling devices apart in a list, and nothing is ever confirmed
against it. The **fingerprint** is four pairs, 64 bits, and is what a person
compares. Both come from the same hash in the same order, so the label is
always a real prefix of the fingerprint rather than a separate lookalike.

## The second machine

Install it, then one command on each:

    $ gage lan
    new identity, named after its own key: grey crowbar
      grey crowbar · lavish jackdaw · sleepy hedgerow · electric delta

    gage lan -- you are "grey crowbar" on this network
      visible and reachable while this runs, silent the moment you stop it
      anything sent to you lands unread in inbox/pending
      broadcasting to: 255.255.255.255, 192.168.1.255

      gallant alcove  at 192.168.1.44:7791  (not paired)
          says : gallant alcove · indigo burrow · merry banner · glassy nettle

Then send, by the two words on the list:

    $ gage send --to "gallant alcove" --subject hi --file notes.md --lan
    handed to gallant alcove at 192.168.1.44:7791, over this network
    it is in their inbox/pending -- not accepted

No name to choose, no key to copy, no pairing first, no relay. The name is
two words taken from the signing key, so nobody picks their own — LocalSend's
device names, except derived rather than chosen, which makes them a slightly
better label at no cost to the person.

**Presence is the process.** It announces while `gage lan` is in the
foreground and goes silent the moment you stop it. That is LocalSend's own
answer to the same objection, and a better one than the flag this started
with: the state is visible on screen rather than sitting in a number of
seconds you have to remember you passed.

**Pairing is an upgrade, not a gate.** An unpaired machine can send to you
and what arrives is `SENDER NOT ON YOUR LIST`, unread, behind the same accept
gate as everything else — which is the protection, and always was. When you
want a key confirmed rather than merely observed:

    $ gage pair laptop
      gallant alcove  at 192.168.1.44
      says : gallant alcove · indigo burrow · merry banner · glassy nettle

    Does the other machine show EXACTLY those words? [y/N] y

Four word-pairs is 64 bits and is what a person compares; the single pair in
the list is 16 bits and is a label only, never confirmed against, because
grinding 65,000 keypairs to match one is trivial. That confirmation is what
makes a key *yours* rather than *some machine on this wifi*, which is what a
[grant](#authority-the-one-thing-that-says-you-may-act) should require before
an agent acts on a message unattended. Requiring it before one file could
move was a step I added and it was wrong.

Underneath, `gage nearby`, `gage pair` and `gage listen` are still there as the
explicit forms, and `gage listen` is the one to use for a machine that should
be reachable without announcing — it answers an address query only when the
query is signed by a key already on your list, so a stranger gets silence they
cannot tell from an empty network. Design and the costs:
[docs/lan-discovery-design.md](docs/lan-discovery-design.md).

## Authority: the one thing that says you may act

Everything above is about what is *known*. None of it says whether an agent
may do what a message asks — and it cannot, because a bundle cannot authorise
its own fulfilment, however well signed. That gap is real and was measured:
[dogfooding this across four agents](docs/dogfood-2026-10-15.md) had two of
them read a verified request from a verified contact and decline, correctly,
for want of authority.

So authority is computed by the receiver from its own list, exactly as trust
is. `~/.gage/authority` is a file **your human writes**:

    # no gage command writes this file; edit it yourself
    allow codex review-request
    allow dana question in-reply-only
    allow <a-public-key> any          # any message KIND, not any action

`gage authority` prints what is granted. There is deliberately **no command
that writes a grant** — a `gage allow` would be reachable by prompt injection,
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

### Accepting without a human, and the budget that bounds it

`accept` has always meant a person looked at a frame and moved a bundle. For
an unattended loop that is the step nothing can do, so what people build
instead is a hook that runs `gage accept` itself — which makes every grant
unbounded and leaves gage unable to tell, afterwards, which acceptances a
human performed. So it is in the tool, where it can be counted:

    allow sndr answer auto-accept max-exchanges 4

    $ gage watch --auto-accept
      7382e954: accepted unattended, 1 of 4 in this thread (allow sndr answer
                in-reply-only auto-accept max-exchanges 4)
      aa3e2665: this thread has used 4 of 4 auto-accepts (…), so it stays pending

Four conditions, all required:

- **The watcher was started with `--auto-accept`.** The file says what the
  human permits; the flag says *this process* is the unattended one. An
  interactive `gage watch` must not move things a reader is about to look for.
- **A grant says `auto-accept`.** Which cannot be written without
  `max-exchanges N` and cannot be written against `any`. Both are refusals,
  not defaults: a half-written grant must not read as an unbounded one, and
  every default here would be a guess at what a person meant.
- **It answers something this machine sent.** `auto-accept` implies
  `in-reply-only`, and the grant you are shown prints the implied modifier so
  the rendered line is what is actually in force.
- **The thread's budget is not spent**, counted from the journal.

**The budget cannot be refilled by a sender.** It is per thread, and a thread
id is a field the *sender* writes, so the key is read out of this machine's
own `sent/` instead: the thread of the parent being answered, which only the
receiver can have written. A reply must name a parent found there and signed
by this machine's own key, so opening a thread is the receiver's act, and a
sender naming a parent that was never sent gets nothing.

The first version of this claimed the implication of `in-reply-only` was the
whole defence. A reviewer showed it is not even half of one: `in_reply_to` and
`thread` are *separate* fields, so a granted sender could answer the same
verified parent with `thread: "aa"`, then `"bb"`, then `"cc"`, and collect a
full budget each time. Validating the parent and then discarding everything
learned from it is what left the hole — the predicate returned a bool. It now
returns the parent, and the budget is keyed on it. A reply that claims a
different thread from the parent it answers is refused outright as well, since
no sender built with `--reply-to` ever does that.

That check is also what made `in-reply-only` mean anything at all. Until this
feature needed it, it tested `in_reply_to.is_some()` — asking the sender
whether the sender is replying. Any sender satisfied it by writing any string
into the field, and a grant written `in-reply-only` was no narrower than one
without it. The string also became a path component, so `../../../../etc` was
reaching out of `sent/` on a `stat`; ids are validated now, by the same
function that exists because [the same hole was found once before](src/manifest.rs),
on `pull`.

**The journal entry is the budget.** There is no counter file: a second place
to keep a count is a second place for it to be wrong, and the record of what
was done is already the record of how much was used. Each unattended accept
writes which grant allowed it, which line of the file that was, the budget key,
and where the count stood.

Three things follow, and each was a defect first:

- **The record is written before the move,** so a failed write leaves the
  bundle in `pending` for a human rather than in `accepted` with nothing
  counting it. The other order spends no budget and accepts anyway.
- **The count is taken again inside the journal lock**, because counting and
  then appending as two steps is a race: two watchers each read `used = 0`
  against `max = 1` and each accepted.
- **A journal that cannot be written turns auto-accept off for the rest of the
  run**, latched. It used to print and carry on, so a full disk would have
  become an unbounded, uncounted accept path for as long as it lasted. A line
  that will not *parse* also declines rather than counts past it — `read`
  skips unreadable lines, which is right for showing history and fails open
  for a counter.

**What it is not:** permission to act — with one honest qualification. The
acceptance itself moves a directory and marks it readable; it does not open
the bundle, hand it to a model, or run anything, and `gage open`'s
`authorised :` block is still the only thing that says what may be done with
what is inside. But `gage watch --auto-accept --on-arrival …` is an end-to-end
unattended pipeline in one process, and the accept is deliberately ordered
*before* the hook so the hook finds the bundle accepted. A reviewer was right
that "nothing opens or runs anything" is true of the acceptance and false of
that combination. What the hook may then do is bounded by the hook, which a
human wrote, and by the grant it is told about — not by this feature.

Nor is the bound a defence against a
determined verified sender — that sender can still reply to everything you
send, within the budget, indefinitely. What it buys is that a *runaway*
exchange — two agents answering each other, a loop, a sender that got stuck —
stops at a number a human chose rather than at whatever the disk runs out of
first.

`gage watch` now also dates arrivals in the journal before anything acts on
them. It did not before, which meant the unattended path — the one the journal
exists for — was leaving the thinnest record: an `accepted` entry with no
`observed` entry in front of it.

## Getting started, and getting someone else started

    gage connect https://relay.example.com

Three steps that have no decisions in them — make an identity, register a
mailbox, work out what to share — and then a deliberate stop at the one that
does. It prints the line the other person runs, and the four word-pairs you
have to read to them out loud. That last part is not automated because
automating it would be removing the only thing gage does.

Run it again whenever: it keeps the identity you have. A command whose job is
to get you started must not be the one that silently throws away the key
everything you have already exchanged was built on.

## Giving it to someone else

    scripts/release.sh my-laptop     # build on every machine reachable
    cat dist/SHA256SUMS

Binaries land in `dist/`, one per platform, each built on the machine it runs
on — cross-compiling needs a C toolchain per target because rustls brings C,
and a binary built where it runs is one fewer thing to be wrong about. Every
binary reports the commit it came from, `gage --version` prints it, and the
release refuses to build from a dirty tree: a binary that names a commit it
does not match is worse than one with no version at all, and the journal
freezes verdicts, so "which gage decided this" needs an exact answer. The stamp
is checked by asking the binary — on the host that built it, when it cannot
run here.

[INSTALL.md](INSTALL.md) is written from the other person's side, including
the two places they are most likely to give up: the macOS quarantine dialog on
an unsigned binary, which looks like the software is broken, and the word-pair
confirmation feeling like a chore when it is the only step that cannot be
automated.

## Use

    gage init owen                      # make your keypair
    gage whoami                         # the line you give to a colleague
    gage add dana <their-key>           # buddy list; keyed on the key, not the name
    gage rotate                         # replace your key without losing your past

    gage send --to dana --subject "backoff refactor" \
             --prompt task.md --decision notes.md \
             --file src/client.rs \
             --agent claude-code --model claude-opus-5 \
             --out ./handoff

    gage inspect ./handoff              # summary, no contents in context
    gage open    ./handoff              # render for an agent, inside the frame
    gage reply   <id> --text "..."      # answer a thread, recipient inferred
    gage forward ./handoff --to group:eng --out ./fwd

    gage lan                            # the whole of the local network, one command
    gage send --to "grey crowbar" --file notes.md --lan
    gage pair laptop                    # confirm a key, rather than just see it

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

    gage seal ./handoff --to dana --out handoff.ctxb
    gage unseal handoff.ctxb --out ./incoming
    gage open ./incoming

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

Your `gage whoami` token is now `signpub.boxpub`. Identities created before
encryption existed gain an encryption key on next load **without changing the
signing key**, so every bundle you signed previously stays verifiable.

A contact with no encryption key on file can be verified but not sealed to,
and `gage seal` refuses rather than silently sending in the clear.

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
it, is what actually leaks -- and its filename says nothing. `gage send`
refuses rather than warns: on an outbound path a warning arrives after the
bundle exists, and for a remote recipient after it has gone.

    outbound scan found 1 item(s) that should not leave:
      notes.md:2  [email]  dana**********************.uk

Findings are **redacted**. A tool whose job is to stop secrets leaving should
not print them to a terminal or into an agent's context on the way to
refusing. Built-in rules cover private-key blocks, AWS/Anthropic/OpenAI/GitHub/
Slack/Google/Stripe key shapes, bearer tokens and real email addresses;
`example.com` and a bare `sk-ant-` in prose do not fire. `~/.gage/scrub.json`
takes `never_send` literals (a customer domain, a codename) and `disable` for
rules a repo legitimately trips. `--allow-findings` overrides and says so.

**Confirmation before anything leaves.** `gage push` prints the recipient,
subject and file list and refuses without `--yes`. The accept gate protects
the receiver; this protects the sender, and it is the one that matters when an
agent is doing the sending.

The gate is on `push`, not `send`, because `send` either delivers to a local
route or writes a directory you still have to move -- nothing has left yet.
An earlier version gated `send` on "has no local route", which is not the same
as "is leaving", and it broke every send to an unrouted handle.

## Relay

Registration proves possession of the box **secret**, not just knowledge of
the box key. That key is what you hand out in a `gage whoami` line, so a relay
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

    gage relay --bind 100.x.y.z:7788

On each machine:

    gage join 100.x.y.z:7788        # registers your mailbox, saves the address
    gage push ./handoff --to dana   # seals, then uploads
    gage pull                       # collects into inbox/pending

**The relay cannot read what it stores.** Compromising it leaks metadata --
which mailbox has mail, how big, when -- and no content. Verified in the test
suite by pushing a bundle with distinctive subject and payload strings and
grepping the relay's store: neither appears.

Four properties the relay enforces, each tested:

- **Fetching requires proof of key possession, not a key name.** Anyone who
  has seen a `gage whoami` line knows your public key, so a name-only scheme
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

### A relay that faces other people

Everything above about the relay assumed it was reachable only from one
person's tailnet, which is how it has run so far. Making it reachable by a
colleague changes the threat model completely, and three things were missing.

**One connection that said nothing held the entire relay for ever.** The
accept loop was sequential and `read_line` blocked inside it: no credentials,
nothing sent, total denial of service from a single TCP socket. The viewer was
given timeouts when the same shape was found there; the relay never was, and
the relay is the part that faces other people. It now sets read and write
timeouts before anything reads, serves connections concurrently up to a cap,
and past that cap refuses politely instead of falling over.

**`/send` takes no authentication, on purpose, so it needs a bound instead.**
A stranger must be able to send you a first message — that is exactly what the
buddy list's "not on your list" section is for — so the answer cannot be
authentication. It is quotas: bytes and envelopes per mailbox, a total store
cap as the backstop when many mailboxes are each individually under their
limit, and a per-address request limit. All four are flags on `gage relay`, so
an operator who wants more says so:

    gage relay --bind 0.0.0.0:7788 --max-mailbox-mb 64               --max-mailbox-msgs 500 --max-store-mb 4096 --rate-per-min 120

A full mailbox is refused with "mailbox is full" and nothing about who filled
it. A letterbox does not report its senders to whoever knocks; the person who
gets to see who is sending is the recipient, when they collect. And the
recipient can still collect what did arrive — a bound on strangers must not
become a bound on you.

Binding anything other than loopback or a tailnet address prints what that
means before it serves a byte.

### TLS, and why it is here despite the payload being sealed

    gage join https://relay.example.com      # certificate verified
    gage join 100.64.0.1:7788             # no TLS: a tailnet or a loopback test

The scheme decides, and the address is written by a person, so the choice is
visible rather than buried in a default.

The payload was always sealed and TLS does not change that. What it changes is
everything *around* it. `/send` carries the recipient's box key in the clear,
so anyone on the path learns who you write to, how often and how big it was —
the content stays sealed and the correspondence does not. And without a server
identity, anything that can answer for that address can accept your push,
return `{"ok":true}` and drop it: nothing readable, nothing delivered, and the
sender has been told it worked. **Signatures cover content; they never covered
delivery.**

Verification uses a compiled-in copy of Mozilla's root list — **not** the
system store, so a relay behind a private CA will fail rather than silently
work, and the suite asserts it in both
directions against `badssl.com`: expired, self-signed, wrong-host and
untrusted-root certificates are each refused *for their own reason*, and a
valid certificate completes a handshake. That last check is not decoration —
emptying the root store so that nothing verifies at all still leaves three of
the four refusals looking correct, because "refused" does not say why.

Those checks need the network, so they **skip** when it is absent — and print
that they skipped, because silently passing a security check that did not run
is the shape of mistake this suite exists to prevent.

Cost: 29 crates, taking the tree from 117 to 146. Worth stating in a project
whose other seven dependencies are all cryptographic primitives.

### Replay

A sealed envelope is a file. Anyone who can reach the relay — including the
relay — can hand the same one over twice, and the content is genuine, which
is exactly what makes it dangerous: **a replayed instruction is a real
instruction that was already carried out.**

Delivery used to ask only whether the id was still in `pending`. Once a bundle
had been accepted that path was gone, so the identical envelope was staged
again as a fresh arrival — for ever, on demand — and the journal recorded
nothing at all. `gage pull` now refuses it and writes a `duplicate` entry, the
one event in the log that records something the machine *declined* to do.

The check is the witness, which was already being recorded:
`sha256(from.key || 0x1f || manifest bytes)`. It identifies **this manifest**,
not merely this id, so a sender resending in good faith is unaffected — a new
message has a new `created` at minimum, so a new witness. The suite asserts
both halves, because the easy over-correction here is to refuse anything from
a sender you have heard from before.

## Conversations

A bundle carries what the sender wants from you:

    gage send --to codex --subject "key rotation" --type question --decision q.md
    gage send --to owen  --type answer --reply-to <id> --decision a.md

`share` (default), `question`, `answer`, `review-request`, `ack`. An unknown
type is refused rather than quietly defaulted. `question` and `review-request`
leave a ball in the recipient's court, and `gage inbox` says so.

    gage threads          # grouped, newest activity first
    gage threads --mine   # only where the ball is in your court
    gage thread <id>      # one exchange, root first
    gage close <id>       # settled, in your view

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

    gage reply <thread-or-message-id> --text "Full jitter, cap 30s."

The id can be a thread or a single message, and a unique prefix is enough.
A thread with **two correspondents** is refused rather than guessed, and that
refusal is the fix for a real attack: `thread` is a field the sender writes,
so anyone who had seen one message of a conversation could post into it,
become "the newest message that is not yours", and collect the reply meant for
someone else. Naming a message instead of a thread is unambiguous, and while
you hold the thread's root, naming the thread *is* naming that message. A
message whose claim to a thread cannot be checked against anything held
locally is shown as a claim, in the list, in `gage thread` and in the viewer.

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

    gage ui            # http://127.0.0.1:7777

The request head is bounded and the socket has a timeout. `read_line` has no
size limit of its own, so a client that sent bytes and never a newline made
the viewer allocate until it died, and one that connected and said nothing
blocked it forever -- which on a single-threaded server is the whole viewer,
and any local process could do either.

Two panes: conversations on the left, the thread on the right, with a
composer at the bottom. Loopback only, never `0.0.0.0`: an inbox viewer on a
laptop has no business being reachable from the network it happens to be on.

Under the conversations is **On this network** — every machine `gage lan` can
see, each with its four word-pairs under it. Drop files on one and they go
straight there over the wifi; `Pair` confirms a fingerprint without leaving
the page. The panel reads the list `gage lan` keeps and never announces
anything itself, so no button here can make this machine visible when the
person did not choose to be.

### The buddy list

A **Buddies** tab beside Chats, which is the shape the project was asked for:
a list you control, where a key asking to be on it is a decision you take and
can refuse. Three sections, because a key is in one of three states.

**Not on your list.** Any key that has sent you something whose signature
checks out, and that is not on your list, not refused and not retired. A
reviewer was right that my first heading — "asking to connect" — put words in
the sender's mouth: an ordinary note from a stranger is not a request for
anything, and the panel should not imply it was. A bundle whose signature does
*not* check mints no entry at all; the first version recorded verification as
a side tag beside an Add button, so a forged bundle produced a card for a key
its sender does not hold. There is no "please add
me" message type and deliberately so: a kind whose purpose is to ask for
trust would be the one thing a sender must not be able to ask for in a way
that looks different from ordinary mail. So a request *is* ordinary mail from
an unlisted key, already behind the same accept gate as everything else.

The gate on approving one is the part worth describing, because the first
version of it was theatre. gage asks you to type one of the four word-pairs —
and **the card shows no fingerprint until you get it right**. The pair asked
for is never pair 1, which is the key's word-label and is shown as the way to
tell one request from another. Get it right and all four appear, so you can
check the rest before anything is added; a wrong answer does not echo the
right one back, because that turns the step into a two-try copying exercise
and teaches you the words do not matter.

My first attempt printed the whole fingerprint on the card *and* asked you to
type a pair from it. The answer was on screen, so typing it was copying.

Being precise about what the current version proves, because a reviewer was
right that my first wording claimed more: a correct answer shows you read the
pair off something other than the request card. Not *which* something — and
there is one source that matters. **A key knows its own word-pairs, because
they come from that key.** So a sender can write the asked-for pair into the
very message that created the request, and the server cannot tell that source
from the other machine's screen. The page says so, in the gate, where the
decision is made:

> If this pair came from the message itself, or from anything this key sent
> you, it proves nothing — a key knows its own word-pairs and can quote them.
> It only means something if it came from the other machine.

That is the honest limit of any out-of-band check: gage cannot see your other
channel, so it cannot verify you used one. What it can do is withhold the
answer, name the trap, and reveal the other three pairs so the comparison you
do make is the full one. One matching pair is 16 bits, and grindable, which
the page also says. The refused list carries no fingerprints either, for the
same reason — a key can be un-refused back into a request, and printing its
pairs two sections down would leave the answer on screen by another route.

A contact added this way is **verify-only**. A manifest does not carry the
sender's encryption key and should not: a sender seals *to* you with the key
you published and never needs to publish its own. So you can check their
signatures and not seal mail to them until you have their `gage whoami` token
or pair on the network, and the list labels them so rather than promising
sealing that silently fails.

**Your list.** Each contact with its four pairs — so you can re-check one
after a machine behaves oddly — what is unread from them, whether they are
sealable, and three flags, each labelled with what it is evidence *of*:

- `routed under this name` — a local route is filed under this name. Keyed by
  name, which is what sending resolves too, and named that way because a
  reviewer pointed out that attributing it to a *key* would be a different
  claim: rename a contact and the answer changes. Verifying it against the key
  would mean opening another agent's `identity.key` to learn a public half,
  which this viewer should not do to render a dot.
- `on this network now` — this key is announcing itself, which it chose to do
  by running `gage lan`.
- `mail can be left` — **your** setup, not them: you are joined to a relay and
  hold an encryption key for them. Whether they ever collect it is not
  something this machine can know.

My first version sent a per-contact age — "announced itself 3s ago" — on a
list that refreshes every 2.5 seconds, with a comment asserting this was not a
presence roster. A reviewer was blunt and correct: that is a presence roster
whatever the comment says. The recency gradient is the part that makes it one,
so there isn't one. Three booleans, no ages, and nothing here polls anybody.

**Refused.** The third state, and the one that was missing: a list that can
say yes and "not asked yet" cannot say **no**, so the only way to stop being
offered the same decision was to accept it. `gage decline <key>` and the
Refuse button record it; `gage undecline` and Un-refuse take it back without
adding anything.

What a refusal is not is a block, and the page, the frame and the CLI all say
so rather than letting you believe otherwise: **nothing in gage can stop a
bundle being delivered.** A refused key's mail still arrives and still sits
behind the accept gate. What the record buys is that the frame reads `SENDER
REFUSED BEFORE` with the date instead of offering the decision again as though
it were new, and that an agent reading it is told the state is a record rather
than a wall.

Two corrections a reviewer extracted here. The Refuse button used to explain
itself only in the message *after* the click, so the explanation now sits under
the button. And the list used to tag a refused key "still arriving", which went
false once everything from it was read — implying delivery had stopped, the
exact misreading the surrounding text exists to prevent. It is a count of what
is held right now, and the general fact is stated unconditionally instead.

A key being on the list is still only ever an explicit act: `gage add` over a
declined key reverses the decline and says so. So the claim is not that a
declined key can *never* reach a grant — it is that it cannot while declined,
and that undoing it takes a deliberate add rather than anything a sender does.

A push through a *relay* is still terminal-only behind `gage push --yes`.
Handing a bundle to a machine on your own wifi is allowed from the page
because the gesture names both halves — particular files, dropped on a
particular named machine you can see — which is more than `--yes` on a
directory says. The outbound scan runs on that path exactly as it does in the
terminal, the findings are shown in the page, and there is deliberately no
override button: a finding sends you back to the terminal to look at the
file.

It never renders payload contents. A page that pastes a stranger's prompt into
a browser is a different risk surface, and `gage open` is where content is read,
inside its frame. What the page shows instead is the verdict, the warnings and
the file list, with the **verdict at the weight of a headline** rather than a
caption, because it is the product and a redesign that buried it would be a
regression.

Each correspondent gets a monogram coloured from their **key**, so two contacts
both calling themselves `codex` look different before you read a word. It is an
aid and never a verdict; the verdict is always spelled out beside it.

A reply written here is delivered to a **local route** only. Anything leaving
the machine still goes through `gage push`, where you see the list first, because
a button in a web page is not that confirmation. Every mutating request must
carry a custom header and may not name a cross-site `Origin` or
`Sec-Fetch-Site`: a page on the open internet can POST to `127.0.0.1` with a
plain form, and without those checks any site you happened to visit could accept
bundles in your inbox or send a reply in your name. A form cannot set a custom
header, and a fetch that sets one has to pass a preflight this server does not
answer.

## Nudges

    gage watch                    # poll, pull, notify
    gage watch --once --quiet     # one check, print instead of notifying
    gage watch --on-arrival CMD   # and run CMD for an arrival a grant covers

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

### The on-arrival hook

`--on-arrival` is the only thing in gage that turns an arrival into an action
with nobody watching, so it is deliberately narrower than the notification
beside it.

**It fires only where a grant already covers the message.** Not merely
`SENDER VERIFIED` -- that says whose key signed something, which is a
statement about what is known, not permission to act. `~/.gage/authority` is
the only file in the tool that says an agent may act, and this is the
unattended path, so it is the one caller that must not settle for less. A
verified sender with no grant, or a grant for a different message kind,
notifies exactly as before and runs nothing. The run prints which grant
matched, so the line in the file and the action taken can be read together.

**The hook never receives the bundle's items.** It gets the id, the sender's
key, the contact name, the type, the subject and the matched grant, in the
environment -- `CTX_BUNDLE_ID`, `CTX_FROM`, `CTX_FROM_KEY`, `CTX_TYPE`,
`CTX_SUBJECT`, `CTX_EXPECTS_REPLY`, `CTX_GRANT`. Nothing on stdin, nothing on
the command line. A bundle's contents are the thing the accept gate exists to
hold back; a hook that handed them over would have quietly removed that gate
for every arrival matching a grant.

Not "never receives message content": the subject is text the *sender* wrote
and it travels here. One bounded line, already in the notification you see,
so it leaks nothing the popup does not -- but a hook that treats it as
trustworthy input is a hook with a problem.

**gage does not accept the bundle.** When the hook returns, gage has moved
nothing: still unread, still in `pending`. The hook itself is handed
`CTX_BUNDLE_ID` and can of course run `gage accept && gage open` -- and for an
agent loop that is the point. What gage guarantees is that *it* never crosses
the gate for you, so crossing it stays an act your own hook performs, with a
journal entry to show it.

**gage does not interpolate sender text into your command.** The subject is
written by whoever sent it; in a shell line it would be command injection with
extra steps. So the command you wrote goes to `sh -c` untouched and every
sender-chosen value arrives as an environment variable, flattened to one
bounded line first -- a newline in `CTX_SUBJECT` is still a newline in
whatever the hook writes it to, and could forge an arrival record there.

That is one link, not the chain. `"$CTX_SUBJECT"` quoted is data; `eval`, an
unquoted expansion inviting word-splitting and globbing, or a value passed
where a command expects an option, each hand the sender a shell -- and the
hook is your code, so nothing here can stop it. Environment values are also
inherited by the hook's children and readable by anything running as you.

A hook that exits non-zero is reported; one that outlives
`--hook-timeout` (default 300s) is killed. Either way the arrival stays
marked announced, because retrying a broken command forever would turn one
bad hook into an endless loop against the relay.

As a background service:

    systemctl --user enable --now ctx-watch.service

`watch` and `pull` share one collection path, because a watcher that collected
differently from a manual pull would announce bundles you could then not find.
The watcher suppresses its nothing-to-do line; a line per poll turns a journal
into noise that hides the one entry that mattered.

## The journal

    gage journal                  # what this machine did with what arrived
    gage journal --bundle <id>    # one bundle's history
    gage journal --json           # the raw JSONL

Every other record in gage is an artifact -- a bundle in `pending`, a copy in
`sent`, a witness in `state.json`. Artifacts say *what was said*. None of them
says *what this machine decided*, and the moment anything happens while nobody
is watching, that is the only question worth asking.

One line per event: `observed`, `accepted`, `rejected`, `opened`.

**`observed`, not `arrived`.** `at` is when a scan happened to run, not when
anything was placed anywhere -- a bundle can even be placed and removed between
scans and never be seen at all. First local observation is the only arrival gage
can honestly assert from its own knowledge, so that is what the event is
called. A bundle already accepted when first seen is marked `backfilled`,
because its verdict was computed after acceptance and calling that an arrival
verdict would be a lie.

**The verdict is written down, not derived.** This is the whole reason the file
exists. A key rotation, a `gage add`, a retirement -- any of them changes what
`Contacts::verdict` returns for a bundle that arrived before it, so a verdict
recomputed on read is a different answer wearing the same name. Retire a
contact's key and the journal still shows the bundle observed as
`SENDER VERIFIED`, with the later lines saying `RETIRED`; recomputation would
have erased that.

What a difference between two lines is *not* is proof of a key change. It
could also be a backfilled first entry, a verdict computed after acceptance, a
contact edited by hand, local tampering, or a gage upgrade changing what a
verdict means. An entry freezes an **outcome**, not the evidence that produced
it: it does not hold the contacts revision, the key's status inputs or the code
version. A difference is a question, not an answer.

**Hashes and verdicts, never contents.** No subject, no filenames, no payload,
no handle. And every field that *does* come off the wire is validated rather
than copied -- the manifest id is a value the signer chooses, so it has to be
hex and bounded or it is replaced by a hash of itself; the same for the keys.
A decoded id can otherwise carry a terminal escape or a confusable into
whatever reads the log next. Partly because the retained bundle already answers "which exact
bytes". Mostly because all of those are text the *sender* wrote, and a log is
read later by a human skimming or a model summarising -- so a field an attacker
can fill is a stored injection against whatever reads the log next, which would
make the audit trail an attack surface. The one sender-chosen value admitted is
the thread id, and only if it looks like one: hex and bounded, or it is
recorded as the fact that it was unparseable.

**A rejection is the entry that matters most.** `gage reject` destroys the
bundle unread, so without a line written before the delete, deletion is
indistinguishable from never having arrived.

What it cannot tell you, said here so nobody reads it as more: gage's knowledge
stops at the bundle boundary. It cannot say what an agent did after `gage open`,
nor whether a human was actually looking -- `accept` records an act, not an
intention. It cannot prove the record is complete. And it is append-only by
convention, not tamper-proof: a process running as you can rewrite it, keys
and all. Claiming otherwise would be theatre. What it defends against is the
realistic case -- an agent or a script quietly dropping the line that
incriminates it, and ordinary loss.

Built before the thing that needs it, deliberately. Capture is the part that
cannot be retrofitted: a verdict never recorded when it was computed is gone,
and a retention policy can be argued about next month.

One thing that ordering does not buy: a hash chain added later proves only
that entries have not changed *since chaining began*. It cannot tell a genuine
pre-chain history from one edited, reordered or fabricated beforehand -- it
would chain a forgery just as faithfully. Capture-first buys evidence about
verdicts, not retroactive tamper evidence.

**The index orders the file, not `seq`.** `n` is allocated while holding the
journal lock, so two processes cannot claim one position; `seq` is the
observation counter that relates an entry to a retirement cut, which is a
different job. Each line is written and `fsync`ed under that same lock,
because a log of decisions that loses the line it just promised is worse than
none.

### The hash chain, and exactly how far it goes

    gage journal --verify

Each entry carries the digest of the previous line **as written**, so
verifying is a re-read of the file and nothing has to agree about canonical
JSON. Three kinds of tampering are caught: a deleted line, an edited line, and
a line appended by something that does not chain. The index is checked
independently, so a deletion someone bothered to re-link still leaves a gap.

**What a clean pass means, and does not.** No chained line has been changed,
removed or reordered — *unless whoever did it also recomputed every following
link*, which anything running as you can do. That is tamper-evidence against a
script quietly dropping the one line that incriminates it. It is not proof
against a determined local process, and no log a process can rewrite could be.
The suite asserts this limit directly: a re-linked edit verifies clean, and
that check exists so the chain is never read as more than it is.

**Entries written before chaining existed are not retroactively verified, and
the command refuses to imply otherwise.** Over a journal where nothing is
chained it prints *"none of them chained"* and *"this check verified
NOTHING"* — the first version printed "the journal chain is intact: 29
entries" over 29 entries it had not checked at all, which is the most
misleading thing it could have said. When the chain does start, the first
chained entry carries a `genesis:` digest over everything above it. That does
not make the old history trustworthy — whoever started the chain could have
edited it first — but it freezes it as it stood, which is strictly better than
leaving those lines unreferenced and rewritable at leisure.

Still unbuilt from `docs/open-decisions.md`: a retention policy, and anchoring
a digest somewhere this machine does not control, which is the only thing that
would survive the local-rewrite case.

## Key rotation

A key gets replaced: a laptop dies, a secret leaks, a contact starts fresh.
Before this existed `gage init` simply refused to overwrite, which is the right
refusal and the wrong ending — the only way out was to delete the key file,
and that turned every bundle you had ever signed into `SENDER UNVERIFIABLE`.
Losing your whole history the day you rotate is a bug, and a tool with that
property teaches people never to rotate.

    gage rotate                 # new keypair, old one kept on record
    gage rotate --compromised   # the old key was stolen
    gage keys                   # what is current, what is retired

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

    gage keychange notice.json            # report what it proves
    gage keychange notice.json --accept   # apply it

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

For a key that was actually stolen, `gage retire <name> --compromised` refuses
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
still be collected — `gage pull` drains the retired mailbox alongside the
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

No accounts, and no presence: nothing announces itself unless you ask it to,
for a number of seconds, having been told what it is about to say. Agents are
invoked rather than online, so the instant-messenger model's buddy list and
accept-before-transfer carry over and its presence does not. If moving
directories by hand gets annoying, add a relay — the format does not change.

Three commands do hold a port, and it is worth naming them rather than letting
"no server" quietly stop being true: `gage ui` on loopback, and `gage lan` and
`gage listen` on the local network. None is required for anything, all are in
the foreground where you can see them, and `gage lan` is the only thing in gage
that announces — for exactly as long as you are looking at it.

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
    bash tests/ui-e2e.sh      # optional: drives the viewer in a real browser

680 checks plus 106 Rust unit tests, and one end-to-end test that opens the
viewer in a browser and completes a connection request.

That last one exists because of a gap the other two could not see. The buddy
panel's confirmation gate lives entirely in the page's client state, and it
**shipped broken**: the reveal step cleared the typed pair and the add step
resent it, so the server rejected every add and the Add button could never
work. Every HTTP check passed throughout, because they drive the endpoint and
not the page. A reviewer found it by reading two lines together, and then a
headless screenshot immediately showed a second one — the Chats filter bar
staying on screen on the Buddies tab, because `.filters{display:flex}` beats
the `hidden` attribute. Neither was reachable from an assertion about JSON.

`tests/ui-e2e.sh` needs playwright and a chromium on the machine and **skips
rather than fails** when they are absent, so an optional dependency cannot
turn a build red. Reinstating the dead-button bug makes it report *"the add
never reported success -- the button is dead"*.

### Running it, and knowing when it breaks

    tests/selfcheck.sh                                  # is this machine good?
    tests/selfcheck-status.sh my-laptop         # is every machine good?

`selfcheck.sh` builds, runs all three suites, writes one status line and exits
non-zero with a specific reason. It is scheduled daily on both machines — a
systemd user timer on Linux, a launchd agent on macOS — and notifies the
person at the machine when it fails. Neither pulls: each reports the commit it
tested, so a machine that is behind says so rather than quietly updating
itself. `selfcheck-status.sh` reads each machine's last result, and reports a
host it cannot reach as **unreachable** rather than as passing — silence is
not evidence of health, which is the whole mistake this exists to stop.

It preflights the ports the suite binds, because a stray `gage ui` once caused
28 failures that looked like real defects. Both failure paths were verified by
causing them: an occupied port, and a deliberately broken verdict label.

To stop it:

    systemctl --user disable --now ctx-selfcheck.timer         # Linux
    launchctl bootout gui/$UID/com.owenware.ctx-selfcheck      # macOS

### It passes on both machines now

It did not before, and nobody had checked. Run on the MacBook for the first
time on 17 October, the suite reported six failures — including *"a killed
writer wedged the lock"*, which would be alarming if it were true. None of
them was a defect in gage:

- `timeout` is GNU coreutils and is not on a stock macOS, so the two checks
  that used it to assert a lock had been **released** failed on its absence.
  The shim uses perl's `alarm`+`exec`, because the obvious shell fallback —
  background it and poll — silently loses stdin: bash redirects an
  asynchronous command's stdin from `/dev/null` when job control is off.
- `ss` is Linux-only, and BSD `netstat` prints `127.0.0.1.7891`.
- BSD `wc` pads its output to a field width, so `ls | wc -l` yields
  `"       0"` and every `= 0` comparison against it was false. That reported
  *"an unbounded auto-accept grant accepted a bundle"* — the suite lying about
  a security property, which is the worse way round.
- BSD `sed` has no `\|` alternation, so a check matched nothing and called a
  perfectly good envelope malformed.
- Two checks read a label with `2>&1 | tail -1`, which merges two streams into
  one pipe and takes whatever lands last — correct here, wrong there, and
  intermittent.
- **Three checks picked a bundle with `inbox --json | head -1`.** Once a home
  holds more than one, that is whichever the filesystem lists first; ext4 and
  APFS disagree, so those checks accepted and opened a different bundle than
  the one they were about. That is a real test bug which passed here every
  time by luck, and the only reason it ever surfaced is that the suite was
  finally run somewhere else. Every one is an attack that worked, or
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
invalid byte, an envelope that unpacked half of itself before refusing, a discovery query
from a key nobody added, and a pairing waved through on a fingerprint that
was one word different, and a dropped file whose name was a path.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you state otherwise, any contribution you intentionally
submit for inclusion in this work shall be dual-licensed as above, with no
additional terms or conditions.
