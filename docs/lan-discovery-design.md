# LocalSend's experience, and which parts of it ctx can have

Asked for 15 Oct: set the second laptop up so it feels like LocalSend.

LocalSend's experience is four separate things. Three of them ctx can have
outright, and one of them is the thing ctx exists not to do. Worth separating
before building anything, because the fourth is where the whole argument for
this tool lives.

## What LocalSend actually does

1. **Zero-config discovery.** It announces itself on the local network and
   shows you everyone else doing the same. No addresses typed, no accounts.
2. **Direct device-to-device transfer.** No server in the middle.
3. **An accept prompt on the receiving device.** Nothing lands until the
   person says yes.
4. **Identity by self-chosen device name.** "Owen's Laptop" is a string that
   device picked, broadcast to anyone listening.

## Where ctx stands on each

**(3) is already built, and is the better version.** `countersign accept` exists
because arrival is not consent: a bundle sits in `pending/` and nothing reads
it until you stage it. That is LocalSend's defining moment, and ctx got there
from the opposite direction -- the buddy list and accept-before-transfer are
the two things worth keeping from instant messenger.

**(2) is half built.** Same machine is a local route and needs no network at
all. Across machines it goes through the relay. A LAN-direct path is new, but
not new machinery: the viewer and the relay are already small hand-rolled
HTTP, and a per-host listener is the same shape again.

**(1) does not exist at all** and is the thing being asked for.

**(4) is the one that cannot be copied.** And the reason is not purity.

## Why the device name does not transfer

LocalSend is right for LocalSend. Anyone on that network can announce
themselves as "Owen's Laptop", and it is fine, because a human looks at the
name and approves one transfer of a file they were already expecting. The
blast radius of a spoof is one unwanted file.

A ctx payload is instructions to an agent. It may be read later, by a
process, unattended, under a grant that says requests of this kind from this
key may be acted on. "I glanced at a device name once" cannot carry that.
Spoofing a peer in a discovery service is the named attack in OWASP ASI07, and
it is the specific thing the verifiable-not-trusted directory in the
commercial plan is an answer to. Shipping it in the local case and arguing
against it in the hosted case would be incoherent.

## The resolution: discovery and trust are different jobs

LocalSend conflates them. Kept apart, you can have LocalSend's discovery
exactly:

- **Discovery answers one question:** which keys are reachable at which
  address, right now. It is a hint about *where*, never a claim about *who*.
  A broadcast carries a handle, a signing key and a port. The handle is
  decoration -- it is a string the sender chose, which is already how `ctx
  open` treats it.
- **Trust stays where it is:** the receiver's own list, keyed on the key.

So first contact is a one-time pairing. Both machines print the same short
fingerprint of the key, you check they match, and you confirm once. That is
SSH's host key and Signal's safety number, and it is ten seconds that happens
once per device, ever.

After pairing: the laptop appears in a nearby list, you send to it by name, it
lands in `pending/`, the accept prompt fires. No relay, no addresses, no
accounts. That is the LocalSend experience, plus the one step that makes the
difference between "a device said it was your laptop" and "this is the key you
confirmed was your laptop".

## Built 15 Oct

    countersign nearby [--announce SECS]       # who is announcing, with fingerprints
    countersign pair <name> [--confirm WORDS]  # compare out of band, then add the key
    countersign listen                         # be reachable: answer queries, take bundles
    countersign push <dir> --to laptop --lan   # straight over the network, no relay

The fingerprint turned out better than four groups of hex: it is four
word-pairs derived from the signing key (`src/words.rs`), so nobody picks
their own, and it can be read across a room.

**Nothing announces by default, ever.** `countersign nearby` listens. `--announce`
takes a number of seconds, defaults to 60 if you pass the bare flag, and
stops on its own -- there is no mode in which a laptop keeps shouting onto
every network it joins. Before it sends anything it prints the handle, both
public keys and the port, and says they go to every host on the network, so
the posture change is read rather than discovered.

**After pairing, finding a machine is a query rather than a broadcast of your
existence.** `countersign listen` binds a UDP socket and answers one thing: a query
signed by a key already on its list. A stranger's query gets silence, which
is indistinguishable from an empty network. The key being asked about travels
as `sha256(key + nonce)`, so the segment does not learn who you are sending
to; the asker's own key is in the clear, because the signature over it is the
whole reason answering is safe. That is a cost at the moment you deliberately
send, not a standing broadcast.

Three ports: 7789/udp for pairing announcements (bound only while `ctx
nearby` runs), 7790/udp for queries, 7791/tcp for an envelope arriving. Split
so the pairing mode and the listener never fight over one socket.

### What the listener does not do

The TCP port takes a sealed envelope from anyone who can reach it, and that
is deliberate: a first bundle from someone new has to be able to arrive, or
`countersign add` could never be the second step. What protects you is what has
always protected you -- it lands in `inbox/pending`, unread, under a verdict
that says `SENDER NOT ON YOUR LIST`, and nothing reads it until you accept
it. Arrival is not consent over this transport either. The query gate hides
your *address* from strangers; it does not pretend to gate delivery, and a
port scan still finds an open port.

Envelopes are refused on the same grounds a relay pull refuses them: sealed
to a key this machine does not hold, a manifest id that would have become a
path, or a signature that does not verify. The refusal is one word on the
wire, because a parser error narrated back to a stranger is a way to find out
the service is there.

## The two real costs

**Presence.** The README says "no server, no presence, no accounts", and it
says so because fetch timing against a relay is already metadata the operator
can see. Broadcasting a handle and a key on every network you join is a louder
version of that: a café wifi learns that this laptop exists, what it calls
itself, and its public key. That is a genuine change of posture, not a
detail. It wants a default of off, an explicit `countersign nearby --announce`, and a
plain statement of what leaves the machine.

**The pairing step cannot be removed.** It is the whole difference, so any
version that skips it for convenience has thrown away the reason to use ctx
rather than LocalSend. Making it fast is the job; making it optional is not.

## Corrected 16 Oct: the three commands should have been one

The design above is right about the properties and wrong about the shape, and
the person who asked for it said so in one sentence: too much work. Counting
honestly, the runbook for a second machine came to eleven steps, and only two
of them were about the second machine. The rest were mine.

What was wrong was the time box. The presence objection is real -- a laptop
should not broadcast its key onto every network it joins -- and the answer
taken here was `--announce 60`, a number of seconds. But LocalSend has the
identical objection and answers it better: it is visible while its window is
open and silent when it is closed, and nobody calls that presence, because the
person can see it running. **The time box is the process lifetime.** Ctrl-C
and the machine is as invisible as it was before, with the state on screen
instead of in a flag you have to remember you passed.

So `countersign lan` is one foreground command that announces, discovers, listens and
receives, and it collapses `nearby --announce`, `nearby` and `listen` into the
thing a person actually does. The explicit three remain underneath;
`countersign listen` in particular is still the right command for a machine that
should be reachable *without* announcing.

Two further steps went the same way:

- **A name nobody has to choose.** `countersign init` with no argument takes a
  word-pair from its own signing key. Derived rather than random, which is
  strictly better than LocalSend: it is the first pair of the fingerprint, so
  the name on the list and the words you confirm cannot disagree. And `ctx
  lan` on a machine with no identity makes one, because being asked to pick a
  name before seeing the thing work is exactly the step being removed.
- **Pairing is an upgrade, not a gate.** This is the one that mattered. An
  unpaired machine can send, and what arrives is `SENDER NOT ON YOUR LIST`,
  unread, behind the accept gate -- which is the protection, and was the
  protection all along. The argument that "the pairing step cannot be removed"
  was about what a *grant* should require before an agent acts unattended, and
  that argument is intact. It was never an argument for requiring a confirmed
  fingerprint before one file could move between two machines, and reading it
  as one turned a correct principle into a bad tool.

## The presence decision, as taken

Default off, time-boxed when on, full disclosure of what is sent, and no
standing announcement in any mode. The README's "no server, no presence, no
accounts" survives with one honest amendment: `countersign listen` *is* a process
holding a port, and the README now says so where it says there is no server.

What was given up to get there: you cannot see a paired machine in a list
without that machine announcing. `countersign nearby` after pairing shows nothing,
because nothing is announcing. That is the price of the property, and it is
the right trade -- a roster that is always visible is a roster somebody else
can also read.
