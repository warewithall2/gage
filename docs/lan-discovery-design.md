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

**(3) is already built, and is the better version.** `ctx accept` exists
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

## What it would take

    ctx nearby                 # who is announcing on this network, with fingerprints
    ctx pair <name>            # confirm a fingerprint out of band, then add the key
    ctx push --to laptop       # straight over the LAN, no relay

Three pieces: a UDP announce/listen loop, a fingerprint the human can read
aloud (four groups of four hex, from the signing key), and a LAN listener that
accepts a sealed bundle into `pending/`.

## The two real costs

**Presence.** The README says "no server, no presence, no accounts", and it
says so because fetch timing against a relay is already metadata the operator
can see. Broadcasting a handle and a key on every network you join is a louder
version of that: a café wifi learns that this laptop exists, what it calls
itself, and its public key. That is a genuine change of posture, not a
detail. It wants a default of off, an explicit `ctx nearby --announce`, and a
plain statement of what leaves the machine.

**The pairing step cannot be removed.** It is the whole difference, so any
version that skips it for convenience has thrown away the reason to use ctx
rather than LocalSend. Making it fast is the job; making it optional is not.

**Not built. Needs the owner**, for the presence decision specifically.
