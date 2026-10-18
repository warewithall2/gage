# Offline root: a design, not yet built

Status: **proposed, not implemented.** Designed by the grok reviewer on
2026-10-15 against `3377f13`, in answer to a specific question: a stolen
online key can countersign its own replacement, so what fixes that without a
third party. Recorded here because it is a ceremony change — it alters what a
person has to keep for the life of an identity — and that is the owner's
decision, not a reviewer's and not an implementer's.

Its own recommendation is to **build the audit log first**: the root's only
job is the day someone rotates in anger, nobody has had that day yet, and
until then it is a file people will leave sitting next to `identity.key`,
which is the failure it exists to prevent.

## The shape

A second ed25519 key that signs succession and nothing else — not bundles,
not relay challenges, not envelopes. No new crypto; the same
`identity::verify`.

* `identity.key` gains one optional field, `root_pub`. The seed is never in
  it.
* `root.seed` is a separate file the person moves off the machine:
  `{ v, root_seed, root_pub, online }`. `Identity::load` never reads it.
* `countersign whoami` prints a second line, `root <rootpub>`, leaving line one
  byte-identical so anything parsing `handle<TAB>signpub.boxpub` keeps working.
* `countersign add <name> <token> --root <rootpub>` pins it. `contacts.json` gains
  `"roots": { "<name>": "<rootpub>" }`, keyed by your name for them rather
  than by the online key, because the online key is the thing that changes.
* `countersign rotate` refuses without `--root <path>` once an identity has one, and
  refuses a path inside the ctx home: that is the file a stolen laptop
  already has.
* The notice gains `sig_root` over the same claim bytes, and the claim gains
  `"root"`. `Claim.v` stays 1 so old binaries keep verifying `sig_old`.
* `ctx restore --root <path> --handle <name>` is the lost-laptop path: the old
  online key comes from the `online` field in the root file rather than being
  typed, and the notice is signed by the root instead of the dead online key.

## Backward compatibility

An identity with no `root_pub` rotates exactly as today. A contact with no
pinned root applies a rooted notice on `sig_old` as today, and is told the
root was not checked. **A notice never installs its own root** — pinning from
a notice is precisely how a stolen online key would introduce one. Learning a
root later is `ctx pin-root <name> <rootpub>`, which says out loud that you
are asserting they gave it to you over another channel.

## What it does not fix

Verbatim from the reviewer, because the softer version would be a lie:

* A stolen online key signs bundles until each contact accepts a notice.
  `verdict` does not consult the root — witnesses and `retired_seq` remain the
  whole of that decision.
* A stolen root file produces a perfect `sig_root`. `--accept` stays manual and
  the out-of-band confirmation stays.
* Contacts who never pinned the root still follow `sig_old`. Sending them a
  rooted notice does not upgrade them.
* Mail not witnessed at accept time stays `ARRIVAL UNRECORDED`. The root is
  not a witness.
* Another ctx home does not learn the retirement; it still needs its own
  `keychange`.
* The root has no X25519 half, so mail sealed to the old box key remains the
  kept-secret problem. `restore` cannot collect it.
* `reason` is still the operator's word. The root does not know whether the
  online key was stolen.
* Group member lists are online signing keys, and nothing rewrites them on
  rotation.
* The root does not rotate. A lost root is retire-and-add.
* A root seed left inside the ctx home is just a second online secret.
  `rotate` refusing that path is the property; nothing detects a copy left
  behind elsewhere.
