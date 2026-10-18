# ADR: identity recovery — passphrase-sealed export

- **Status:** Accepted (design). **Not implemented.**
- **Date:** 2026-10-18
- **Decided by:** Owen
- **Supersedes:** nothing. **Implemented by:** a later phase; nothing in this
  repository does any of this yet.

## Context: the problem being solved

`~/.gage/identity.key` is the one file in gage whose loss cannot be undone.
Every contact who confirmed your word-pairs confirmed *that* key. Lose it and:

- every contact must re-confirm a new key, over a voice call, one at a time;
- every bundle you ever signed becomes unverifiable by anyone who has not
  already witnessed it;
- mail already sealed to your old encryption key is unreadable, permanently;
- your mailbox registration on a relay is bound to the old signing key, and
  first-registration-wins means it cannot be rebound.

The cost is super-linear in how well gage is working: the more contacts who
have done the ceremony, the worse a loss is. And the triggering event is
ordinary — a reinstall, a dead disk, a laptop left in a taxi, a `rm -rf` in the
wrong directory. **A common accident with an unrecoverable outcome is a design
problem, not user error.**

## Decision

**Encrypted backup/export: a passphrase-sealed file the owner stores
themselves.** Opt-in, explicit, no new third parties and no network surface.
The same key, in a safer drawer.

## Options considered

### Option 1 — Encrypted backup/export  ✅ **CHOSEN**

The owner runs a command, supplies a passphrase, and gets a file. Restoring it
on a new machine reconstructs the identity.

**Security analysis.** The secret stays a secret the owner holds; no one else
is introduced. The attack surface is exactly two things: the passphrase, and
wherever the file is stored. An attacker needs both — the file is useless
without the passphrase, and the passphrase is useless without the file, which
is a meaningfully better position than either alone. A strong KDF makes offline
brute force expensive rather than free. The honest cost: it converts "lose the
key, lose everything" into **"your security is now your passphrase's
strength"**, and a weak passphrase on a file synced to a cloud drive is a worse
posture than no backup at all.

**UX cost.** One command to export, one to restore, and a passphrase the owner
must not lose — which is the same class of problem as the key, moved somewhere
a person can write it down. Modest, and familiar from every other tool that
does this.

**Failure modes.** Forgotten passphrase (back to identity death, with an extra
step). File stored next to the thing it protects, or in a backup the attacker
also has. A silent restore overwriting a *working* identity — addressed in the
spec below. Restore paths that are never exercised and turn out broken on the
one day they are needed — which is why the drill is a requirement, not a
nicety.

### Option 2 — Trusted-contact recovery  ❌ **rejected**

Split a recovery secret among existing confirmed buddies; some threshold of
them can help you back.

**Why it lost.** It introduces a **new social attack surface that fights the
ceremony model.** gage's whole claim is that trust is receiver-computed and
confirmed out of band by a human. Trusted-contact recovery inverts that: it
makes other people's actions able to reconstitute *your* identity, and the
request to help necessarily arrives over a channel — which is exactly the
channel an attacker would use. "Alice says she lost her key, please approve"
is a social-engineering prompt with a key at the end of it, and the people
being asked are the same people whose only verification tool is a voice call
they must now initiate under time pressure while someone claims to be locked
out.

It also multiplies collusion risk (a threshold of contacts, or anyone who
compromises that many) and demands a share-distribution protocol, a threshold
scheme, and a recovery ceremony — a large amount of new cryptographic and
social machinery for a tool whose current virtue is that a person can read all
of it. Rejected on surface area and on model coherence, not on cryptographic
grounds.

### Option 3 — No recovery (status quo)  ❌ **rejected**

**Why it lost.** It is the most secure option and it is not a reasonable
product. A common accident is punished with identity death, and the punishment
grows with adoption. "Do not lose this file" is not a recovery story; it is a
warning placed where a feature should be. Rejected as an answer, though it
remains the **default**: nothing is backed up unless the owner asks.

## Requirements this design must satisfy

Recorded as given, because the implementation phase will be checked against
them:

1. **Opt-in, never silent.** Export is an explicit act. Nothing is backed up by
   default, and no command creates a backup as a side effect of doing something
   else.
2. **Restore is tested, not just export.** The restore drill belongs in
   `tests/selfcheck.sh`, with fixture identities. An untested restore path is a
   backup that does not exist.
3. **Restore shows the identity's word-pair fingerprint**, so the owner can
   confirm the backup really is their identity before trusting it.
4. **The trade is written in plain words wherever this is documented:** opting
   in converts *"lose the key, lose everything"* into *"your security is your
   passphrase's strength."*
5. **Passphrase-sealed file:** strong KDF plus a modern AEAD, versioned format.
   No new third parties, no network surface.

---

# Specification for the implementation phase

Design only. Nothing below exists yet. Written as the thing to build.

## Scope: what is in the backup

**In:**

- the signing keypair (ed25519) — the thing that cannot be replaced;
- the encryption keypair (X25519) — without it, historic sealed mail stays
  unreadable even with the signing key back;
- retired keys and their records, because `KEY RETIRED` versus `KEY REJECTED`
  depends on knowing what was retired and when, and losing that turns old
  attributable bundles into unplaceable ones;
- the handle.

**Out, deliberately:**

- the contact list, journal, inbox, sent, state and relay address. These are
  recoverable or re-earnable, they are much larger, and some of it is other
  people's correspondence. A backup should be the irreplaceable minimum, so
  that a leaked backup costs as little as possible beyond the key itself.
  (A separate "export my whole home" is a different feature with a different
  risk profile; this is not it.)

The file therefore contains the key material and the minimum needed to
interpret it, and nothing about who you talk to.

## Format sketch

A single file. Versioned, and the version is outside the ciphertext so a
future reader can refuse intelligibly rather than failing to decrypt:

    {
      "fmt": "gage-identity-backup",
      "v": 1,
      "kdf":    { "name": "argon2id", "m": <KiB>, "t": <iters>, "p": <lanes>,
                  "salt": "<b64, 16 bytes, fresh per export>" },
      "cipher": { "name": "xchacha20poly1305", "nonce": "<b64, fresh>" },
      "ct": "<b64 ciphertext>"
    }

- **KDF: Argon2id**, parameters stored in the file so they can be raised later
  without breaking old backups. Chosen for memory-hardness: the threat is
  offline brute force against a human-chosen passphrase.
- **AEAD: XChaCha20-Poly1305**, consistent with the `crypto_box` primitives
  already in the tree, with the whole header as **associated data** so the
  stated KDF parameters cannot be downgraded by editing the file — an attacker
  who rewrote `m` to something cheap would break authentication.
- Plaintext is the key material above, as JSON.
- **No passphrase hint, no identity label, and no fingerprint outside the
  ciphertext.** A backup file should not announce whose it is. The fingerprint
  is shown after a successful decrypt (requirement 3), which is when the owner
  can act on it.

## Command surface

    gage export-identity --out <file>     # prompts twice for a passphrase
    gage restore-identity <file>          # prompts once, prints the fingerprint

Names to be settled in implementation; the shape is the commitment. Both are
explicit, neither has a `--force` that skips a confirmation, and the passphrase
is read from a prompt rather than a flag so it does not land in shell history
or in `ps`. If a non-interactive form is ever needed it reads from a file
descriptor, never an argument.

## Export semantics

- Refuses if there is no identity to export.
- Prompts for the passphrase **twice** and compares, because a typo in a
  backup passphrase is discovered at the worst possible moment.
- Refuses a passphrase below a stated minimum length, and says the trade in
  requirement 4 out loud at the moment of export — the one moment the owner is
  thinking about it.
- Writes `0600`, via a temp file and rename, like every other sensitive write
  in the tree.
- Prints the fingerprint of what it just exported, so the owner can see it
  matches the identity they meant.
- Says plainly where **not** to put it: not beside the gage home, not in the
  same backup as the machine it came from.

## Restore semantics

The part most likely to be got wrong, so it is specified tightly.

1. **Never silently overwrite an existing identity.** If `identity.key` is
   already present, restore **refuses** and says so, naming both
   fingerprints — the one on disk and the one in the backup — so the owner can
   see whether they are about to replace a working identity with an older copy.
   There is no `--force`. Replacing a live identity is a deliberate act that
   should require moving the existing key aside by hand, which is visible and
   reversible.
2. **Decrypt, then confirm, then write.** The fingerprint is printed from the
   decrypted material and the owner confirms it before anything touches the
   home directory. A restore that wrote first and reported second would be a
   restore that could silently install the wrong identity.
3. **All of it or none of it.** Written to a temp location and moved into place
   atomically; a half-restored identity — signing key present, retired records
   missing — would produce wrong trust verdicts, which is worse than no
   restore.
4. **A restored identity is not a witness.** The local witness record is not in
   the backup and is not reconstructed. Bundles that arrive after a restore
   have no record of having been seen before, so a retired-key bundle will read
   `cannot be placed either side of the retirement` rather than `KEY RETIRED`.
   This is correct and must be documented: a restore brings back the key, not
   the machine's memory of what it saw.
5. **Unknown `v` refuses**, naming the version, rather than attempting a
   best-effort parse.
6. **Wrong passphrase is a clean failure** — authentication fails and nothing
   is written. No partial state, no retry counter, no lockout.

## The drill (requirement 2)

In `tests/selfcheck.sh`, over fixture homes only:

1. create a fixture identity, note its fingerprint;
2. export it with a known passphrase;
3. restore into a **fresh empty home**, and assert the fingerprint, the handle,
   the signing key and the encryption key all match;
4. assert a bundle signed before the export still verifies under the restored
   identity, and that mail sealed to the old encryption key still unseals —
   the two things a backup exists for;
5. assert restore into a home that **already has** an identity refuses, writes
   nothing, and leaves the existing key byte-identical;
6. assert a wrong passphrase fails cleanly and writes nothing;
7. assert a truncated or bit-flipped file fails authentication rather than
   producing garbage.

Checks 5, 6 and 7 are the ones that matter. Everyone tests the happy path.

## What this does not solve

- A forgotten passphrase is still identity death, with one more step.
- It does nothing for a key that was **stolen** rather than lost; that is
  `gage rotate` and the retirement machinery, which is a different problem.
- It does not restore the relay mailbox binding, which is held by the relay and
  keyed to the signing key — a restore of the same key should simply work
  against the same relay, and that assumption needs testing against a real
  relay during implementation.
- It does not help someone who loses the key *and* the backup.
