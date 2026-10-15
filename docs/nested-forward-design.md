# Nested-envelope forward: grok's design

Received as ctx bundle `5831a71efc250f6c` on 15 October 2026, in reply to
the brief in decision 3. Grok's words, lightly reformatted; it has not been
reviewed or built. Recorded because it is a complete answer to a format
question that was open, and because it found a bug in the current `seal`
path along the way.

**Not built.** See the note at the end for why this waits for the v2 cutover.

---

**1. What a forwarder carries.** The exact bytes of the received `manifest.json` and `manifest.sig`, copied with `fs::copy` into `prior/manifest.json` and `prior/manifest.sig`. If that bundle was already a forward, its `prior/` tree is copied one level down the same way. Payload files are copied once, to `items/` at the root. The new manifest does not embed the old one as a JSON value. It carries the sha256 of those two files, and the forwarder's signature covers the new manifest's exact bytes, so it covers those hashes the same way a signature today covers item digests. Verification reads `prior/manifest.json` back off disk and checks the inner signature against those bytes. Parsing is only how you learn which key to check. Nothing in `forward`, `seal`, or `unseal` re-serialises a prior manifest. Re-serialising would break the inner signature, which is why the bytes are a file copy and not a JSON string.

The new manifest has no `chain` field. The chain is the walk down `prior/`. It is `"v": 2`. `create` stays v1. The outer id is new on every hop: sha256 of this hop's key, the prior manifest hash, digests of items this hop adds, subject, and `created`. The author's id stays inside the author's manifest and is shown as the origin id. It is not the directory name, so two forwards of the same bytes cannot share `pending/` and suppress each other. `thread` and `in_reply_to` are not copied out of the inner manifest.

Old binaries require `chain` and have no `prior`, so a v2 forward fails to parse and `open` shows nothing. That is the right downgrade. A v2 document that still carried a chain an old `expected_id()` would accept would render as a v1 forward, author unproven, or as a direct message.

**2. Three hops on disk, and the check that fails closed.** Alice wrote it, Bob forwarded it, Carol forwarded that to Dave:

```
manifest.json                 Carol, the bytes she signed
manifest.sig
items/note.md                 one copy of the payload
prior/manifest.json           Bob's exact bytes
prior/manifest.sig
prior/prior/manifest.json     Alice's exact bytes
prior/prior/manifest.sig
```

Dave verifies in order. Any failure withholds the contents, and later steps do not run.

1. Carol's signature over `manifest.json`. On failure the bundle is `SENDER UNVERIFIABLE` and the walk stops.
2. The hash of `prior/manifest.json` matches the hash in the manifest she signed, and the same for the sig file.
3. Bob's signature over those exact prior bytes, under the key inside those bytes. **This is the step that fails closed if Carol lied about what Bob signed.** She can enclose anything and honestly sign the hash of it, so step 2 still passes. Step 3 fails unless Bob signed those bytes. The author named further in is not shown. Label: `ENCLOSED HOP INVALID (the bytes this sender committed to were not signed by the key those bytes name)`.
4. The author bytes match the hash inside Bob's signed manifest. That catches the other lie: Bob's real signature with different author bytes swapped underneath. Label: `CHAIN LINK BROKEN (a signed manifest's hash of the enclosed hop does not match the enclosed bytes)`.
5. Alice's signature over her exact bytes.
6. Item digests against the single payload copy, including items any hop added. Overlapping paths are tamper.
7. The allowlist, once per hop, on that hop's own key and that hop's own bytes. Carol being on the list does not move Alice's verdict.

The next hop is always the literal directory `prior/`. The walker never follows a path taken from a manifest, and it refuses symlinks.

**3. What `open` prints.** The two unknowns are two axes the five sender verdicts fold into one label for one party. The signature axis: hop 1 valid, hop 2 valid, and the author's signature over the innermost bytes valid too. The list axis: the author's key is not on your list. Hop 2 already occupies the trust line, so that line cannot also be `SENDER NOT ON YOUR LIST`. The viewer classifies with `startsWith("SENDER NOT")`. The sample below assumes hop 1 and hop 2 are on the list, which is the rendering where one green sender verdict most invites a reader to treat the author as known. A prior hop whose signature is valid and whose key is absent gets `PRIOR HOP ABSENT FROM YOUR LIST` instead, a different label and not a prefix of the author one.

```
  trust      : SENDER VERIFIED (signature valid, key is on your list)
  sender     : carol (key CarolKey1234…), name confirmed against your list
  subject    : <the cover Carol signed>
  origin     : <alice's id>  "<alice's subject>"

  hop 1      : bob (key BobKey123456…), name confirmed against your list
               PRIOR HOP VERIFIED (signature valid, key is on your list)
               bob signed the exact bytes enclosed under him. A receipt of
               those bytes. His list is not visible here, and this line does
               not say he knows the author.

  author     : AUTHOR ABSENT FROM YOUR LIST (signature valid, you have never accepted this key)
               key AliceKey1234…
               CLAIMED HANDLE UNCONFIRMED (the signed manifest says "alice",
               which is text that key put there and not a name you assigned)
```

Contents are shown: the forwarders are accountable and the author really signed. If the author key is rejected, or the author's arrival is unrecorded, the contents are withheld even though both forwarders verify. Membership and the handle are different labels. `AUTHOR ABSENT FROM YOUR LIST` is the key. `CLAIMED HANDLE UNCONFIRMED` is the name, and it is printed only because the signature checked. When the innermost signature is invalid, the handle is not printed. No new label is a prefix of another, none contains another, and none starts with `SENDER`, `ARRIVAL`, or `VERDICT`. The trust line stays the sender's existing verdict. The viewer classifies that field only.

**4. Size.** Ten hops are ten manifests and ten signatures, stored once. A manifest here is about 700–900 bytes and a signature is 88, so ten hops is about 10 KB plus one copy of the payload. That is acceptable. The bound is 16 hops and 64 KiB for any one manifest or sig, checked before the walk recurses. The 17th hop is refused by `forward` and withheld by `open`. It is not truncated to a shorter chain that looks sound. Embedding the previous manifest as a JSON string grows a quote as 2^n because each level escapes the backslashes of the level above. Base64 of the whole previous blob grows by 4/3 per hop: still small at 10, about 5 MB at 30, then past the 25 MB seal cap. Both also invite a parser to re-serialise. The hash-linked files avoid that.

`seal` today packs the manifest, the sig, and `m.items` only, so a relay hop would drop `prior/`. The sealed package carries the prior files as their own list, paths matching `^(prior/)+manifest\.(json|sig)$` only, written back verbatim on unseal. An old unsealer ignores that field, writes a v2 manifest with no `prior/` tree, and the old `open` fails to parse it.

**Where it breaks.** Wrapping a v1 forward does not create an author. The innermost v1 manifest was signed by its `from` key only, and `chain[0]` is still that signer's claim. The author is that `from` key only when the innermost manifest is direct (`chain[0]` matches `from`, or a v2 with no prior). Otherwise the label is `INNER AUTHOR UNPROVEN` and the body is withheld. Dropped hops are invisible: Carol can forward Alice's original and skip Bob, and Alice's signature still verifies. The chain is the hops the sender enclosed, not a promise that nobody else handled the bytes. Witnesses are per hop, stamped when the nested bundle arrives, and only after steps 1–6 pass, or the old pre-seed attack applies at every level. Items a middle hop adds belong to that hop. Carol's memory file is fenced under Carol even when Alice is `AUTHOR KEY ACCEPTED`. The cover subject is Carol's; Alice's subject is shown from Alice's manifest only after her signature checks. One `serde_json::to_vec_pretty` on a prior manifest, anywhere on the path, invalidates that hop and every honest forward of it.

---

## Why this waits

Two reasons, neither about the design's quality.

**It is the second v2 format break on the table.** Codex's id cutover
(decision 1) is also a format change, and also claims `"v": 2`. Shipping them
separately means two migrations across four ctx homes and a relay, two windows
where old and new binaries disagree about what a bundle is, and two chances to
strand mail that is already on disk. One cutover carrying both is strictly
less risk than two carrying one each.

**Forwarding is the least-exercised path in the tool.** The 15 October dogfood
put real traffic through send, seal, push, pull, accept, open, reply and
threads. Nothing forwarded anything. Multi-hop provenance is a real hole, and
it is a hole in a feature that has never carried a message, while the same
dogfood found two things blocking the paths every message takes: an agent
cannot act on a request without authority from outside the bundle, and an
agent without a shell cannot reach ctx at all.

## The bug it found on the way

> `seal` today packs the manifest, the sig, and `m.items` only, so a relay hop
> would drop `prior/`.

That is a property of the *current* seal path, not of this design: it means a
nested bundle would survive local delivery and be silently flattened by a
round trip through the relay. Whatever the format ends up being, the sealed
package has to carry the prior files explicitly, with paths constrained to
`^(prior/)+manifest\.(json|sig)$` and written back verbatim on unseal. Fix it
as part of the cutover, not before.
