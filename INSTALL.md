# Giving gage to someone else

Everything here assumes the other person has never seen this project and does
not want to install a compiler. Each step says what it is for, because every
one of them is a place a person gives up.

## 1. Get it onto their machine

**The one line, which is what to send unless you have a reason not to:**

    curl -fsSL https://gage.sh/install.sh | sh

It works out their OS and architecture, downloads the matching binary and its
`SHA256SUMS` from the latest release, verifies the checksum before installing
anything, and puts one file in `~/.local/bin`. No sudo, no compiler.

**On macOS this avoids the Gatekeeper dialog entirely**, and that is the
reason to prefer it. The "cannot be opened because the developer cannot be
verified" warning comes from the `com.apple.quarantine` attribute, which
browsers, Mail and AirDrop attach to what they deliver and `curl` does not.
A binary you email to a Mac tester hits that wall; the same binary fetched by
the installer does not.

(An earlier version of this page said macOS refuses the file "because it was
not downloaded through a browser". That is backwards, and backwards in the
direction that matters: being downloaded through a browser is what causes it.)

`Gage.app` is a separate matter — it is quarantined however it arrives, and
nothing here helps until it is notarised. See
[notarize-checklist.md](notarize-checklist.md). A tester who only needs the
viewer can run `gage ui`, which opens the same window from the CLI install.

### Sending a file instead

Still supported, and a better demonstration of the two-channel idea if
someone asks how the checksum step works. From `dist/`, pick the one for
their machine:

| their machine | file |
|---|---|
| Mac, Apple silicon (M1–M4) | `gage-0.3.0-darwin-arm64` |
| Linux, 64-bit Intel/AMD | `gage-0.3.0-linux-x86_64` |

Send the matching line from `dist/SHA256SUMS` too, over a *different* channel
from the binary — a text message if you emailed the file. That is the same
idea as the word-pairs below: one channel can be tampered with, two is harder.
They check it with:

    shasum -a 256 gage-0.3.0-darwin-arm64      # macOS
    sha256sum gage-0.3.0-linux-x86_64          # Linux

Then:

    chmod +x gage-0.3.0-*
    mkdir -p ~/.local/bin && mv gage-0.3.0-* ~/.local/bin/gage
    gage --version

macOS will refuse to run it the first time, because it arrived over a channel
that quarantines it. Right-click it in Finder → **Open** → **Open**, once.
(Or `xattr -d com.apple.quarantine ~/.local/bin/gage`.) Worth saying up
front: a colleague who hits a scary "cannot be opened" dialog with no
explanation stops there — which is the whole reason the installer above is
the default.

## 2. They run one command

    gage connect https://your-relay.example.com

That makes their identity, registers a mailbox on the relay, and prints the
single line they send you. Run it again any time to see where you stand — it
keeps the identity you already have and never replaces it.

`https://` means the certificate is checked. A bare `host:port` means it is
not, which is fine on a private network and not fine across the internet;
`connect` says so at the moment the choice is made.

No relay yet? Run `gage connect` with no address. It still makes the identity
and prints the line below, and tells you the two ways to exchange without a
relay: by moving the bundle directory yourself, or with `gage lan` if you are
both on the same network.

## 3. You add each other — the one step that needs a human

`connect` prints a line that looks like this:

    gage add theirname AbC123….XyZ789…

That is public key material, so it is safe to send however you like — email,
Slack, a text. You run theirs, they run yours.

Then the part that is **not** automated, on purpose. `gage add` prints four
word-pairs for the key you just added, and `connect` printed four for your
own. **Read them to each other out loud — on a call, in person, not in the
same channel you sent the line through.** If one word differs, it is not
their key and somebody is in between.

To see the pairs again later: `gage fingerprint` for your own key, and
`gage fingerprint theirname` for a contact's. Compare that plain form — it
covers both halves of an identity. `gage fingerprint --signing-only` prints a
*different* four pairs on purpose, for confirming a connection request from
someone whose encryption key you do not have yet. If the two of you compare
different forms the words will not match, and that is not an attack.

This is the only moment where a human decides who their agent will listen to.
Everything else in gage is downstream of it: skip it, and `SENDER VERIFIED`
only ever means "this is the key I was handed", which could have come from
anyone.

## 4. Send something

    gage send --to theirname --type question --subject "spec review" \
             --prompt ask.md --file spec.md --out /tmp/pkg
    gage push /tmp/pkg --to theirname --yes

`send` will note that there is "no local route" for them. That is expected
here and is not a failure — it means it could not hand the bundle over on this
machine, which is what `push` is for. The bundle was built.

**No relay?** Then skip `push` entirely — it will tell you there is nowhere to
push to. `/tmp/pkg` is the whole bundle and it is signed, so move that
directory however you already move things: a shared folder, git, email, a USB
stick. They run `gage open <wherever-it-landed>` and get exactly the same
frame. The relay is a convenience for when you are not on the same machine or
network; it is never what makes the bundle trustworthy.

On their side, if it came through a relay:

    gage pull
    gage inbox
    gage accept <id>

If you handed the directory over yourself, there is nothing to pull and
nothing to accept — `gage open <dir>` renders it directly. `inbox` stays empty
because nothing arrived through a relay or a route, which is correct and not a
sign anything went wrong.

`accept` prints the `gage open` line to run, with the right path already in
it. Use that rather than typing a path: the home is `~/.gage` on a new
install, and still `~/.ctx` or `~/.countersign` for anyone who had this
before it was renamed.

What they see is a frame saying who signed it, whether that key is on their
list, and that nothing inside carries any authority. That is the product.

## 5. Optional: the window

    gage ui        # http://127.0.0.1:7777

A buddy list: who is on their list, who has written to them and is not, and
who they have refused. Approving someone there asks them to type one of the
four word-pairs, read off *your* screen.

## 6. Optional: back up the key before anything depends on it

    gage export-identity --out ~/gage-identity.backup

This is worth mentioning early, because the moment it matters is after four
people have confirmed their key — and by then it is too late to have done it.

`identity.key` is the one file whose loss cannot be undone. Everyone who
confirmed their word-pairs confirmed *that* key, so a dead disk means a phone
call to each of them, and mail already sealed to the old key is gone.

Say the trade out loud when you suggest it, because it is a real one: **this
turns "lose the key, lose everything" into "your security is your passphrase's
strength."** The file is encrypted, and an attacker who takes it can attack
the passphrase offline as fast as their hardware allows. So a long passphrase
and a file kept somewhere other than that machine is strictly better than no
backup; a short passphrase, or the file sitting in the same cloud folder as
everything else, is **worse** than no backup.

Restoring, on a new machine:

    gage restore-identity ~/gage-identity.backup

It prints the four word-pairs of the identity in the file before it writes
anything. Compare them against your record. It refuses to write over an
identity that is already there.

## What to expect to go wrong

- **The quarantine dialog on macOS** (step 1), if you sent a file rather than
  the installer. The most likely place to lose someone, and it looks like the
  software is broken. The installer avoids it; `Gage.app` cannot until it is
  notarised.
- **Confirming word-pairs feels like a chore** (step 3), and people will want
  to skip it. If they skip it, they have added a key they never checked, and
  the verdict `SENDER VERIFIED` then means only "this is the key you were
  given", which may have come from anyone.
- **Nothing arrives.** `gage pull` collects; it is not a daemon. `gage watch`
  polls if they want that.
