# Giving ctx to someone else

Everything here assumes the other person has never seen this project and does
not want to install a compiler. Each step says what it is for, because every
one of them is a place a person gives up.

## 1. Send them a binary

From `dist/`, pick the one for their machine:

| their machine | file |
|---|---|
| Mac, Apple silicon (M1–M4) | `ctx-0.1.0-darwin-arm64` |
| Linux, 64-bit Intel/AMD | `ctx-0.1.0-linux-x86_64` |

Send the matching line from `dist/SHA256SUMS` too, over a *different* channel
from the binary — a text message if you emailed the file. That is the same
idea as the word-pairs below: one channel can be tampered with, two is harder.
They check it with:

    shasum -a 256 ctx-0.1.0-darwin-arm64      # macOS
    sha256sum ctx-0.1.0-linux-x86_64          # Linux

Then:

    chmod +x ctx-0.1.0-*
    mkdir -p ~/.local/bin && mv ctx-0.1.0-* ~/.local/bin/ctx
    ctx --version

macOS will refuse to run it the first time, because it was not downloaded
through a browser and is not notarised. Right-click it in Finder → **Open** →
**Open**, once. (Or `xattr -d com.apple.quarantine ~/.local/bin/ctx`.) This is
worth saying up front: a colleague who hits a scary "cannot be opened" dialog
with no explanation stops there.

## 2. They make an identity

    ctx init

That writes `~/.ctx/identity.key`, which is theirs and never leaves the
machine. It prints four word-pairs — their fingerprint. Those come from the
key, so nobody picks their own.

## 3. They point at your relay

    ctx join https://your-relay.example.com

`https://` means the certificate is checked. A bare `host:port` means it is
not, which is fine on a private network and not fine across the internet.

## 4. You add each other — the one step that needs a human

    ctx whoami            # both of you run this; it prints name and key

Send each other that key line. Then:

    ctx add theirname <their key>

`ctx add` prints the four word-pairs for the key you just added. **Confirm
those with them out loud — on a phone call, in person, not in the same
channel you sent the key through.** If one word differs, it is not their key.

This step cannot be automated, and that is the point: it is the only moment
where a human decides who their agent will listen to. Everything else in ctx
is downstream of it.

## 5. Send something

    ctx send --to theirname --type question --subject "spec review" \
             --prompt ask.md --file spec.md --out /tmp/pkg
    ctx push /tmp/pkg --to theirname --yes

On their side:

    ctx pull
    ctx inbox
    ctx accept <id>
    ctx open ~/.ctx/inbox/accepted/<id>

What they see is a frame saying who signed it, whether that key is on their
list, and that nothing inside carries any authority. That is the product.

## 6. Optional: the window

    ctx ui        # http://127.0.0.1:7777

A buddy list: who is on their list, who has written to them and is not, and
who they have refused. Approving someone there asks them to type one of the
four word-pairs, read off *your* screen.

## What to expect to go wrong

- **The quarantine dialog on macOS** (step 1). The most likely place to lose
  someone, and it looks like the software is broken.
- **Confirming word-pairs feels like a chore** (step 4), and people will want
  to skip it. If they skip it, they have added a key they never checked, and
  the verdict `SENDER VERIFIED` then means only "this is the key you were
  given", which may have come from anyone.
- **Nothing arrives.** `ctx pull` collects; it is not a daemon. `ctx watch`
  polls if they want that.
