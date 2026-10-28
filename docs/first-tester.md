# Trying Gage — a packet for the first tester

Thank you for doing this. It should take about twenty minutes. You do not
need to know anything about the project, and you do not need to install a
compiler.

There are two of you: **you**, and **the person who sent you this**. Below,
they are "your partner". You will each end up with the other's key confirmed,
and you will send each other one piece of work.

If anything goes wrong, that is the useful part. Write it down rather than
working around it — the questions at the end ask for exactly that.

## What Gage is, in two lines

When one person's AI assistant hands work to another person's AI assistant,
nothing normally says who wrote it or whether it can be trusted. Gage wraps
that handoff so the receiving side is told who signed it, whether you have
ever confirmed that person, and that nothing inside it is an instruction.

## 1. Install it (about 3 minutes)

One line in a terminal:

    curl -fsSL https://gage.sh/install.sh | sh

It works out your OS and architecture, downloads the matching binary **and**
its published checksum, verifies the checksum before installing anything, and
puts one file in `~/.local/bin`. It never uses sudo and it never writes
anywhere else. If the checksum does not match it stops and deletes what it
downloaded.

That is a script piped into a shell, which is a thing worth being asked to
trust. Read it first if you would rather — it is short:

    curl -fsSL https://gage.sh/install.sh -o install.sh
    less install.sh && sh install.sh

Then:

    gage --version

**On a Mac this just works**, with no security dialog. The "cannot be opened
because the developer cannot be verified" warning comes from a quarantine
flag that browsers, Mail and AirDrop attach to what they download — `curl`
does not. A file your partner emails you gets that flag; the same file
fetched by the installer does not.

If `gage: command not found`, `~/.local/bin` is not on your PATH:

    export PATH="$HOME/.local/bin:$PATH"

### If your partner sent you a file instead

They may send the binary directly, with its checksum on a **separate**
channel — two channels on purpose, since tampering with the file would mean
tampering with both. Check it matches:

    sha256sum gage-*-linux-x86_64          # Linux
    shasum -a 256 gage-*-darwin-arm64      # Mac

Compare that to the line they sent; it must match exactly. Then:

    chmod +x gage-*
    mkdir -p ~/.local/bin && mv gage-* ~/.local/bin/gage
    gage --version

**On a Mac the first run will be refused** this way, because the file arrived
over a channel that quarantines it. Right-click it in Finder, choose
**Open**, then **Open** again. Once only.

### If you were sent Gage.app instead

Drag it to **Applications** and double-click it. It starts everything it
needs and opens its own window; there is no terminal step, and section 2
below happens in that window instead.

**The first open will be refused the same way.** Right-click **Gage** in
Applications, choose **Open**, then **Open** again. The app is quarantined
however it reaches you — the installer above cannot help here, because what
it installs is the command-line tool. Until the app is notarized this is
expected rather than a fault; see
[notarize-checklist.md](notarize-checklist.md). You can also skip the app
entirely and run `gage ui` from the terminal, which opens the same window.

Worth saying because it has already misled us once: an app *built* on the
machine it runs on has no quarantine flag either. So the person who sent you
the app may tell you in good faith that there is no such dialog. There is,
for you, because yours arrived over the network.

## 2. Make your identity (about 1 minute)

    gage quickstart

This walks you through the whole thing — it is the same commands the rest of
this packet spells out, asked one at a time. It will:

1. **Make your identity**, a keypair on this machine. It asks for a name,
   which is only a label; leave it empty and gage derives two words from the
   key itself.
2. **Offer to add your partner's key.** You do not have it yet, so answer
   **n** — section 4 comes back to this.
3. **Offer to send a first bundle.** Also **n** for now; section 5.

What it prints matters, so leave it on screen: a line starting with
`gage add`, which is public and which you send your partner, and **four
word-pairs**, which are not for sending anywhere — they are what you read
out loud in section 4.

Everything after this can be done either from the page or from the terminal,
and the packet shows the terminal form because it is the same on every
machine.

**If you would rather not be walked through it**, `gage connect` does the
identity step alone and prints the same two things. And if your partner gave
you a relay address, `gage connect <that address>` also sets up a mailbox so
you can exchange over the internet. Without one you can still do everything
here on the same network, or by sending files to each other.

## 3. Open the page (about 1 minute)

    gage ui

Opens a local page at `http://127.0.0.1:7777`. Leave it running in its own
terminal tab — everything below can be done from the terminal, but the page
is the easier way to see where you are.

It opens on **Setup**, a checklist of five things, each marked *done* or *not
yet* with the evidence underneath. It is not a written guide: every line is
read from this machine's own state, so it answers for your machine rather
than for the project in general. Right now it should say **one** of the five
is done — this machine has an identity, and nothing else has happened yet. By
the end of this test all five should be.

(This paragraph said "two" until a reviewer counted. It was one, and the step
about having a way to reach somebody could not be satisfied by handing a file
over at all, so following this packet to the end left you at four of five with
nothing you could do about it. Both are fixed; if the page and this paragraph
ever disagree again, the page is reading your machine and this is a sentence
somebody typed.)

The other three tabs: **Chats** is what has arrived and what you sent,
**Buddies** is whose keys you have confirmed, **Agents** is for pointing an
AI assistant at gage, which is beyond what this test needs.

Nothing on this page leaves your machine, and it never reaches the network.

## 4. Pair — the one part that needs two humans

This is the step the whole thing rests on, and it is deliberately not
automated. **Do this on a phone call or in person — not over the same
channel you used to send the key line.**

**First, swap key lines.** Send your partner your `gage add ...` line. They
send you theirs. Email, chat, anything — this is public key material and it
is safe to send in the open. Each of you runs the line the other sent:

    gage add theirname AbC123….XyZ789…

When you run it, your screen prints four word-pairs for the key you just
added. Something like:

    this key says : molten grotto · latter geyser · rugged cascade · lunar mallard

**Then, read them to each other.** On the call:

- **You read out the four pairs your own `gage connect` printed** — the ones
  for *your* key. Your partner compares them to what *their* screen shows for
  you.
- **They read out the four pairs their `gage connect` printed.** You compare
  them to what *your* screen shows for them.

So each person reads their own words, and the other person checks them. All
four pairs must match, in order. **If even one word is different, stop and
tell your partner** — that is the result this step exists to produce, and it
means something is wrong with the key you were given.

To see the words again at any time:

    gage fingerprint              # your own
    gage fingerprint theirname    # a contact's

Use that plain form for this comparison. There is a `--signing-only` option
that prints a *different* four pairs for a different situation; if one of you
uses it and the other does not, the words will not match even though nothing
is wrong.

**Last, write it down.** This is a new step and it is the one that makes the
call mean anything:

    gage confirm theirname

It asks you to type the four pairs they read out. Type them as they said them
— punctuation and capitals do not matter, the words and their order do. If
they do not match the key on your list, nothing is recorded and you should go
back to the paragraph above.

Until you run this, `gage` will say so on every bundle from them:

    trust      : SENDER ON YOUR LIST, UNCONFIRMED (signature valid, but
                 nobody here ever compared this key's word-pairs)

That is not an error and mail still arrives. It is the tool declining to claim
you did something it has no record of. Before this existed, `gage add` alone
printed `SENDER VERIFIED` — so the verdict said "a human checked this" when
all that had happened was a key being pasted, and anything that could add a
contact could manufacture it. **If you only test one thing in this packet,
test whether that distinction is clear from the output alone**, because it is
the change three reviewers asked for and the one most likely to be confusing.

After it, bundles from them read:

    trust      : SENDER VERIFIED (signature valid, key is on your list,
                 word-pairs confirmed)

## 5. Send each other something (about 10 minutes)

Make two small files — any text will do. One is a question you want answered;
one is a document the question is about.

    gage send --to theirname --type question --subject "a test" \
              --prompt ask.md --file notes.md --out /tmp/pkg

You will see a note saying there is **"no local route"** for them. That is
expected and is not a failure — it just means it could not hand the bundle
over on this machine. The bundle was built.

Then get it to them, whichever way applies:

**On the same network as your partner** — the same wifi, say — there is a
one-command form that builds it and hands it over in a single step. Run
`gage lan` in another terminal tab on *both* machines, then:

    gage send --to theirname --type question --subject "a test" \
              --prompt ask.md --file notes.md --lan

Both of you need the other on your list first (section 4), because a query
from a key you have not added is ignored on purpose. If it says it got no
answer, do not debug it — use the file path below and tell us, since that is
the kind of thing this test is for.

**If you have a relay address:**

    gage push /tmp/pkg --to theirname --yes

**Otherwise, send it as one file.** `/tmp/pkg` is a directory, and what is in
it is signed but *readable* — so seal it first, which encrypts it to your
partner's key and gives you a single file to attach:

    gage seal /tmp/pkg --to theirname --out /tmp/pkg.gageb

That envelope reveals only their key, its size and the time it was made. Send
it however you normally send a file; the channel does not have to be a private
one, which is rather the point.

**When something arrives for you:**

If it came over a relay or your own network, it is already waiting:

    gage pull        # only if you are using a relay
    gage inbox
    gage accept <the id it shows>

`accept` prints the exact `gage open ...` line to run. Run that line.

If your partner sent you a `.gageb` file instead, receive it from where you
saved it:

    gage unseal ~/Downloads/pkg.gageb
    gage inbox
    gage accept <the id it shows>

That is the same three steps as above, because a file handed over is mail like
any other: it lands unread in your inbox, `accept` prints the `gage open ...`
line to run, and you can `gage reply <id>` to answer it.

Decrypting it proves only that it was addressed to you. `gage open` is the
step that tells you who signed it and whether you have confirmed them, and it
says so itself when you unseal.

Read what it prints carefully — this is the part we most want your reaction
to. Now swap roles, so each of you has sent one and received one.

## 6. Optional: keep a copy of your key

    gage export-identity --out ~/gage-backup

Only if you intend to keep using gage after this test. The key in
`~/.gage/identity.key` is the thing your partner confirmed when you read the
word-pairs to each other — if you lose it, you would have to do that call
again, with them and with anyone else.

It asks for a passphrase twice and writes one encrypted file. The honest
version of what that buys: **it turns "lose the key, lose everything" into
"your security is that passphrase."** Use a long one, and keep the file
somewhere other than this computer. A copy of your key with a guessable
passphrase is worse than no copy at all.

To bring it back on another machine, `gage restore-identity ~/gage-backup`. It
shows you the four word-pairs before it does anything, so you can check it is
really yours.

## What success looks like

By the end you should have:

- [ ] A working `gage --version`.
- [ ] Your own identity, and your partner's key on your list.
- [ ] All four word-pairs confirmed out loud, in both directions.
- [ ] One thing you sent that they received, and one thing they sent that you
      received.
- [ ] An opened bundle where, **before** you see any of the content, you are
      told who signed it, whether that key is on your list, and that nothing
      inside carries any authority. It should say `SENDER VERIFIED`.
- [ ] The Setup tab showing all five steps done.

That second-to-last one is the product. Everything else is plumbing to get you
there.

If a step failed and you could not finish, that is still a successful test.
Stop where you are and answer the questions.

## Six questions

Please answer in your own words — short is fine, blunt is better.

1. **Where did you get stuck?** Any moment you had to re-read something,
   guess, or ask your partner what to do. Even small ones.

2. **When you opened the received bundle, what did that screen mean to you?**
   Say it back in your own words. What did you think it was telling you to do,
   or not do?

3. **Did the word-pair call feel worth doing, or did it feel like a chore
   you'd skip next time?** Be honest — if you would skip it, say so.

4. **What would you actually use this for**, if anything? A real situation
   from your own work, not a hypothetical.

5. **What did you expect it to do that it didn't?** Anything you went looking
   for and could not find counts.

6. **Would you set this up with a third person next week?** Why or why not?

Send the answers back however is easiest. Thank you — this is the first time
anyone outside the project has tried it, and the stuck points are worth more
than the parts that worked.
