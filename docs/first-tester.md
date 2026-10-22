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

    sha256sum gage-0.3.1-linux-x86_64          # Linux
    shasum -a 256 gage-0.3.1-darwin-arm64      # Mac

Compare that to the line they sent; it must match exactly. Then:

    chmod +x gage-0.3.1-*
    mkdir -p ~/.local/bin && mv gage-0.3.1-* ~/.local/bin/gage
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

    gage connect

That creates your identity and prints two things: a line starting with
`gage add`, and four word-pairs.

If your partner gave you a relay address, use it instead —
`gage connect <that address>` — which also sets up a mailbox so you can
exchange over the internet. Without one you can still do everything here if
you are on the same network, or by sending files to each other.

Keep the output on screen. You need both parts next.

## 3. Pair — the one part that needs two humans

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

## 4. Send each other something (about 10 minutes)

Make two small files — any text will do. One is a question you want answered;
one is a document the question is about.

    gage send --to theirname --type question --subject "a test" \
              --prompt ask.md --file notes.md --out /tmp/pkg

You will see a note saying there is **"no local route"** for them. That is
expected and is not a failure — it just means it could not hand the bundle
over on this machine. The bundle was built.

Then get it to them, whichever way applies:

    gage push /tmp/pkg --to theirname --yes    # if you have a relay

If you have no relay, send them the `/tmp/pkg` directory as a zip, or run
`gage lan` on both machines if you are on the same network.

**When something arrives for you:**

    gage pull        # only if you are using a relay
    gage inbox
    gage accept <the id it shows>

`accept` prints the exact `gage open ...` line to run. Run that line.

Read what it prints carefully — this is the part we most want your reaction
to. Now swap roles, so each of you has sent one and received one.

## 5. Optional: the window

    gage ui

Opens a local page at `http://127.0.0.1:7777` showing your conversations and
who is on your list. Nothing leaves your machine.

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

That last one is the product. Everything else is plumbing to get you there.

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
