# What gage does not stop

Written 22 October 2026, against the agent-security incidents that were
public at the time. `docs/threat-model.md` lists adversaries and non-goals in
the abstract. This file does the more uncomfortable version: real incidents,
named, with an honest answer about each.

It exists because a security tool that lets people believe it covers more
than it does has done them harm, and because the fastest way to lose a
reader's trust is for them to work out the limit themselves.

## The short answer

**gage would not have prevented any of the publicly reported agent
compromises of 2026.** Every one of them arrived through an open channel —
a web page, a pull-request title, an issue title, an email, a package
registry. gage governs messages between two parties who have confirmed each
other's keys. It never sees any of those channels.

| Incident | Vector | Would gage have helped? |
|---|---|---|
| Cursor sandbox escape (CVE-2026-50548/9) | injection in fetched content → RCE | **No.** Content came from the web and the repo. |
| AutoJack (Microsoft research, Jun 2026) | malicious web page hijacks a browsing agent | **No.** |
| Coding-agent key leak (Claude Code Security Review action, Gemini CLI Action, Copilot Agent) | a **PR title** talks the agent into posting its own API key | **No.** |
| Cline triage bot → backdoored `cline@2.3.0`, ~4,000 machines | a **GitHub issue title** → npm typosquat → supply chain | **No.** |
| Microsoft 365 Copilot zero-click (CVE-2025-32711) | a crafted email extracts data | **No.** |

Anyone selling you a tool that claims otherwise about this list is selling
you something.

## What gage is actually for, stated narrowly

One channel: a signed bundle handed from an identified party to a reader who
has confirmed that party's key out of band. On that channel it does three
things nothing else in the handoff does — the key is confirmed by humans
comparing word-pairs, arrival is separated from acceptance, and the reading
agent is handed a frame that says the contents are data carrying no
authority, with contents withheld rather than annotated on a bad verdict.

If your agents exchange work through that channel, those properties hold. If
they read the web, their issue tracker, their email or their package manager
— and they do — gage is not in the path.

## The part worth taking from the incidents

Every one of them is the same sentence: **content from an untrusted source
entered an agent's context and was treated as instruction.**

That is this project's thesis, and the incidents are evidence for it. The
honest reading is uncomfortable in a useful way: the *idea* generalises and
the *product* does not. Nonced fences, trust computed rather than carried,
withholding rather than annotating, "this is data and carries no authority"
— none of that depends on the content arriving as a signed bundle. A PR
title and a fetched page could go through the same frame.

That is a much larger surface than bundle transport, and it is the argument
in `docs/drafts/a2a-issue-draft.md`: identity verification establishes who
sent a message and says nothing about whether acting on it is safe.

## Where gage is the one exposed, not the one defending

**gage ships an MCP server.** Several 2026 findings are about malicious MCP
servers attacking the clients that load them — `mcp-remote` RCE
(CVE-2025-6514), Trail of Bits' "line jumping" (a server reaches the model
through tool descriptions before any tool is called), and vaguer reports of
command injection via the STDIO transport. That is a category gage sits
inside.

Audited on 22 October 2026, against those classes:

- **Tool-description injection / line jumping: not applicable.** Every tool
  description in `src/mcp.rs` is a static string compiled into the binary.
  There is no path by which a sender, a contact or a bundle can alter what
  the host model reads at `tools/list`.
- **Command injection via the transport: not applicable.** The MCP server
  spawns no subprocess and invokes no shell. It is stdin, stdout and
  `serde_json`.
- **Tool-result injection: this is the real surface, and one hole was found
  and fixed.** See below.
- **Token passthrough / confused deputy: not applicable.** There are no
  tokens, no OAuth, and no upstream service to be confused about.
- **What remains true and is not a bug:** the server acts with the identity's
  full authority for anything the CLI can do unattended, and any local
  process that can spawn it has that authority. It is not a sandbox and does
  not claim to be.

- **An agent CAN put a key on the buddy list alone.** This bullet used to
  claim the opposite — "the single exception is that it cannot put a key on
  the buddy list alone — `gage_pair_confirm` needs the word-pairs echoed
  back" — and a reviewer drove a stranger's key through it in two tool calls.
  `gage_pair_start` *returns* the word-pairs, so the echo
  `gage_pair_confirm` checks is an echo of something the server just said.
  The check catches a transcription slip between two calls. It cannot catch
  an agent that never asked a human, which is the only attacker here.

  What is true instead is narrower and holds: **nothing reachable over MCP
  writes a confirmation.** A key paired this way is on the list and reads
  `SENDER ON YOUR LIST, UNCONFIRMED`; it never reads `SENDER VERIFIED`, and
  `authority` honours no grant under it. Only a human typing four word-pairs
  back — `gage confirm`, or the viewer's confirm step, which shows none of
  them — produces the stronger verdict.

  The limit of *that*, stated here rather than left for the next review: an
  agent with **shell** access is not bound by it. It can run `gage
  fingerprint` and `gage confirm` in sequence, or simply write
  `contacts.json`. Nothing in a program can stop a process that can write
  that program's files. The boundary is the MCP surface — a tool-using model
  with no shell — and that is the surface this claim is about.

### The hole the audit found: the subject walked past the accept gate

`gage_inbox` returns a row per waiting bundle. Those rows carried the
sender's `subject` and claimed handle **raw and unbounded**, while every
human-facing print in `main.rs` routed the same strings through `one_line`.

That is backwards, and backwards in the direction this project exists to get
right: a human skimming a listing is not executing it, and the agent reading
the same listing is.

Measured before the fix: a sender **nobody had confirmed**, whose bundle
**nobody had accepted**, delivered 441 bytes of instruction-shaped text into
a reading agent's context — because listing an inbox is not accepting
anything. The payload stayed behind the accept gate. The subject did not.

It is the same shape as the Cline incident, where the injection was in a
GitHub issue *title*.

Fixed by `manifest::safe_display`: escaped so it cannot forge a line of a
frame, and bounded with the truncation announced rather than silent. The
tool description now tells the agent, where it will read it, that `subject`
and `from_handle_claimed` are sender-chosen.

**Be precise about what that fix is.** Bounding caps an attacker's budget;
it does not remove the injection. 160 characters is still room for a short
one. What actually informs the reader is the verdict printed beside it —
`SENDER NOT ON YOUR LIST` — and that was always correct. A stronger option
is open and not taken: grade the display budget by trust, so an unconfirmed
sender gets far less room than a confirmed one.

## "Memory-safe because Rust" would be an overclaim

Added 22 October 2026, the day PHP2Shell was patched — two use-after-frees
and an OPcache type confusion in PHP's core engine (CVE-2026-109618,
CVE-2026-109619, CVSS 9.2), pre-authentication RCE on WordPress, Drupal and
Joomla, affecting every PHP release back to 5.4. Found by three
model-assisted research teams, not by an attacker.

**Nothing about that class touches gage**, which is not an interpreter and
does not parse multipart requests. The relevance is the other direction: the
same tooling that found decade-old memory corruption in the most deployed
runtime on earth will be pointed at everything else, and gage is not
exempt.

So, the honest inventory rather than the comfortable sentence:

    76 unique crates in the dependency tree
    ring v0.17.14   -- C and hand-written assembly
    cc, libc        -- present
    aws-lc-sys      -- absent, deliberately (see Cargo.toml)
    openssl-sys     -- absent

gage's own code is Rust, and its TLS and crypto primitives bottom out in C
and assembly through `ring`. That is a reasonable choice and the manifest
explains it. It is not the same as "memory-safe", and a security tool should
not let a reader round it up to that.

The related discipline already in the manifest — five new crates rather than
seventeen, no primitive at two versions — is the thing that actually bounds
this, and it reads better in October than it did when it was written.

### What the first dependency audit found

`cargo audit` was run against the tree for the first time on 22 October 2026,
in the same hour as the above. It found two advisories, **both published that
week**, and both in the one area where this project's dependencies do
security-relevant work:

| Advisory | Crate | What |
|---|---|---|
| RUSTSEC-2026-0382 (20 Oct) | `rustls-webpki` 0.103.15 | certificate verification may accept distrusted intermediates |
| RUSTSEC-2026-0381 (19 Oct) | `webpki-roots` 1.0.9 | bundled roots allow trust in distrusted emSign intermediates |

Fixed by moving to `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10, which
is a lockfile change and nothing else.

**What was actually at risk, stated honestly.** Bundle payloads are sealed to
the recipient's box key, so TLS here is defence in depth rather than the thing
keeping contents private — `docs/spec.md` and the README's relay section both
say TLS is present *despite* the payload being sealed. What a bad certificate
chain would have exposed is the relay protocol and its metadata: which
mailbox, how often, how large. That is worth protecting and is not the same
as "the payload was at risk".

**The lesson is the cadence, not the bugs.** Both advisories were days old.
Nobody had run an audit before because the dependency list is short and
hand-justified, which is exactly the reasoning that makes a tree feel safe
without being checked. `cargo audit` is cheap and this project does not
currently run it anywhere.

## Known gaps, named

- **Send-side restraint does not exist.** The authority file governs what an
  agent may act *on*; nothing governs what it may *send*. An injected agent
  with a grant cannot be made to act on a stranger's message, but it can be
  talked into sending anything to anyone already on its list. The outbound
  content scan (`src/scrub.rs`) refuses on secret-shaped content, which is a
  real mitigation and not the same thing. This is the shape of the Cline
  chain one hop earlier, and it is listed as "not on the plan" in
  `docs/thesis-and-plan.md` because the answer is not obvious.
- **The frame cannot make a model obey it.** Stated in the threat model and
  worth repeating here: everything above is about what the reader is *told*.
  `tests/injection/` is the only test of whether a reader *behaves*
  differently, it has to be written by a human, and as of this date it has
  not been run.
- **The journal is rewritable up to the last anchor.** See
  `docs/adr-journal-anchoring.md`.
- **Nothing here is notarised.** `Gage.app` is quarantined however it
  arrives.

## How to keep this file honest

When a new agent-security incident is public, add a row and answer the
question. If the answer is ever "yes, gage would have stopped that", it
needs the same standard of evidence as anything else here: which gate, on
which channel, and a test that fails when the gate is removed.
