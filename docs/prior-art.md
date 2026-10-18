# Prior art: what is already built, and what is left

Written 15 Oct 2026, after the name "Signet" was proposed for this project and
the search turned up two existing projects of that name doing adjacent work.
The naming problem is the small half. The useful half is that one of them has
already shipped three of the four items that were top of this roadmap, which
changes what is worth building here.

## Prismer-AI/signet

<https://github.com/Prismer-AI/signet>. Apache-2.0 / MIT, 346 commits,
`signet-core` 0.11.0 on crates.io, `signet-auth` on PyPI, the
`@signet-auth/*` npm scope, and a Claude Code plugin. Active, not a stub.

**What it does.** Every *tool call* an agent makes gets an Ed25519-signed
receipt over the action, signer, timestamp and nonce, canonicalised with RFC
8785, appended to a local hash-chained log. `signet proxy` sits in front of an
MCP server as a stdio proxy and injects the receipt into
`params._meta._signet`, so neither the agent nor the server changes. The
server side verifies with `verifyRequest(..., trustedKeys)` at its execution
boundary. Delegation: a root key grants scoped authority (`--tools`,
`--targets`, `--ttl`, `--max-depth`, and since 0.11 `--max-calls` and
`--spend-limit`), permissions may narrow and never widen, and a v4 receipt
carries the chain as proof of authorisation. `signet revoke` invalidates a
token.

**Where it agrees with ctx.** Verification is local and offline against keys
the verifier already holds. There is no registry and no hosted control plane;
its README says so explicitly. So "the receiver decides, with no central
authority" is **not** a differentiator for ctx. Two independent projects
reached it, which is evidence the property is right rather than evidence it is
ours.

**What it has that ctx does not.**

- Allowlisted delegation with narrowing scopes and expiry — [decision
  6](open-decisions.md#6-receiver-side-delegation-who-may-act-on-a-request)
  here, unbuilt.
- A hash-chained audit log — decision 4 here, unbuilt.
- An MCP integration — item 1 of the build order, unbuilt.

That is three for three on what was queued. Building them as planned would
have been building a worse second copy.

**What it does not do, and does not claim to.** Nothing in its README
addresses how a *receiving* agent should treat content it was handed. No
framing, no fencing, no withholding of contents on a bad verdict, no statement
that a signed document carries no authority. That is consistent with its
design rather than an oversight: its unit is an outbound tool call, not an
inbound document. Its own non-goals say it "does not replace sandboxing,
least-privilege design, or human approval where those are required", and that
it cannot yet prove that a key's claimed owner controls it.

## kodandy/signet

<https://github.com/kodandy/signet>. "Cryptographic authorization delegation
layer for local AI agents" — Ed25519 delegation tokens and hash-chained logs.
Same shape, smaller. Named here because it also holds the name.

## kravadk/Signet

On-chain provenance on Sui and Walrus. Unrelated beyond the word.

## So is the idea taken?

No, but the sentence this project has been describing itself with is.

"Signed context with local trust and no central authority" describes Prismer's
Signet as accurately as it describes ctx. The part that does not transfer is
the axis each one signs along:

|  | Prismer's Signet | ctx |
| --- | --- | --- |
| Unit | one agent's outbound tool call | a document handed to another agent |
| Question answered | did this agent really do this, under whose grant | who wrote this, and may I act on it |
| Boundary | the executing server's admission check | the receiving model's context window |
| Failure it prevents | an unattributable or out-of-scope action | a payload read as an instruction |
| Reader of the verdict | an auditor, or a server, later | the model, right now, before it acts |

Their verdict is read by a program at the execution boundary. Ours is read by
a language model in the seconds before it decides what to do. That is why
`gage open` spends its effort on nonced fences, labels that are not prefixes of
one another, and withholding contents rather than annotating them: the reader
can be talked out of its conclusion, which is not a hazard a `verifyRequest`
call has.

The honest positioning is therefore **the receiving agent's half of the trust
boundary**, and the headline evidence for it is already in the repo: in
[the dogfood log](dogfood-2026-10-15.md), two of three agents read a verified
request from a verified contact and declined to act on it, because `gage open`
told them the contents carried no authority. A receipt layer does not produce
that behaviour, because it is not in the conversation.

## The MCP question, decided

An MCP server for ctx was item 1 of the build order. It is **not** the same
thing as Prismer's proxy — theirs signs calls passing through, ours would
expose `gage inbox`, `gage open` and `gage reply` as tools so an agent need not
have a shell. No overlap. It is still deferred, for two reasons that came out
of the dogfood rather than out of the competitive picture:

1. **Access was never the blocker.** Grok found the skill, ran the binary and
   read its inbox unaided. It then declined to act, correctly, for want of
   authority. An MCP server removes friction that was not stopping anyone.
2. **It puts the frame on a transport that weakens it.** `gage open`'s defence
   is a nonced text fence in stdout that the model reads as data. Over MCP the
   same text arrives as a *tool result*, which harnesses present as the
   tool's own trustworthy output, and some summarise or truncate it. The
   nonce still cannot be forged, but a fence the harness may reformat around
   is a weaker fence than one in a terminal, and the whole point of the
   product is on that side. Doing it properly means deciding what the frame
   looks like when the receiver is a tool-call result, which is a design task.

One genuine argument for it: the server process would own `CTX_HOME`, which
would close the identity footgun that fired during the dogfood when grok ran
`gage` with no `CTX_HOME` and reported owen's inbox as its own. Worth having,
not worth leading with.

**So: receiver-side authority first, MCP after it, and designed with the
framing question answered rather than inherited.**
