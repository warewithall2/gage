# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

Only the 0.1.x line receives security fixes. Earlier prototypes, and builds
carrying the former `ctx` / `countersign` names, are not supported.

## Reporting a vulnerability

Report privately, by email, to **owenware92@gmail.com**. Please do not open a
public issue for a vulnerability — a public report is a working exploit handed
to everyone running the tool before there is anything to upgrade to.

Useful things to include, as far as you have them:

- what an attacker gains, and what they must already hold to try it
- the smallest reproduction you can manage, with the commit or release
- which trust boundary it crosses

You will get an acknowledgement. Once there is a fix, we will agree on
disclosure timing with you, and you will be credited unless you would rather
not be.

## Scope and threat model

Read the threat model before reporting, so we can talk about the same
boundary:

- `README.md` — "The receiving agent's half of the trust boundary",
  "Keys, said out loud", "Authority: the one thing that says you may act",
  "Encryption", "Outbound safety", "Relay", "Key rotation", and
  "What this is not", which states plainly what is *not* defended.
- `docs/` — design notes, including `offline-root.md`,
  `lan-discovery-design.md`, `nested-forward-design.md`, and
  `open-decisions.md` for questions that are knowingly still open.
- `docs/reviews/` — prior adversarial review rounds and their dispositions.
- `tests/attacks.sh` — attacks that worked, or nearly worked, during
  development, kept as regressions.

A behaviour that `README.md` already names as out of scope is not a
vulnerability, but a convincing argument that it should be in scope is worth
sending.
