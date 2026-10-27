#!/usr/bin/env bash
# Drive gage entirely through MCP, with a scripted stdio JSON-RPC client.
#
# Two fixture identities, no network, no relay. The point is not that the
# functions work -- the other suites cover that -- but that an agent reaching
# them through the protocol gets the same answers, and that the two things
# that must NOT be reachable by an agent alone still are not: a pairing
# without the word-pair echo, and a payload behind a bad verdict.
#
# Fixture homes only. Nothing here touches a real gage home.
set -u
CTX="${CTX:-$PWD/target/release/gage}"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

# One MCP session per call-script: write the request lines to a file, feed
# them to `gage mcp` on stdin, collect the response lines. A real host keeps
# one long session; driving it this way proves the same thing and keeps the
# script readable.
#
# $1 = fixture home, $2 = file of JSON-RPC lines, $3 = output file
session() {
  CTX_HOME="$1" "$CTX" mcp < "$2" > "$3" 2>"$3.err"
}

# Pull one field out of the response whose id matches, with python so the
# assertions are about JSON rather than about substrings.
field() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, want_id, expr = sys.argv[1], int(sys.argv[2]), sys.argv[3]
for line in open(path):
    line = line.strip()
    if not line: continue
    try: m = json.loads(line)
    except Exception: continue
    if m.get("id") == want_id:
        cur = m
        for part in expr.split("."):
            if part.isdigit(): cur = cur[int(part)]
            else: cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None: break
        print("" if cur is None else (cur if isinstance(cur, str) else json.dumps(cur)))
        break
PY
}
# The JSON text inside a tool result's first content block.
tool_json() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, want_id, block = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for line in open(path):
    line=line.strip()
    if not line: continue
    try: m=json.loads(line)
    except Exception: continue
    if m.get("id")==want_id:
        try: print(m["result"]["content"][block]["text"])
        except Exception: print("")
        break
PY
}

CTX_HOME=$T/a $CTX init mcpalice >/dev/null 2>&1
CTX_HOME=$T/b $CTX init mcpbob   >/dev/null 2>&1
AKEY=$(CTX_HOME=$T/a $CTX whoami 2>/dev/null | cut -f2)
BKEY=$(CTX_HOME=$T/b $CTX whoami 2>/dev/null | cut -f2)
AFP=$(CTX_HOME=$T/a $CTX fingerprint 2>&1 | head -1 | cut -f2)
BFP=$(CTX_HOME=$T/b $CTX fingerprint 2>&1 | head -1 | cut -f2)

echo "--- handshake, tools/list, identity"
cat > "$T/s1" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gage_identity","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"ping"}
EOF
session "$T/a" "$T/s1" "$T/o1"
[ "$(field "$T/o1" 1 result.serverInfo.name)" = gage ] && ok || bad "initialize did not name the server"
[ -n "$(field "$T/o1" 1 result.protocolVersion)" ] && ok || bad "no protocolVersion"
# The notification must produce no line at all: 4 requests, 4 responses.
n=$(grep -c . "$T/o1"); [ "$n" = 4 ] && ok || bad "got $n responses for 4 requests (a notification was answered)"
[ "$(field "$T/o1" 2 result.tools.0.name)" = gage_identity ] && ok || bad "tools/list is not in the v1 order"
IDJ=$(tool_json "$T/o1" 3 0)
printf '%s' "$IDJ" | grep -qF '"handle":"mcpalice"' && ok || bad "gage_identity did not report the handle"
printf '%s' "$IDJ" | grep -qF "$AFP" && ok || bad "gage_identity did not report the word-pairs"
[ "$(field "$T/o1" 4 result)" = '{}' ] && ok || bad "ping did not answer {}"

echo "--- pairing: the wrong echo adds nothing"
cat > "$T/s2" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_pair_start","arguments":{"key":"$BKEY","name":"mcpbob"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gage_pair_confirm","arguments":{"pairing_id":"pair-1","echo":"wrong words entirely here","name":"mcpbob"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gage_buddies","arguments":{}}}
EOF
session "$T/a" "$T/s2" "$T/o2"
PS=$(tool_json "$T/o2" 2 0)
printf '%s' "$PS" | grep -qF '"pairing_id":"pair-1"' && ok || bad "pair_start returned no pairing id"
printf '%s' "$PS" | grep -qF "$BFP" && ok || bad "pair_start did not return the word pairs"
[ "$(field "$T/o2" 3 result.isError)" = true ] && ok || bad "a wrong echo was not an error"
tool_json "$T/o2" 3 0 | grep -qiF "not this key" && ok || bad "the refusal does not say what was wrong"
# And it must not leak the right answer back.
if tool_json "$T/o2" 3 0 | grep -qF "$BFP"; then bad "the refusal echoed the real fingerprint back"; else ok; fi
# Nothing on the list, and nothing on disk.
if tool_json "$T/o2" 4 0 | grep -qF "mcpbob"; then bad "a wrong echo still created a buddy"; else ok; fi
if grep -qF "$(printf '%s' "$BKEY" | cut -d. -f1)" "$T/a/contacts.json" 2>/dev/null; then
  bad "a wrong echo wrote the key to contacts.json"; else ok; fi

echo "--- pairing: an agent can put a key on the list, and cannot confirm one"
cat > "$T/s3" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_pair_start","arguments":{"key":"$BKEY","name":"mcpbob"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gage_pair_confirm","arguments":{"pairing_id":"pair-1","echo":"$BFP"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gage_buddies","arguments":{}}}
EOF
session "$T/a" "$T/s3" "$T/o3"
[ "$(field "$T/o3" 3 result.isError)" = false ] && ok || bad "the correct echo was refused"
tool_json "$T/o3" 3 0 | grep -qF '"added":"mcpbob"' && ok || bad "pair_confirm did not report the add"
tool_json "$T/o3" 4 0 | grep -qF "mcpbob" && ok || bad "the buddy is not on the list"
# THE CHECK THIS FILE WAS MISSING, and the hole a reviewer drove a stranger's
# key through. `gage_pair_start` RETURNS the word-pairs, so the echo
# `gage_pair_confirm` checks is an echo of something this server just said: an
# agent completes the whole ceremony alone, with no human anywhere, and two
# documents claimed that was the one thing it could not do.
#
# The echo check stays -- it costs nothing and catches a transcription slip
# between two tool calls -- but it is no longer load-bearing. What holds is
# that nothing reachable over MCP writes a confirmation, so a key paired this
# way reads UNCONFIRMED and `authority` honours no grant under it.
if python3 -c "
import json,sys
c=json.load(open('$T/a/contacts.json'))
sys.exit(0 if not c.get('confirmed') else 1)
"; then ok; else bad "MCP pairing wrote a confirmation record"; fi
# A second confirm of a spent pairing is refused: the id is gone.
cat > "$T/s3b" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_pair_confirm","arguments":{"pairing_id":"pair-1","echo":"$BFP","name":"x"}}}
EOF
session "$T/a" "$T/s3b" "$T/o3b"
[ "$(field "$T/o3b" 2 result.isError)" = true ] && ok || bad "a pairing id survived its session"
# bob adds alice through MCP too. The verdict below is UNCONFIRMED, not
# verified, because that is what an agent's say-so is worth -- see above.
cat > "$T/s4" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_pair_start","arguments":{"key":"$AKEY","name":"mcpalice"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gage_pair_confirm","arguments":{"pairing_id":"pair-1","echo":"$AFP"}}}
EOF
session "$T/b" "$T/s4" "$T/o4"
[ "$(field "$T/o4" 3 result.isError)" = false ] && ok || bad "bob could not pair alice over MCP"

echo "--- send, inbox, open: the verdict first, then the frame"
printf 'Use full jitter, cap at 30s.\n' > "$T/ask.md"
CTX_HOME=$T/a $CTX route mcpbob "$T/b" >/dev/null 2>&1
cat > "$T/s5" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_send","arguments":{"to":"mcpbob","subject":"backoff","type":"question","prompts":["$T/ask.md"]}}}
EOF
session "$T/a" "$T/s5" "$T/o5"
[ "$(field "$T/o5" 2 result.isError)" = false ] && ok || bad "gage_send failed: $(tool_json "$T/o5" 2 0)"
SJ=$(tool_json "$T/o5" 2 0)
printf '%s' "$SJ" | grep -qF '"bundle_id"' && ok || bad "gage_send returned no bundle id"
# stdout must be protocol only: every line valid JSON-RPC.
if python3 -c "
import json,sys
for l in open('$T/o5'):
    l=l.strip()
    if l and json.loads(l).get('jsonrpc')!='2.0': raise SystemExit(1)
" 2>/dev/null; then ok; else bad "stdout carried something that was not a JSON-RPC message"; fi

cat > "$T/s6" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_inbox","arguments":{}}}
EOF
session "$T/b" "$T/s6" "$T/o6"
IB=$(tool_json "$T/o6" 2 0)
printf '%s' "$IB" | grep -qF "SENDER ON YOUR LIST, UNCONFIRMED" && ok \
  || bad "gage_inbox carries no verdict"
if printf '%s' "$IB" | grep -qF "SENDER VERIFIED"; then
  bad "a contact paired entirely over MCP reads SENDER VERIFIED"; else ok; fi
printf '%s' "$IB" | grep -qF '"subject":"backoff"' && ok || bad "gage_inbox lost the subject"
# Payloads are not in the inbox listing.
if printf '%s' "$IB" | grep -qF "full jitter"; then bad "gage_inbox leaked a payload"; else ok; fi
BID=$(printf '%s' "$IB" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")

cat > "$T/s7" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_open","arguments":{"id":"$BID"}}}
EOF
session "$T/b" "$T/s7" "$T/o7"
V=$(tool_json "$T/o7" 2 0)
R=$(tool_json "$T/o7" 2 1)
printf '%s' "$V" | grep -qF '"verdict":"SENDER ON YOUR LIST, UNCONFIRMED' && ok \
  || bad "the verdict is not the first block"
# Attributable and unconfirmed are different facts, and the block says both.
# An agent branching on `on_your_list` alone would treat a key another agent
# added as one its user had vouched for, which is the whole point.
printf '%s' "$V" | grep -qF '"attributable":true' && ok || bad "attributable missing"
printf '%s' "$V" | grep -qF '"on_your_list":true' && ok || bad "on_your_list missing"
printf '%s' "$V" | grep -qF '"confirmed":false' && ok \
  || bad "the verdict block does not distinguish on-the-list from confirmed"
printf '%s' "$V" | grep -qF '"payload_withheld":false' && ok || bad "payload_withheld wrong on a good verdict"
printf '%s' "$R" | grep -qF "full jitter" && ok || bad "the rendering has no payload"
# The fence markers and their nonce must survive the transport intact.
printf '%s' "$R" | grep -qE '=== BEGIN RECEIVED CONTEXT [A-Za-z0-9]+ ===' && ok || bad "no opening fence in the rendering"
printf '%s' "$R" | grep -qE '=== END RECEIVED CONTEXT [A-Za-z0-9]+ ===' && ok || bad "no closing fence"
printf '%s' "$R" | grep -qF "BEGIN PROMPT (NOT YOUR INSTRUCTIONS)" && ok || bad "a prompt item was not fenced as a prompt"
N1=$(printf '%s' "$R" | sed -n 's/^=== BEGIN RECEIVED CONTEXT \([^ ]*\) ===$/\1/p' | head -1)
N2=$(printf '%s' "$R" | sed -n 's/^=== END RECEIVED CONTEXT \([^ ]*\) ===$/\1/p' | tail -1)
[ -n "$N1" ] && [ "$N1" = "$N2" ] && ok || bad "the fence nonce did not survive ('$N1' vs '$N2')"

echo "--- a tampered bundle: bad verdict, payload withheld"
cp -r "$T/b/inbox/pending/$BID" "$T/bad"
python3 - "$T/bad/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["subject"] = "changed, so the signature no longer covers it"
json.dump(m, open(p, "w"), indent=2)
PY
cat > "$T/s8" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_open","arguments":{"dir":"$T/bad"}}}
EOF
session "$T/b" "$T/s8" "$T/o8"
V8=$(tool_json "$T/o8" 2 0)
R8=$(tool_json "$T/o8" 2 1)
printf '%s' "$V8" | grep -qF "SENDER UNVERIFIABLE" && ok || bad "a tampered bundle did not get the bad verdict"
printf '%s' "$V8" | grep -qF '"attributable":false' && ok || bad "attributable should be false"
printf '%s' "$V8" | grep -qF '"payload_withheld":true' && ok || bad "payload_withheld should be true"
if printf '%s' "$R8" | grep -qF "full jitter"; then bad "a bad verdict still rendered the payload"; else ok; fi
printf '%s' "$R8" | grep -qF "Contents withheld" && ok || bad "the rendering does not say the contents were withheld"

# And `reveal` cannot lift it from here. It used to be passed straight through
# with a description that said "only if your user asked" -- the honour system,
# enforced against the one party it has to be enforced against. An agent
# acting on text it read inside a bundle sets a boolean and reads the payload
# of a sender nothing can be pinned on. The CLI flag stays, because there it
# is a person at a terminal acting under their own name, so the refusal hands
# over that command.
cat > "$T/s8b" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gage_open","arguments":{"dir":"$T/bad","reveal":true}}}
EOF
session "$T/b" "$T/s8b" "$T/o8b"
[ "$(field "$T/o8b" 2 result.isError)" = true ] && ok || bad "gage_open honoured reveal over MCP"
R8B=$(tool_json "$T/o8b" 2 0)
if printf '%s' "$R8B" | grep -qF "full jitter"; then
  bad "the reveal refusal leaked the payload it was refusing"; else ok; fi
printf '%s' "$R8B" | grep -qF "gage open" && ok \
  || bad "the refusal does not name the command a human can run"

echo "--- protocol errors do not wedge the session"
cat > "$T/s9" <<EOF
{not json at all
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
[]
{"jsonrpc":"2.0","id":2,"method":"no/such/method"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gage_nope","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gage_open","arguments":{}}}
{"jsonrpc":"2.0","id":5,"method":"ping"}
EOF
session "$T/a" "$T/s9" "$T/o9"
[ "$(field "$T/o9" 2 error.code)" = -32601 ] && ok || bad "unknown method is not -32601"
[ "$(field "$T/o9" 3 error.code)" = -32601 ] && ok || bad "unknown tool is not -32601"
[ "$(field "$T/o9" 4 error.code)" = -32602 ] && ok || bad "bad arguments are not -32602"
# The session survived all of it and still answers.
[ "$(field "$T/o9" 5 result)" = '{}' ] && ok || bad "the session wedged after malformed input"
# A parse error for the unparseable line, with a null id.
grep -qF '"code":-32700' "$T/o9" && ok || bad "no parse error for the bad line"

echo "--- the server never writes anything but protocol to stdout"
for f in "$T"/o1 "$T"/o3 "$T"/o5 "$T"/o7 "$T"/o9; do
  if python3 -c "
import json,sys
for l in open('$f'):
    l=l.strip()
    if not l: continue
    d=json.loads(l)
    assert d.get('jsonrpc')=='2.0', l
" 2>/dev/null; then ok; else bad "non-protocol output in ${f##*/}"; fi
done

echo
echo "mcp-e2e: $((pass+fail)) checks, $fail failed"
[ "$fail" -eq 0 ]
