#!/usr/bin/env bash
# Drive the viewer in a real browser: the buddy panel's confirmation gate,
# and the first-run front door from nothing to a sent-and-verified bundle.
# Skips, rather than fails, when the tools are not here: this is an addition
# to the shell suite and must not turn a missing optional dependency into a
# red build.
#
# Every runtime probe below pins CTX_HOME to a directory under this script's
# own temp dir. Nothing here reads the machine's real home -- a test that
# touches the identity it is testing around is a test that can lose it.
set -u
CTX="${CTX:-$PWD/target/release/gage}"
PORT="${UI_E2E_PORT:-7931}"
FRPORT="${UI_E2E_FIRSTRUN_PORT:-7932}"
RXPORT="${UI_E2E_RECEIVE_PORT:-7933}"
LANPORT="${UI_E2E_LISTEN_PORT:-7934}"
CHROME="${CHROME:-/usr/bin/chromium}"
HERE=$(cd "$(dirname "$0")" && pwd)

MOD=$(find "$HOME/.local/share/mise/installs/npm-playwright" -maxdepth 4 \
      -type d -name node_modules -path '*/.mise/*' 2>/dev/null | head -1)
[ -z "$MOD" ] && MOD=$(node -e "console.log(require.resolve('playwright'))" 2>/dev/null \
                       && echo "")
if [ ! -x "$CHROME" ] || [ -z "$MOD" ]; then
  echo "ui-e2e: skipped (needs playwright and a chromium at \$CHROME)"
  exit 0
fi

T=$(mktemp -d)
pids=""
trap 'rm -rf "$T"; for p in $pids; do kill "$p" 2>/dev/null; done' EXIT
mkdir -p "$T"/{u1,u2,u3,fa,fb,w}
fail=0

# ---------------------------------------------------------------------------
# Scenario 1: the buddy panel's confirmation gate.
# ---------------------------------------------------------------------------
for h in u1 u2 u3; do CTX_HOME=$T/$h $CTX init $h >/dev/null 2>&1; done
K1=$(CTX_HOME=$T/u1 $CTX whoami | cut -f2)
printf 'the quarterly numbers\n' > "$T/w/f.md"
for h in u2 u3; do
  CTX_HOME=$T/$h $CTX add u1 "$K1" >/dev/null 2>&1
  CTX_HOME=$T/$h $CTX route u1 "$T/u1" >/dev/null
  CTX_HOME=$T/$h $CTX send --to u1 --type question --subject "review this" \
    --prompt "$T/w/f.md" >/dev/null 2>&1
done
# u2 goes on the list, so exactly one request is left and the script knows
# whose it is.
CTX_HOME=$T/u1 $CTX add u2 "$(CTX_HOME=$T/u2 $CTX whoami | cut -f2)" >/dev/null 2>&1
CTX_HOME=$T/u1 $CTX inbox >/dev/null 2>&1
CTX_HOME=$T/u1 $CTX ui --port "$PORT" >/dev/null 2>&1 &
pids="$pids $!"
sleep 2

J=$(curl -s -H "Origin: http://127.0.0.1:$PORT" -H 'X-Gage: 1' \
    "http://127.0.0.1:$PORT/api/buddies")
read -r K PAIR <<<"$(printf '%s' "$J" | python3 -c "
import sys,json
r=json.load(sys.stdin)['requests']
if len(r)!=1: raise SystemExit('expected exactly one request, got %d' % len(r))
print(r[0]['key'], r[0]['ask_pair'])")" || { echo "ui-e2e: fixture is wrong"; exit 1; }
WANT=$(CTX_HOME=$T/u3 $CTX fingerprint --signing-only 2>/dev/null | head -1 | cut -f2 \
       | awk -F' · ' -v n="$PAIR" '{print $n}')

RUN=$T/run; mkdir -p "$RUN"; ln -s "$MOD" "$RUN/node_modules"
cp "$HERE/ui-e2e.mjs" "$RUN/"
cd "$RUN" || exit 1
scenario() { CHROME="$CHROME" node ui-e2e.mjs "$@" || fail=$((fail+1)); }

scenario buddies "http://127.0.0.1:$PORT" "$K" "$WANT" "wrong words"

# ---------------------------------------------------------------------------
# Scenario 2 and 3: the front door. `fa` has NO identity and never touches a
# terminal -- everything on that side happens in the page, which is the claim
# the first-run work makes. `fb` is the buddy on the other end of the voice
# call, and the CLI builds it: it stands in for a second machine that is
# already set up.
# ---------------------------------------------------------------------------
CTX_HOME=$T/fb $CTX init buddyb >/dev/null 2>&1
BTOK=$(CTX_HOME=$T/fb $CTX whoami 2>/dev/null | cut -f2)
# The short label is what a nearby list shows, and `whoami` prints it in the
# block it writes to stderr.
BLAB=$(CTX_HOME=$T/fb $CTX whoami 2>&1 | sed -n 's/^ *shown as *: *//p')

# `gage listen` on loopback, so the bundle the page sends has somewhere real
# to land: the send path is the CLI's own and it ends in a TCP delivery. Its
# query port is moved off the default, because this suite must not fight for
# a socket with anything else on the machine.
CTX_HOME=$T/fb CTX_LAN_QUERY_BIND=22989 CTX_LAN_QUERY_DEST=22989 \
  $CTX listen --bind 127.0.0.1 --port "$LANPORT" > "$T/listen.log" 2>&1 &
pids="$pids $!"

# What `gage lan` would have written while it ran, written here instead. The
# alternative is a real announcement, and a broadcasting `gage lan` in a test
# shares this machine's network with every other LAN check -- which is the
# collision the suite's own preflight warns about. The page cannot tell the
# difference: `/api/nearby` reads this file and never announces.
python3 - "$T/fa/nearby.json" "$BTOK" "$BLAB" "$LANPORT" <<'PY'
import json, sys, time
p, tok, lab, port = sys.argv[1:5]
sign, box = tok.split(".", 1)
json.dump([{"label": lab, "handle": "buddyb", "sign": sign, "boxpub": box,
            "addr": "127.0.0.1:%s" % port, "at": int(time.time())}], open(p, "w"))
PY

CTX_HOME=$T/fa $CTX ui --port "$FRPORT" > "$T/fa-ui.log" 2>&1 &
pids="$pids $!"
sleep 2

# A last check on the fixture itself before the browser opens: if `fa` has an
# identity already then this is not a first run and a green result would mean
# nothing.
if [ -e "$T/fa/identity.key" ]; then
  echo "ui-e2e: the first-run fixture already has an identity"
  exit 1
fi

scenario firstrun "http://127.0.0.1:$FRPORT" "front runner" "$BLAB" \
         "buddy b" "Hello from the page" > "$T/fr.out" 2>&1
sed '/^WORDS /d' "$T/fr.out"

# The words the page showed are this key's own. Checked out here, against
# what the CLI renders from the key on disk, because a page that shows four
# plausible words from somewhere else would pass every check inside it.
if [ -e "$T/fa/identity.key" ]; then
  AFP=$(CTX_HOME=$T/fa $CTX fingerprint 2>/dev/null | cut -f2)
  SHOWN=$(sed -n 's/^WORDS //p' "$T/fr.out" | head -1)
  if [ "$SHOWN" = "$AFP" ]; then :; else
    fail=$((fail+1))
    echo "  FAIL: the page showed $SHOWN; the key says $AFP"
  fi
  # The handle it was given, and not one the page invented.
  CTX_HOME=$T/fa $CTX whoami 2>/dev/null | cut -f1 | grep -qx 'front runner' || {
    fail=$((fail+1)); echo "  FAIL: the identity the page created is not the handle that was typed"; }
else
  fail=$((fail+1))
  echo "  FAIL: the wizard ran and no identity exists in the first-run home"
fi

# Now the other end puts the new key on its list -- the half of the voice
# call that happens on the other machine -- so what `fb`'s console renders is
# a verdict about a key it has confirmed.
AKEY=$(CTX_HOME=$T/fa $CTX whoami 2>/dev/null | cut -f2)
if [ -n "$AKEY" ]; then
  CTX_HOME=$T/fb $CTX add frontrunner "$AKEY" >/dev/null 2>&1
fi
CTX_HOME=$T/fb $CTX ui --port "$RXPORT" > "$T/fb-ui.log" 2>&1 &
pids="$pids $!"
sleep 2
scenario receive "http://127.0.0.1:$RXPORT" "Hello from the page" "frontrunner"

echo
[ "$fail" -eq 0 ] && echo "ui-e2e: ok" || echo "ui-e2e: $fail scenario(s) failed"
[ "$fail" -eq 0 ]
