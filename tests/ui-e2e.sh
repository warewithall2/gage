#!/usr/bin/env bash
# Drive the buddy panel in a real browser. Skips, rather than fails, when the
# tools are not here: this is an addition to the shell suite and must not turn
# a missing optional dependency into a red build.
set -u
CTX="${CTX:-$PWD/target/release/countersign}"
PORT="${UI_E2E_PORT:-7931}"
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

T=$(mktemp -d); trap 'rm -rf "$T"; kill ${uipid:-0} 2>/dev/null' EXIT
mkdir -p "$T"/{u1,u2,u3,w}
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
uipid=$!
sleep 2

J=$(curl -s -H "Origin: http://127.0.0.1:$PORT" -H 'X-Ctx: 1' \
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
cd "$RUN" && CHROME="$CHROME" node ui-e2e.mjs \
  "http://127.0.0.1:$PORT" "$K" "$WANT" "wrong words"
