#!/usr/bin/env bash
# Build and run every suite, and say plainly whether this machine is good.
#
# It exists because of what happened on 17 October: the suite had never been
# run on the second machine, and when it finally was it reported six
# failures. None was a defect in ctx -- but one of them claimed an unbounded
# auto-accept grant had accepted a bundle, which is a security property, and
# the suite was simply wrong. Nothing would have told anybody. A suite that
# runs only on the machine it was written on, only when someone remembers,
# is a suite you cannot cite.
#
# Designed for a timer, so it is quiet when it passes and specific when it
# does not. Exit 0 means this machine is good at this commit.
set -u

cd "$(dirname "$0")/.." || exit 2
REPO=$PWD
OUT="${CTX_SELFCHECK_DIR:-$HOME/.ctx-selfcheck}"
mkdir -p "$OUT"
LOG="$OUT/last.log"
STATUS="$OUT/status"
: > "$LOG"

say()  { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() {
  say "FAILED: $*"
  printf 'fail\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)" "$*" > "$STATUS"
  # Tell the person at the machine. Best effort on each platform, and never
  # fatal: a missing notifier must not turn a passing run into a failure or
  # a failing one into silence -- the log and the exit code are the record.
  if command -v notify-send >/dev/null 2>&1; then
    notify-send -u critical "ctx selfcheck failed" "$* -- see $LOG" 2>/dev/null || true
  elif command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$* -- see $LOG\" with title \"ctx selfcheck failed\"" 2>/dev/null || true
  fi
  exit 1
}

say "ctx selfcheck on $(uname -s) $(uname -m), $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Preflight: the suite binds fixed ports, and a stray listener on one of them
# once produced 28 failures that looked like real defects and were not. Say
# so up front rather than letting the suite blame the code.
BUSY=""
for p in 7799 7809 7813 7891 7892 7893 7895 7898 7903 7905; do
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":$p " && BUSY="$BUSY $p"
  else
    netstat -an -p tcp 2>/dev/null | grep -i listen | grep -q "\.$p " && BUSY="$BUSY $p"
  fi
done
[ -n "$BUSY" ] && fail "ports in use by something else:$BUSY (the suite needs them; a stray \`ctx ui\` is the usual cause)"

# The working tree must be clean, or the result describes code nobody has.
if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
  say "note: working tree is dirty; testing it as it stands"
fi
HEAD=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
say "commit $HEAD"

command -v cargo >/dev/null 2>&1 || . "$HOME/.cargo/env" 2>/dev/null
command -v cargo >/dev/null 2>&1 || fail "no cargo on PATH"

say "building..."
cargo build --release >>"$LOG" 2>&1 || fail "the release build did not compile"

say "unit tests..."
UNIT=$(cargo test --release 2>&1 | tee -a "$LOG" | grep -E '^test result' | head -1)
printf '%s\n' "$UNIT" | grep -q ' 0 failed' || fail "unit tests: ${UNIT:-no result line}"
NU=$(printf '%s' "$UNIT" | sed -n 's/.*ok\. \([0-9]*\) passed.*/\1/p')

say "attack suite..."
ATT=$(bash tests/attacks.sh 2>&1 | tee -a "$LOG" | grep -E '[0-9]+ checks,' | tail -1)
printf '%s\n' "$ATT" | grep -q ', 0 failed' || fail "attack suite: ${ATT:-no result line}"
NC=$(printf '%s' "$ATT" | sed -n 's/\([0-9]*\) checks.*/\1/p')

# Optional, and skipping is not failing: it needs a browser.
say "viewer end-to-end..."
E2E=$(bash tests/ui-e2e.sh 2>&1 | tee -a "$LOG" | tail -1)
case "$E2E" in
  *"ui-e2e: ok"*)      E2ESTATE="ok" ;;
  *"skipped"*)         E2ESTATE="skipped" ;;
  *)                   fail "viewer end-to-end: $E2E" ;;
esac

say "OK: $NC checks, $NU unit tests, viewer $E2ESTATE, at $HEAD"
printf 'ok\t%s\t%s\t%s checks, %s unit tests, viewer %s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HEAD" "$NC" "$NU" "$E2ESTATE" > "$STATUS"
