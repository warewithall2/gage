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
    notify-send -u critical "gage selfcheck failed" "$* -- see $LOG" 2>/dev/null || true
  elif command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$* -- see $LOG\" with title \"gage selfcheck failed\"" 2>/dev/null || true
  fi
  exit 1
}

say "gage selfcheck on $(uname -s) $(uname -m), $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Preflight: the suite binds fixed ports, and a stray listener on one of them
# once produced 28 failures that looked like real defects and were not. Say
# so up front rather than letting the suite blame the code.
BUSY=""
for p in 7799 7809 7813 7817 7818 7819 7891 7892 7893 7895 7898 7903 7905 \
         7931 7932 7933 7934 7935 7936 7937 7938 7939 7940; do
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":$p " && BUSY="$BUSY $p"
  else
    netstat -an -p tcp 2>/dev/null | grep -i listen | grep -q "\.$p " && BUSY="$BUSY $p"
  fi
done
[ -n "$BUSY" ] && fail "ports in use by something else:$BUSY (the suite needs them; a stray \`gage ui\` is the usual cause)"

# Same reason as the ports: a real `gage lan` shares the network with the LAN
# checks, so "nobody announcing" sees a genuine announcement. An environment
# collision reported as a defect wastes more time than it saves.
for _p in $(pgrep -x gage 2>/dev/null; pgrep -x ctx 2>/dev/null); do
  if tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null | grep -qE ' (lan|listen)( |$)'; then
    fail "a real \`gage lan\` or \`gage listen\` is running (pid $_p); the LAN checks share that network and would report failures that are not defects"
  fi
done

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

# The launcher and the app bundle, which selfcheck did NOT run for the length
# of the packaging work -- so `tests/packaging.sh` was a suite with no caller,
# and the macOS window had no test at all partly because of it. Its own stage,
# like the drill, so a failure says which thing broke. On this machine the
# window checks inside it skip themselves; on a Mac they compile and run the
# window's URL predicates.
say "launcher and app bundle..."
PKG=$(bash tests/packaging.sh 2>&1 | tee -a "$LOG" | grep -E '[0-9]+ checks,' | tail -1)
printf '%s\n' "$PKG" | grep -q ', 0 failed' || fail "packaging: ${PKG:-no result line}"
NP=$(printf '%s' "$PKG" | sed -n 's/\([0-9]*\) checks.*/\1/p')

# The decision record that chose encrypted backup asked for this by name:
# "restore is tested, not just export." An export path that runs and a restore
# path that does not is a backup that does not exist, and the day you find out
# is the day you needed it. Its own stage rather than a line inside the attack
# suite, so a failure here says which thing broke.
say "identity restore drill..."
DRILL=$(bash tests/restore-drill.sh 2>&1 | tee -a "$LOG" | grep -E 'restore drill:' | tail -1)
printf '%s\n' "$DRILL" | grep -q ', 0 failed' || fail "identity restore drill: ${DRILL:-no result line}"
ND=$(printf '%s' "$DRILL" | sed -n 's/restore drill: \([0-9]*\) checks.*/\1/p')

# Optional, and skipping is not failing: it needs a browser.
say "viewer end-to-end..."
E2E=$(bash tests/ui-e2e.sh 2>&1 | tee -a "$LOG" | tail -1)
case "$E2E" in
  *"ui-e2e: ok"*)      E2ESTATE="ok" ;;
  *"skipped"*)         E2ESTATE="skipped" ;;
  *)                   fail "viewer end-to-end: $E2E" ;;
esac

# Dependency advisories. LAST on purpose: `fail` exits on the first stage
# that breaks, so an advisory published this morning must not be allowed to
# mask a real test regression. By the time this runs, everything this machine
# can prove about its own code has already been proved.
#
# Added 22 October 2026, after the first `cargo audit` this project ever ran
# found two advisories that were three and four days old -- both in
# certificate verification. Nobody had audited because the dependency list is
# short and hand-justified in the manifest, which is exactly the reasoning
# that makes a tree feel safe without anybody checking it. A short list
# bounds exposure; it does not tell you when one of them is announced
# vulnerable.
#
# Skipping is not failing, and a skip is SAID -- the same rule the four
# certificate checks in the attack suite follow. Silently passing a security
# check that did not run is the shape of mistake this file exists to prevent.
say "dependency advisories..."
AUDIT=""
if command -v cargo-audit >/dev/null 2>&1; then
  AUDIT=cargo-audit
elif [ -x "$HOME/.cargo/bin/cargo-audit" ]; then
  AUDIT="$HOME/.cargo/bin/cargo-audit"
fi
if [ -z "$AUDIT" ]; then
  DEPSTATE="skipped"
  say "  SKIP: cargo-audit is not installed, so dependencies were NOT checked"
  say "        cargo install cargo-audit"
else
  AOUT=$("$AUDIT" audit 2>&1); ARC=$?
  printf '%s\n' "$AOUT" >> "$LOG"
  if [ "$ARC" -eq 0 ]; then
    DEPSTATE="ok"
  elif printf '%s\n' "$AOUT" | grep -qiE 'vulnerabilit(y|ies) found'; then
    # A real finding fails the run, which is the whole point: it is how you
    # hear about it within a day instead of never. If an advisory has no fix
    # available yet and this would otherwise stay red, that is what
    # `.cargo/audit.toml`'s ignore list is for -- a deliberate, recorded
    # decision rather than a check nobody runs.
    say "$(printf '%s\n' "$AOUT" | grep -E '^(Crate|ID|Title|Solution):' | head -20)"
    fail "dependency advisories: $(printf '%s\n' "$AOUT" | grep -iE 'vulnerabilit(y|ies) found' | tail -1)"
  else
    # Non-zero for a reason that is not a finding -- almost always that the
    # advisory database could not be fetched. Reported as a skip with its
    # reason, never as a pass.
    DEPSTATE="skipped"
    say "  SKIP: could not check dependencies: $(printf '%s\n' "$AOUT" | tail -1)"
  fi
fi

say "OK: $NC checks, $NU unit tests, $ND restore-drill checks, $NP packaging checks, viewer $E2ESTATE, deps $DEPSTATE, at $HEAD"
printf 'ok\t%s\t%s\t%s checks, %s unit tests, %s restore-drill checks, %s packaging checks, viewer %s, deps %s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HEAD" "$NC" "$NU" "$ND" "$NP" "$E2ESTATE" "$DEPSTATE" > "$STATUS"
