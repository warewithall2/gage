#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 2
T=$(mktemp -d)
pass=0; fail=0
ok() { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
want() { if grep -qF -- "$2" "$1"; then ok; else bad "expected '$2' in ${1##*/}"; fi; }
cleanup() {
  [ -n "${LAUNCH_PID:-}" ] && kill "$LAUNCH_PID" 2>/dev/null || :
  [ -n "${EXISTING_PID:-}" ] && kill "$EXISTING_PID" 2>/dev/null || :
  wait 2>/dev/null || :
  rm -rf "$T"
}
trap cleanup EXIT

mkdir -p "$T/bin"
FIXTURE_BIN="$T/bin/gagefixture$$"
cat > "$FIXTURE_BIN" <<'STUB'
#!/bin/bash
printf '%s|%s|%s\n' "$GAGE_HOME" "$*" "$$" >> "$GAGE_TEST_LOG"
exec -a "${0##*/} $*" /bin/sleep 600
STUB
chmod +x "$FIXTURE_BIN"
cat > "$T/bin/open" <<'OPEN'
#!/bin/sh
printf '%s\n' "$*" >> "$GAGE_OPEN_LOG"
OPEN
chmod +x "$T/bin/open"
cat > "$T/bin/curl" <<'CURL'
#!/bin/sh
printf '%s\n' "$*" >> "$GAGE_CURL_LOG"
[ "${GAGE_CURL_FAIL:-0}" = 1 ] && exit 7
printf '{"home":"%s"}\n' "$GAGE_CURL_HOME"
CURL
chmod +x "$T/bin/curl"

# Fixture homes. Ensure the identity path chosen by the launcher is passed
# unchanged to the stub services.
run_with_home() {
  label=$1; home=$2; expected=$3; existing=${4:-}
  mkdir -p "$home"
  : > "$T/services-$label.log"; : > "$T/open-$label.log"
  : > "$T/curl-$label.log"
  if [ -n "$existing" ]; then
    env -u GAGE_HOME -u COUNTERSIGN_HOME -u CTX_HOME HOME="$home" \
      GAGE_TEST_LOG="$T/services-$label.log" "$FIXTURE_BIN" "$existing" & EXISTING_PID=$!
    sleep .1
  fi
  GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/services-$label.log" \
    GAGE_OPEN="$T/bin/open" GAGE_OPEN_LOG="$T/open-$label.log" \
    GAGE_CURL_LOG="$T/curl-$label.log" GAGE_CURL_HOME="$expected" PATH="$T/bin:$PATH" \
    GAGE_HOME="${explicit_home:-}" COUNTERSIGN_HOME="${counter_home:-}" \
    CTX_HOME="${ctx_home:-}" HOME="$home" GAGE_UI_PORT=17777 GAGE_START_TIMEOUT=2 \
    "$PWD/packaging/macos/gage-launcher" >"$T/out-$label" 2>&1 &
  LAUNCH_PID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$T/open-$label.log" ] && break; sleep .1; done
  want "$T/open-$label.log" "http://127.0.0.1:17777/"
  want "$T/curl-$label.log" "http://127.0.0.1:17777/api/state"
  # The stub logs argv. Home selection is proven by an env capture wrapper
  # around the stub for this check below, while these counts prove no duplicate.
  if [ -n "$existing" ]; then
    n=$(grep -c "|$existing|" "$T/services-$label.log" || :)
    [ "$n" = 1 ] && ok || bad "$label started duplicate $existing service (count $n)"
  else
    want "$T/services-$label.log" "lan"
    want "$T/services-$label.log" "ui"
    want "$T/services-$label.log" "watch --every 120"
  fi
  kill "$LAUNCH_PID" 2>/dev/null || :; wait "$LAUNCH_PID" 2>/dev/null || :; LAUNCH_PID=
  if [ -n "$existing" ]; then
    if kill -0 "$EXISTING_PID" 2>/dev/null; then ok; else bad "launcher killed pre-existing $existing"; fi
    kill "$EXISTING_PID" 2>/dev/null || :; wait "$EXISTING_PID" 2>/dev/null || :; EXISTING_PID=
  fi
  :
}

echo "home selection follows identity.rs"
mkdir -p "$T/homes/explicit" "$T/homes/.gage" "$T/homes/.countersign" "$T/homes/.ctx"
# Four branches: explicit override, then each fallback as the first extant home.
for branch in explicit gage countersign ctx countersign_env ctx_env; do
  h="$T/h-$branch"; mkdir -p "$h"
  counter_home=; ctx_home=
  case "$branch" in
    explicit) mkdir -p "$h/.gage"; explicit_home="$T/homes/explicit"; want_home="$T/homes/explicit" ;;
    gage) mkdir -p "$h/.gage" "$h/.countersign" "$h/.ctx"; explicit_home=; want_home="$h/.gage" ;;
    countersign) mkdir -p "$h/.countersign" "$h/.ctx"; explicit_home=; want_home="$h/.countersign" ;;
    ctx) mkdir -p "$h/.ctx"; explicit_home=; want_home="$h/.ctx" ;;
    countersign_env) mkdir -p "$h/.gage"; explicit_home=; counter_home="$T/homes/countersign"; want_home="$T/homes/countersign" ;;
    ctx_env) mkdir -p "$h/.gage"; explicit_home=; ctx_home="$T/homes/.ctx"; want_home="$T/homes/.ctx" ;;
  esac
  run_with_home "$branch" "$h" "$want_home"
  first=$(head -1 "$T/services-$branch.log")
  case "$first" in "$want_home|"*) ok;; *) bad "$branch selected wrong home: $first";; esac
  for candidate in "$h/.gage" "$h/.countersign" "$h/.ctx"; do
    if [ -e "$candidate/identity.key" ]; then bad "$branch created an identity at $candidate"; else ok; fi
  done
done

echo "existing services are adopted; quit cleans up owned processes only"
h="$T/h-adopt"; mkdir -p "$h/.gage"
explicit_home=; counter_home=; ctx_home=
# One already-running service does not get a second invocation.
run_with_home adopt "$h" "$h/.gage" lan
for service in ui 'watch --every 120'; do
  if grep -qF "$service" "$T/services-adopt.log"; then ok; else bad "missing newly started $service"; fi
done
# The launcher must have reaped its two child services when it quit.
while IFS='|' read -r _home service pid; do
  case "$service" in lan) continue;; esac
  if kill -0 "$pid" 2>/dev/null; then bad "launcher-owned $service process $pid survived quit"; else ok; fi
done < "$T/services-adopt.log"

echo "a same-named service from another home is not adopted"
h="$T/h-wrong-home"; wrong="$T/other-home"; mkdir -p "$h/.gage" "$wrong"
: > "$T/wrong-home.log"; : > "$T/wrong-home-curl.log"
GAGE_HOME="$wrong" GAGE_TEST_LOG="$T/wrong-home.log" "$FIXTURE_BIN" ui & EXISTING_PID=$!
sleep .1
GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/wrong-home.log" GAGE_OPEN="$T/bin/open" \
  GAGE_OPEN_LOG="$T/wrong-home-open.log" GAGE_CURL_LOG="$T/wrong-home-curl.log" \
  GAGE_CURL_HOME="$h/.gage" PATH="$T/bin:$PATH" HOME="$h" GAGE_UI_PORT=17777 \
  GAGE_START_TIMEOUT=2 "$PWD/packaging/macos/gage-launcher" >"$T/wrong-home-out" 2>&1 &
LAUNCH_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$T/wrong-home-open.log" ] && break; sleep .1; done
kill "$LAUNCH_PID" 2>/dev/null || :; wait "$LAUNCH_PID" 2>/dev/null || :; LAUNCH_PID=
[ -s "$T/wrong-home-open.log" ] && ok || bad "launcher did not start its own UI after finding only a different-home service"
n=$(grep -c '|ui|' "$T/wrong-home.log" || :)
[ "$n" = 2 ] && ok || bad "wrong-home UI was adopted or an unexpected duplicate was started (ui count $n)"
if kill -0 "$EXISTING_PID" 2>/dev/null; then ok; else bad "launcher stopped the pre-existing wrong-home UI"; fi
kill "$EXISTING_PID" 2>/dev/null || :; wait "$EXISTING_PID" 2>/dev/null || :; EXISTING_PID=

echo "a UI endpoint must report the selected home before opening"
h="$T/h-wrong-ui-state"; mkdir -p "$h/.gage"; : > "$T/wrong-ui-state.log"
GAGE_HOME="$h/.gage" GAGE_TEST_LOG="$T/wrong-ui-state.log" "$FIXTURE_BIN" ui & EXISTING_PID=$!
sleep .1
GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/wrong-ui-state.log" GAGE_OPEN="$T/bin/open" \
  GAGE_OPEN_LOG="$T/wrong-ui-state-open.log" GAGE_CURL_LOG="$T/wrong-ui-state-curl.log" \
  GAGE_CURL_HOME="$T/other-home" PATH="$T/bin:$PATH" HOME="$h" GAGE_UI_PORT=17777 \
  GAGE_START_TIMEOUT=1 "$PWD/packaging/macos/gage-launcher" >"$T/wrong-ui-state-out" 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok || bad "launcher opened a UI reporting another home"
n=$(grep -c '|ui|' "$T/wrong-ui-state.log" || :)
[ "$n" = 1 ] && ok || bad "same-home UI was not adopted cleanly (ui count $n)"
[ ! -s "$T/wrong-ui-state-open.log" ] && ok || bad "browser opened a UI whose state named another home"
if kill -0 "$EXISTING_PID" 2>/dev/null; then ok; else bad "launcher stopped the pre-existing UI"; fi
kill "$EXISTING_PID" 2>/dev/null || :; wait "$EXISTING_PID" 2>/dev/null || :; EXISTING_PID=

echo "a missing UI port fails within the configured bound"
: > "$T/fail.log"
GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/fail.log" GAGE_OPEN="$T/bin/open" \
  GAGE_OPEN_LOG="$T/fail-open.log" GAGE_HOME="$T/fail-home" HOME="$T" \
  GAGE_CURL_LOG="$T/fail-curl.log" GAGE_CURL_FAIL=1 GAGE_CURL_HOME= PATH="$T/bin:$PATH" \
  GAGE_UI_PORT=17778 GAGE_START_TIMEOUT=1 "$PWD/packaging/macos/gage-launcher" >"$T/failure" 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok || bad "launcher succeeded without a listener"
want "$T/failure" "did not report the selected home within 1s"
[ ! -s "$T/fail-open.log" ] && ok || bad "browser opened although the UI did not answer"

echo "bundle metadata is a valid plist XML document"
mkdir -p "$T/app-input"
cp "$FIXTURE_BIN" "$T/app-input/gage"
bash packaging/macos/make-app.sh "$T/app-input/gage" "$T/bundle" >"$T/make" 2>&1
if xmllint --noout "$T/bundle/Gage.app/Contents/Info.plist" 2>/dev/null; then ok; else bad "Info.plist is not well-formed XML"; fi
want "$T/bundle/Gage.app/Contents/Info.plist" "sh.gage.app"
want "$T/bundle/Gage.app/Contents/Info.plist" "13.0"
[ -x "$T/bundle/Gage.app/Contents/MacOS/gage-launcher" ] && ok || bad "launcher missing executable bit in bundle"

echo "$pass checks, $fail failed"
[ "$fail" -eq 0 ]
