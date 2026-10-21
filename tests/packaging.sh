#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 2
T=$(mktemp -d)
pass=0; fail=0
LAUNCH_PID=; EXISTING_PID=; CHILD_PIDS=
ok() { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
want() { if grep -qF -- "$2" "$1"; then ok; else bad "expected '$2' in ${1##*/}"; fi; }
cleanup() {
  for pid in $CHILD_PIDS; do kill "$pid" 2>/dev/null || :; done
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    alive=
    for pid in $CHILD_PIDS; do
      if kill -0 "$pid" 2>/dev/null; then alive="$alive $pid"; fi
    done
    [ -z "$alive" ] && break
    sleep .05
  done
  for pid in $CHILD_PIDS; do kill -KILL "$pid" 2>/dev/null || :; done
  for pid in $CHILD_PIDS; do wait "$pid" 2>/dev/null || :; done
  rm -rf "$T"
}
trap cleanup EXIT
track_pid() { CHILD_PIDS="$CHILD_PIDS $1"; }
forget_pid() {
  target=$1; kept=
  for pid in $CHILD_PIDS; do [ "$pid" = "$target" ] || kept="$kept $pid"; done
  CHILD_PIDS=$kept
}
stop_pid() {
  target=$1
  [ -n "$target" ] || return 0
  kill "$target" 2>/dev/null || :
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    kill -0 "$target" 2>/dev/null || break
    sleep .05
  done
  kill -KILL "$target" 2>/dev/null || :
  wait "$target" 2>/dev/null || :
  forget_pid "$target"
}

mkdir -p "$T/bin"
# The run directory is the isolation boundary: use the accepted executable
# name, but keep every record under this run's private fixture home.
FIXTURE_BIN="$T/bin/gage"
cat > "$FIXTURE_BIN" <<'STUB'
#!/bin/bash
service=${1:-}; shift || :
printf '%s|%s %s|%s\n' "$GAGE_HOME" "$service" "$*" "$$" >> "$GAGE_TEST_LOG"
if [ "$service" = watch ] && [ "${1:-}" = --once ]; then exit 0; fi
case "$service" in lan|ui|watch) ;; *) exec -a "gage $service $*" /bin/sleep 600;; esac
mkdir -p "$GAGE_HOME/run"
record="$GAGE_HOME/run/$service.pid"
printf '%s\n' "$$" > "$record"
exec -a "gage $service" /bin/bash -c '
record=$1
trap '\''rm -f "$record"'\'' EXIT
trap '\''exit 0'\'' HUP INT TERM
while :; do sleep 1 & wait "$!" || :; done
' "gage $service" "$record"
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
cat > "$T/bin/vim" <<'VIM'
#!/bin/bash
exec -a 'vim src/lan.rs' /bin/sleep 600
VIM
chmod +x "$T/bin/vim"

start_stub() {
  home=$1; log=$2; service=$3; shift 3
  ( trap - EXIT; exec env -u GAGE_HOME -u COUNTERSIGN_HOME -u CTX_HOME HOME="$home" GAGE_HOME="$home" \
    GAGE_TEST_LOG="$log" "$FIXTURE_BIN" "$service" "$@" ) &
  EXISTING_PID=$!
  track_pid "$EXISTING_PID"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$home/run/$service.pid" ] && break
    sleep .05
  done
}
stop_existing() {
  [ -n "$EXISTING_PID" ] || return 0
  stop_pid "$EXISTING_PID"
  EXISTING_PID=
}
run_launcher() {
  label=$1; home=$2; curl_home=$3; timeout=${4:-2}; mode=${5:-explicit}; base_home=${6:-$T/user-$label}
  mkdir -p "$home"
  : > "$T/services-$label.log"; : > "$T/open-$label.log"; : > "$T/curl-$label.log"
  user_home=$base_home; mkdir -p "$user_home"
  selector=(GAGE_HOME="$home")
  case "$mode" in
    gage) selector=(GAGE_HOME= HOME="$user_home"); mkdir -p "$user_home/.gage" "$user_home/.countersign" "$user_home/.ctx"; home="$user_home/.gage" ;;
    countersign) selector=(GAGE_HOME= HOME="$user_home"); mkdir -p "$user_home/.countersign" "$user_home/.ctx"; home="$user_home/.countersign" ;;
    ctx) selector=(GAGE_HOME= HOME="$user_home"); mkdir -p "$user_home/.ctx"; home="$user_home/.ctx" ;;
    countersign_env) selector=(GAGE_HOME= COUNTERSIGN_HOME="$home");;
    ctx_env) selector=(GAGE_HOME= CTX_HOME="$home");;
  esac
  ( trap - EXIT; exec env GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/services-$label.log" \
    GAGE_OPEN="$T/bin/open" GAGE_OPEN_LOG="$T/open-$label.log" \
    GAGE_CURL_LOG="$T/curl-$label.log" GAGE_CURL_HOME="$curl_home" PATH="$T/bin:$PATH" \
    "${selector[@]}" GAGE_UI_PORT=17777 GAGE_START_TIMEOUT="$timeout" \
    "$PWD/packaging/macos/gage-launcher" ) >"$T/out-$label" 2>&1 &
  LAUNCH_PID=$!
  track_pid "$LAUNCH_PID"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -s "$T/open-$label.log" ] && break
    sleep .05
  done
}
stop_launcher() {
  [ -n "$LAUNCH_PID" ] || return 0
  stop_pid "$LAUNCH_PID"
  LAUNCH_PID=
}
count_service() { grep -c "|$1 " "$2" 2>/dev/null || :; }

echo "Linux ps argv probe (the same command used by the launcher)"
( trap - EXIT; exec env GAGE_HOME="$T/probe-home" "$FIXTURE_BIN" lan ) > /dev/null 2>&1 & probe_pid=$!
track_pid "$probe_pid"
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$T/probe-home/run/lan.pid" ] && break; sleep .05; done
probe_line=$(ps -p "$probe_pid" -o command= 2>/dev/null || :)
case "$probe_line" in "gage lan"*) ok;; *) bad "Linux ps argv did not expose gage subcommand: $probe_line";; esac
stop_pid "$probe_pid"

echo "identity home selection follows identity.rs"
for branch in explicit gage countersign ctx countersign_env ctx_env; do
  h="$T/h-$branch"; mkdir -p "$h"
  case "$branch" in
    explicit) selected="$T/homes/explicit"; mkdir -p "$selected" ;;
    gage) selected="$h/.gage" ;;
    countersign) selected="$h/.countersign" ;;
    ctx) selected="$h/.ctx" ;;
    countersign_env) selected="$T/homes/countersign"; mkdir -p "$selected" ;;
    ctx_env) selected="$T/homes/ctx"; mkdir -p "$selected" ;;
  esac
  mkdir -p "$h"
  run_launcher "$branch" "$selected" "$selected" 2 "$branch" "$h"
  want "$T/open-$branch.log" "http://127.0.0.1:17777/"
  first=$(head -1 "$T/services-$branch.log")
  case "$first" in "$selected|"*) ok;; *) bad "$branch selected wrong home: $first";; esac
  stop_launcher
  for candidate in "$h/.gage" "$h/.countersign" "$h/.ctx"; do
    if [ -e "$candidate/identity.key" ]; then bad "$branch created identity at $candidate"; else ok; fi
  done
done

echo "live per-home records are adopted only for their own service"
for existing in lan ui watch; do
  h="$T/adopt-$existing/.gage"; mkdir -p "$h"
  : > "$T/adopt-$existing-existing.log"
  start_stub "$h" "$T/adopt-$existing-existing.log" "$existing" ${existing:+$( [ "$existing" = watch ] && printf '%s' '--every 120' )}
  run_launcher "adopt-$existing" "$h" "$h"
  want "$T/open-adopt-$existing.log" "http://127.0.0.1:17777/"
  for service in lan ui watch; do
    n=$(count_service "$service" "$T/services-adopt-$existing.log")
    if [ "$service" = "$existing" ]; then [ "$n" = 0 ] && ok || bad "$existing duplicate started (count $n)"; else [ "$n" = 1 ] && ok || bad "missing newly started $service (count $n)"; fi
  done
  kill -0 "$EXISTING_PID" 2>/dev/null && ok || bad "adopted $existing was not left running"
  stop_launcher; stop_existing
done

echo "a live service record does not answer for other services"
h="$T/cross-service/.gage"; mkdir -p "$h"; : > "$T/cross-service-existing.log"
start_stub "$h" "$T/cross-service-existing.log" ui
ui_pid=$(cat "$h/run/ui.pid")
printf '%s\n' "$ui_pid" > "$h/run/lan.pid"
printf '%s\n' "$ui_pid" > "$h/run/watch.pid"
run_launcher cross-service "$h" "$h"
[ "$(count_service lan "$T/services-cross-service.log")" = 1 ] && ok || bad "UI record incorrectly answered for lan"
[ "$(count_service watch "$T/services-cross-service.log")" = 1 ] && ok || bad "UI record incorrectly answered for watch"
[ "$(count_service ui "$T/services-cross-service.log")" = 0 ] && ok || bad "UI record did not answer for ui"
stop_launcher; stop_existing

echo "legacy executable names remain adoptable"
for name in ctx countersign; do
  ln -s "$FIXTURE_BIN" "$T/bin/$name"
  h="$T/legacy-$name/.gage"; mkdir -p "$h"; : > "$T/legacy-$name-existing.log"
  ( trap - EXIT; exec env GAGE_HOME="$h" GAGE_TEST_LOG="$T/legacy-$name-existing.log" "$T/bin/$name" lan ) & EXISTING_PID=$!
  track_pid "$EXISTING_PID"
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$h/run/lan.pid" ] && break; sleep .05; done
  run_launcher "legacy-$name" "$h" "$h"
  [ "$(count_service lan "$T/services-legacy-$name.log")" = 0 ] && ok || bad "$name service was not adopted"
  stop_launcher; stop_existing
done

echo "a stale record and a live non-gage PID are not adopted"
h="$T/stale/.gage"; mkdir -p "$h/run"; : > "$T/stale-source.log"
( trap - EXIT; exec /bin/sleep 600 ) & stale_pid=$!; track_pid "$stale_pid"
kill "$stale_pid"; wait "$stale_pid" 2>/dev/null || :; forget_pid "$stale_pid"
printf '%s\n' "$stale_pid" > "$h/run/lan.pid"
run_launcher stale "$h" "$h"
[ "$(count_service lan "$T/services-stale.log")" = 1 ] && ok || bad "dead stale PID suppressed lan startup"
stop_launcher

h="$T/reused/.gage"; mkdir -p "$h/run"
( trap - EXIT; exec /bin/sleep 600 ) & reused_pid=$!; track_pid "$reused_pid"; printf '%s\n' "$reused_pid" > "$h/run/lan.pid"
run_launcher reused "$h" "$h"
[ "$(count_service lan "$T/services-reused.log")" = 1 ] && ok || bad "live non-gage PID was adopted"
stop_launcher; stop_pid "$reused_pid"

echo "different-home records are invisible; malformed and missing records start"
other="$T/other/.gage"; target="$T/target/.gage"; mkdir -p "$target"
: > "$T/other.log"; start_stub "$other" "$T/other.log" lan
run_launcher other-home "$target" "$target"
[ "$(count_service lan "$T/services-other-home.log")" = 1 ] && ok || bad "different-home record suppressed lan startup"
stop_launcher; stop_existing

mkdir -p "$target/run"; printf '12x\n' > "$target/run/lan.pid"
run_launcher malformed "$target" "$target"
[ "$(count_service lan "$T/services-malformed.log")" = 1 ] && ok || bad "malformed record suppressed lan startup"
stop_launcher
rm -f "$target/run/lan.pid"
run_launcher missing "$target" "$target"
[ "$(count_service lan "$T/services-missing.log")" = 1 ] && ok || bad "missing record suppressed lan startup"
stop_launcher

echo "argv matching uses executable and subcommand positions"
h="$T/argv-send/.gage"; mkdir -p "$h/run"
( trap - EXIT; exec env GAGE_HOME="$h" GAGE_TEST_LOG="$T/send.log" "$FIXTURE_BIN" send --file lan ) & fake_pid=$!; track_pid "$fake_pid"
printf '%s\n' "$fake_pid" > "$h/run/lan.pid"
run_launcher argv-send "$h" "$h"
[ "$(count_service lan "$T/services-argv-send.log")" = 1 ] && ok || bad "gage send --file lan matched lan service"
stop_launcher; stop_pid "$fake_pid"

h="$T/argv-vim/.gage"; mkdir -p "$h/run"
( trap - EXIT; exec "$T/bin/vim" ) & fake_pid=$!; track_pid "$fake_pid"; printf '%s\n' "$fake_pid" > "$h/run/lan.pid"
run_launcher argv-vim "$h" "$h"
[ "$(count_service lan "$T/services-argv-vim.log")" = 1 ] && ok || bad "vim src/lan.rs matched lan service"
stop_launcher; stop_pid "$fake_pid"

echo "a UI state home mismatch is refused even with a live home record"
h="$T/wrong-ui/.gage"; mkdir -p "$h"
: > "$T/wrong-ui-existing.log"; start_stub "$h" "$T/wrong-ui-existing.log" ui
GAGE_BIN="$FIXTURE_BIN" GAGE_TEST_LOG="$T/services-wrong-ui.log" GAGE_OPEN="$T/bin/open" \
  GAGE_OPEN_LOG="$T/open-wrong-ui.log" GAGE_CURL_LOG="$T/curl-wrong-ui.log" GAGE_CURL_HOME="$T/stranger" \
  PATH="$T/bin:$PATH" GAGE_HOME="$h" HOME="$T/wrong-ui-user" GAGE_UI_PORT=17777 GAGE_START_TIMEOUT=1 \
  "$PWD/packaging/macos/gage-launcher" > "$T/out-wrong-ui" 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok || bad "launcher accepted UI state for another home"
[ ! -s "$T/open-wrong-ui.log" ] && ok || bad "browser opened wrong-home UI"
[ "$(count_service ui "$T/services-wrong-ui.log")" = 0 ] && ok || bad "duplicate UI started despite valid home record"
kill -0 "$EXISTING_PID" 2>/dev/null && ok || bad "existing UI was stopped after state mismatch"
stop_existing

echo "watch --once writes no run record"
h="$T/once/.gage"; mkdir -p "$h"
GAGE_HOME="$h" GAGE_TEST_LOG="$T/once.log" "$FIXTURE_BIN" watch --once
[ ! -e "$h/run/watch.pid" ] && ok || bad "watch --once wrote a service record"

echo "bundle metadata is a valid plist XML document"
mkdir -p "$T/app-input"; cp "$FIXTURE_BIN" "$T/app-input/gage"
bash packaging/macos/make-app.sh "$T/app-input/gage" "$T/bundle" >"$T/make" 2>&1
if xmllint --noout "$T/bundle/Gage.app/Contents/Info.plist" 2>/dev/null; then ok; else bad "Info.plist is not well-formed XML"; fi
want "$T/bundle/Gage.app/Contents/Info.plist" "sh.gage.app"
want "$T/bundle/Gage.app/Contents/Info.plist" "13.0"
[ -x "$T/bundle/Gage.app/Contents/MacOS/gage-launcher" ] && ok || bad "launcher missing executable bit in bundle"

echo "$pass checks, $fail failed"
[ "$fail" -eq 0 ]
