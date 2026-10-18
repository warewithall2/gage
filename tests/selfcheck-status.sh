#!/usr/bin/env bash
# What every machine last said about itself.
#
# The status file is per-machine, which answers "is THIS machine good". The
# question the project actually has is "are both", because its whole claim is
# two machines -- and the way that went wrong was nobody looking at the
# second one for weeks.
#
#   tests/selfcheck-status.sh [ssh-host ...]
#
# Reads this machine's file directly and each host's over ssh. A host it
# cannot reach is reported as unreachable, never as passing.
set -u
F="${CTX_SELFCHECK_DIR:-$HOME/.ctx-selfcheck}/status"

show() {
  local who=$1 line=$2
  if [ -z "$line" ]; then
    printf '  %-22s %s\n' "$who" "no result yet -- has the timer run?"
    return
  fi
  local state ts commit rest
  state=$(printf '%s' "$line" | cut -f1)
  ts=$(printf '%s' "$line" | cut -f2)
  commit=$(printf '%s' "$line" | cut -f3)
  rest=$(printf '%s' "$line" | cut -f4-)
  local mark="ok  "
  [ "$state" != ok ] && mark="FAIL"
  printf '  %-22s %s  %s  %s  %s\n' "$who" "$mark" "$ts" "$commit" "$rest"
}

echo "countersign selfcheck, last result per machine:"
show "$(hostname -s 2>/dev/null || echo this-machine)" "$(cat "$F" 2>/dev/null)"

for h in "$@"; do
  line=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" \
         "cat \${CTX_SELFCHECK_DIR:-\$HOME/.ctx-selfcheck}/status 2>/dev/null" 2>/dev/null)
  if [ -z "$line" ]; then
    # Distinguished from a pass on purpose: silence is not evidence of
    # health, and this is the exact shape of mistake the whole script is
    # about.
    if ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" true 2>/dev/null; then
      show "$h" ""
    else
      printf '  %-22s %s\n' "$h" "UNREACHABLE -- this says nothing about whether it is good"
    fi
    continue
  fi
  show "$h" "$line"
done
