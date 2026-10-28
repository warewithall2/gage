#!/usr/bin/env bash
# Drive a full handoff between two FIXTURE identities, for the demo capture.
#
#   scripts/demo.sh
#
# Everything happens in a throwaway directory: two homes (alice and bob) and a
# relay with its own store, on a port nothing else uses. It never reads or
# writes the real gage home, never touches ~/.gage, and never talks to the
# services running on this machine. The commands and their output are real --
# the only thing this script does is echo each command before running it, so a
# recording shows what was typed.
set -u

GAGE="${GAGE:-$PWD/target/release/gage}"
PORT="${PORT:-7912}"
T=$(mktemp -d)
A=$T/alice
B=$T/bob
# So the `gage` that is echoed is exactly the `gage` that runs, whatever is
# installed on this machine's PATH.
mkdir -p "$T/bin"
ln -sf "$GAGE" "$T/bin/gage"
PATH="$T/bin:$PATH"
export PATH
export GAGE_HOME=""   # set per-command below; never inherited

cleanup() {
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

# Echo the command, then run it. `p` is prose between steps.
say() { printf '\n\033[38;5;108m# %s\033[0m\n' "$*"; }
run() { printf '\033[1m$ %s\033[0m\n' "$2"; ( export GAGE_HOME="$1"; eval "$2" ); }
pause() { sleep "${1:-1}"; }

say "Two people, two machines. Here they are two fixture homes in /tmp."
run "$A" "gage init alice"
pause
run "$B" "gage init bob"
pause

say "The line each one gives the other. It is a public key, not a secret."
run "$A" "gage whoami"
pause
ALICE_KEY=$(GAGE_HOME=$A gage whoami 2>/dev/null | awk 'NR==1{print $2}')
BOB_KEY=$(GAGE_HOME=$B gage whoami 2>/dev/null | awk 'NR==1{print $2}')

say "Adding a key prints the four word-pairs it derives, and says what it"
say "has NOT done: nobody has compared them yet."
run "$A" "gage add bob $BOB_KEY"
pause 2
run "$B" "gage add alice $ALICE_KEY"
pause 2

say "Both screens must show the same four pairs for that key. Nobody picks"
say "their own words -- they come from the key itself."
run "$A" "gage fingerprint bob"
pause 2

say "This is the ceremony: alice and bob read those pairs to each other out"
say "loud, on a phone call. Then each writes down that they did."
say "Until they do, bundles read SENDER ON YOUR LIST, UNCONFIRMED -- the tool"
say "will not claim a check nobody performed."
# The fixture types the words back for them, which is the one thing a script
# can do and a person cannot: the point of `gage confirm` is that the words
# come off the OTHER machine. Read from each home's own view of the other.
BOB_WORDS=$(GAGE_HOME=$A gage fingerprint bob 2>/dev/null | cut -f2)
ALICE_WORDS=$(GAGE_HOME=$B gage fingerprint alice 2>/dev/null | cut -f2)
run "$A" "gage confirm bob '$BOB_WORDS'"
pause 2
run "$B" "gage confirm alice '$ALICE_WORDS'" >/dev/null
pause

say "A relay, for when the other agent is not on your filesystem. It holds"
say "sealed envelopes and cannot read them."
printf '\033[1m$ gage relay --bind 127.0.0.1:%s --store ./relay &\033[0m\n' "$PORT"
gage relay --bind "127.0.0.1:$PORT" --store "$T/relay" >"$T/relay.log" 2>&1 &
RELAY_PID=$!
sleep 1
sed -n '1,3p' "$T/relay.log"
pause
run "$A" "gage join 127.0.0.1:$PORT"
pause
run "$B" "gage join 127.0.0.1:$PORT"
pause

say "alice hands bob a task: a prompt, a decision, and the file they refer to."
printf 'Use full jitter and cap the backoff at 30s.\n' > "$T/task.md"
printf 'We chose full jitter over equal jitter: thundering herds.\n' > "$T/notes.md"
printf 'pub fn retry() { /* ... */ }\n' > "$T/client.rs"
run "$A" "gage send --to bob --subject 'backoff refactor' --prompt $T/task.md --decision $T/notes.md --file $T/client.rs --agent claude-code --out $T/handoff"
pause 2

say "Nothing leaves the machine unsealed, and nothing leaves without saying so."
run "$A" "gage push $T/handoff --to bob --yes"
pause 2

say "bob collects. It arrives unread, behind the accept gate."
run "$B" "gage pull"
pause
run "$B" "gage inbox"
pause 2

ID=$(GAGE_HOME=$B gage inbox --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')

say "Arrival is not consent. Accepting is a separate act."
run "$B" "gage accept $ID"
pause

say "And this is the whole point: before bob's agent sees any content, it is"
say "told who signed it, that the key is confirmed, and that nothing inside"
say "carries any authority."
printf '\033[1m$ gage open ~/.gage/inbox/accepted/%s\033[0m\n' "$ID"
( export GAGE_HOME="$B"; gage open "$B/inbox/accepted/$ID" )
pause 3
