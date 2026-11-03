#!/usr/bin/env bash
# Cross-version compatibility: the new code and the last release, both ways.
#
# The replay-defense change adds two OPTIONAL fields to the signed manifest
# and deliberately does not bump FORMAT_VERSION. That claim rests on three
# properties of the code, and reasoning about them is not the same as running
# them against a real old binary:
#
#   * signature verification is over the raw manifest.json bytes re-read from
#     disk, not a re-serialization, so a field an old reader has never heard
#     of cannot change what it verifies;
#   * `Manifest` has no `deny_unknown_fields`, so an old reader parses a new
#     manifest instead of refusing it;
#   * `expires` and `context` are not in `expected_id`, so an old reader's
#     recomputation of the content id still matches.
#
# All three are invisible from inside one version. Hence this file: a bundle
# built by THIS tree is opened by the released binary, and a bundle built by
# the released binary is opened by this tree.
#
# Fixture identities and fixture homes only. Nothing here touches a real home,
# a real contact list or the services.
set -u
cd "$(dirname "$0")/.." || exit 2
REPO=$PWD
NEW="${CTX:-$REPO/target/release/gage}"
# The release to check against. One minor version back is the one upgrade
# anybody actually performs.
PREV_TAG="${GAGE_PREV_TAG:-v0.3.5}"
pass=0; fail=0
ok()   { pass=$((pass+1)); }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
want()   { if grep -qF -e "$2" "$1"; then ok; else bad "expected to find: $2  (in ${1##*/})"; fi; }
wantno() { if grep -qF -e "$2" "$1"; then bad "should NOT contain: $2  (in ${1##*/})"; else ok; fi; }
code()   { if [ "$2" = "$3" ]; then ok; else bad "exit $2, wanted $3 ($1)"; fi; }

[ -x "$NEW" ] || { echo "compat: no binary at $NEW; cargo build --release first"; exit 2; }

# ---------------------------------------------------------------------------
# The previous release's binary.
#
# Built from the tag into a cache, rather than taken off PATH: `gage` on PATH
# is whatever was last installed, which during a release window is the thing
# being tested. A binary whose version cannot be confirmed is not used, and
# the run SKIPS rather than passing -- a compatibility check that silently
# did not happen is the one kind of result this file must never produce.
# ---------------------------------------------------------------------------
CACHE="${CTX_COMPAT_DIR:-${CTX_SELFCHECK_DIR:-$HOME/.ctx-selfcheck}/compat}"
PREV="${GAGE_PREV_BIN:-$CACHE/$PREV_TAG/gage}"
WANTVER=${PREV_TAG#v}

prev_is_right() {
  [ -x "$PREV" ] || return 1
  "$PREV" --version 2>/dev/null | grep -q "$WANTVER"
}

skip() {
  echo "compat: SKIP -- $1"
  echo "        The two new manifest fields were NOT checked against $PREV_TAG."
  echo "        compat: 0 checks, 0 failed, SKIPPED"
  exit 0
}

if ! prev_is_right; then
  command -v git >/dev/null 2>&1 || skip "no git, so $PREV_TAG cannot be built"
  git -C "$REPO" rev-parse "$PREV_TAG" >/dev/null 2>&1 \
    || skip "this repo has no tag $PREV_TAG"
  command -v cargo >/dev/null 2>&1 || . "$HOME/.cargo/env" 2>/dev/null
  command -v cargo >/dev/null 2>&1 || skip "no cargo on PATH"
  SRC=$CACHE/$PREV_TAG/src
  rm -rf "$SRC"; mkdir -p "$SRC" || skip "cannot write $SRC"
  echo "compat: building $PREV_TAG (once; cached in $CACHE)"
  # `git archive` rather than a worktree: the stash and the worktree list are
  # shared with every other checkout of this repo, and a test must not touch
  # either. --offline because the lockfile is checked in and a compatibility
  # test that needs the network is one that fails on a train.
  git -C "$REPO" archive "$PREV_TAG" | tar -x -C "$SRC" \
    || skip "could not extract $PREV_TAG"
  ( cd "$SRC" && CARGO_TARGET_DIR="$CACHE/$PREV_TAG/target" \
      cargo build --release --offline >"$CACHE/$PREV_TAG/build.log" 2>&1 ) \
    || skip "$PREV_TAG did not build (see $CACHE/$PREV_TAG/build.log)"
  mkdir -p "$(dirname "$PREV")"
  cp "$CACHE/$PREV_TAG/target/release/gage" "$PREV" \
    || skip "could not place the $PREV_TAG binary"
  prev_is_right || skip "the binary built from $PREV_TAG does not report $WANTVER"
fi

echo "compat: $("$PREV" --version) vs $("$NEW" --version)"

T=$(mktemp -d)
trap '[ -n "${KEEPT:-}" ] || rm -rf "$T"' EXIT
[ -n "${KEEPT:-}" ] && echo "fixtures kept in $T"

# Fixture identities, fixture homes. Created by the NEW binary and used by
# both: the identity file format is unchanged by this work, and sharing one
# pair of homes is what makes "the other binary opens it" mean anything.
mkdir -p "$T"/{new,old}
GAGE_HOME=$T/new $NEW init newside >/dev/null 2>&1
GAGE_HOME=$T/old $NEW init oldside >/dev/null 2>&1
NK=$(GAGE_HOME=$T/new $NEW whoami | cut -f2)
OK_=$(GAGE_HOME=$T/old $NEW whoami | cut -f2)

# Both sides add AND confirm, so a verdict that drops to UNCONFIRMED is a
# real finding rather than an artefact of the fixture.
addc() { # addc <home> <name> <key> <binary>
  GAGE_HOME=$1 $4 add "$2" "$3" >/dev/null 2>&1 || return 1
  local fp; fp=$(GAGE_HOME=$1 $4 fingerprint "$2" 2>/dev/null | cut -f2) || return 1
  [ -n "$fp" ] || return 1
  GAGE_HOME=$1 $4 confirm "$2" "$fp" >/dev/null 2>&1
}
addc "$T/old" newside "$NK"  "$NEW" || bad "fixture: old home could not add the new side"
addc "$T/new" oldside "$OK_" "$NEW" || bad "fixture: new home could not add the old side"
GAGE_HOME=$T/new $NEW route oldside "$T/old" >/dev/null
GAGE_HOME=$T/old $NEW route newside "$T/new" >/dev/null
printf 'the payload\n' > "$T/work.md"

# ---------------------------------------------------------------------------
echo "a NEW bundle carrying both new fields verifies and opens under $PREV_TAG"
# ---------------------------------------------------------------------------
GAGE_HOME=$T/new $NEW send --to oldside --subject "new-with-fields" \
  --file "$T/work.md" --ttl 7d --context "build run 12" >/dev/null 2>&1
B1=$(GAGE_HOME=$T/old $NEW inbox --json | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('subject')=='new-with-fields': print(r['id']); break")
if [ -n "$B1" ]; then ok; else bad "the new-fields bundle was not delivered"; fi
want "$T/old/inbox/pending/$B1/manifest.json" '"expires"'
want "$T/old/inbox/pending/$B1/manifest.json" '"context": "build run 12"'
GAGE_HOME=$T/old "$PREV" open "$T/old/inbox/pending/$B1" > "$T/c1.txt" 2>&1
code "old-opens-new" $? 0
# The signature verified over bytes containing two fields this binary has
# never heard of, and the content id it recomputed still addressed the
# content. Both would show up here as a verdict or a tamper line.
want   "$T/c1.txt" "SENDER VERIFIED"
wantno "$T/c1.txt" "does not address this content"
wantno "$T/c1.txt" "PAYLOAD DOES NOT MATCH"
wantno "$T/c1.txt" "Contents withheld"
want   "$T/c1.txt" "the payload"
# It cannot ENFORCE what it does not know about, and that is the whole shape
# of an optional field: the old reader is not broken by it, and it is not
# pretending to honour it either. Stated as a check so that nobody later
# reads this suite as proving old binaries gate expiry.
wantno "$T/c1.txt" "expires    :"

echo "and $PREV_TAG can inspect it without reporting a defect"
GAGE_HOME=$T/old "$PREV" inspect "$T/old/inbox/pending/$B1" > "$T/c2.txt" 2>&1
code "old-inspects-new" $? 0
wantno "$T/c2.txt" "TAMPERED"

echo "KNOWN LIMITATION: forwarding through $PREV_TAG strips both fields, and the strip is visible"
mkdir -p "$T/third"
GAGE_HOME=$T/third $NEW init third >/dev/null 2>&1
TK=$(GAGE_HOME=$T/third $NEW whoami | cut -f2)
addc "$T/third" oldside "$OK_" "$NEW" || bad "fixture: third could not add the old side"
addc "$T/old" third "$TK" "$NEW"      || bad "fixture: old side could not add third"
GAGE_HOME=$T/old "$PREV" accept "$B1" >/dev/null 2>&1
GAGE_HOME=$T/old "$PREV" forward "$T/old/inbox/accepted/$B1" --to third \
  --out "$T/fwd" >/dev/null 2>&1
code "old-forwards-new" $? 0
# The sharpest thing this file found, and it is a limitation rather than a
# defect in either version -- so it is PINNED here rather than left as a
# permanent red that nobody could act on.
#
# A forward re-signs, which means it re-serializes the manifest through the
# forwarding binary's own struct. A 0.3.5 struct has no `expires` and no
# `context`, so a 0.3.5 hop drops both and signs the result. The next
# recipient then holds a handoff with no bound and no run label on it.
#
# A FORMAT_VERSION bump does NOT fix this, which is why it is not a format
# decision: 0.3.5 never checks `manifest.v` on a bundle (only the backup
# format and a rotation claim are version-checked), so a bump is invisible to
# it and it would go on stripping. Nothing in this tree can make a binary
# preserve a field it does not have. What IS true, and is the property worth
# holding, is the next check: the strip leaves no trace of a binding, so a
# new reader reports "not declared" rather than inventing a bound that was
# never honoured. Senders who need the binding to survive every hop need
# every hop upgraded, and that is now written down in docs/spec.md.
#
# Asserted in the direction reality runs, so that a future release which
# preserves the fields turns this check red and makes somebody come and read
# this note.
if [ -f "$T/fwd/manifest.json" ]; then
  wantno "$T/fwd/manifest.json" '"expires"'
  wantno "$T/fwd/manifest.json" '"context"'
  echo "  NOTE: a $PREV_TAG hop re-signs without the two new fields, so forwarding"
  echo "        through an un-upgraded machine strips the expiry and the run label."
  # And the consequence a reader depends on: nothing is invented in their
  # place, and the stripped bundle is not reported as bound to anything.
  GAGE_HOME=$T/third $NEW open "$T/fwd" > "$T/cf.txt" 2>&1
  code "new-opens-stripped-forward" $? 0
  want  "$T/cf.txt" "expires    : not declared"
  want  "$T/cf.txt" "context    : not declared"
else
  bad "the forward produced no manifest"
fi

# ---------------------------------------------------------------------------
echo "a bundle built by $PREV_TAG opens under the new code"
# ---------------------------------------------------------------------------
GAGE_HOME=$T/old "$PREV" send --to newside --subject "old-bundle" \
  --file "$T/work.md" >/dev/null 2>&1
B2=$(GAGE_HOME=$T/new $NEW inbox --json | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('subject')=='old-bundle': print(r['id']); break")
if [ -n "$B2" ]; then ok; else bad "the $PREV_TAG bundle was not delivered"; fi
# It has neither field, which is exactly the state the new code must read as
# "the sender declared nothing" rather than as anything having lapsed.
wantno "$T/new/inbox/pending/$B2/manifest.json" '"expires"'
wantno "$T/new/inbox/pending/$B2/manifest.json" '"context"'
GAGE_HOME=$T/new $NEW open "$T/new/inbox/pending/$B2" > "$T/c3.txt" 2>&1
code "new-opens-old" $? 0
want   "$T/c3.txt" "SENDER VERIFIED"
want   "$T/c3.txt" "expires    : not declared"
want   "$T/c3.txt" "context    : not declared"
want   "$T/c3.txt" "the payload"
wantno "$T/c3.txt" "Contents withheld"
wantno "$T/c3.txt" "EXPIRED"

echo "an old bundle is not retroactively expired, however old it is"
GAGE_HOME=$T/new $NEW inbox --json > "$T/c4.txt" 2>&1
want   "$T/c4.txt" '"freshness": "undeclared"'
want   "$T/c4.txt" '"expired": false'
# Not even when this machine is in a run: declaring no context is the state
# of every bundle built before the field existed, so it must never read as a
# mismatch.
GAGE_CONTEXT="build run 12" GAGE_HOME=$T/new $NEW open \
  "$T/new/inbox/pending/$B2" > "$T/c5.txt" 2>&1
want   "$T/c5.txt" "context_match : undeclared"
wantno "$T/c5.txt" "MISMATCH"

echo "a bundle built by the new code WITHOUT the fields is byte-identical in shape to one $PREV_TAG writes"
# The compatibility promise at its narrowest: an existing invocation, after
# the upgrade, produces a manifest with the same set of keys it did before.
GAGE_HOME=$T/new $NEW send --to oldside --subject "new-plain" \
  --file "$T/work.md" >/dev/null 2>&1
B3=$(GAGE_HOME=$T/old $NEW inbox --json | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('subject')=='new-plain': print(r['id']); break")
python3 - "$T/old/inbox/pending/$B3/manifest.json" \
          "$T/new/inbox/pending/$B2/manifest.json" <<'PY'
import json,sys
new=set(json.load(open(sys.argv[1])))
old=set(json.load(open(sys.argv[2])))
extra=new-old
print("KEYS-MATCH" if not extra else "KEYS-DIFFER "+",".join(sorted(extra)))
PY
GAGE_HOME=$T/old "$PREV" open "$T/old/inbox/pending/$B3" > "$T/c6.txt" 2>&1
code "old-opens-new-plain" $? 0
want "$T/c6.txt" "the payload"

echo
echo "compat: $((pass+fail)) checks, $fail failed"
[ "$fail" -eq 0 ]
