#!/usr/bin/env bash
# Build release binaries for every machine we can reach, and check them.
#
# The gap this closes: until now, giving gage to another person meant telling
# them to install Rust and compile it. That is a development workflow, not a
# product, and it is the step that decides whether a colleague ever starts.
#
#   scripts/release.sh [ssh-host ...]
#   scripts/release.sh --audit          # no build: just where this version is
#
# Either way it ends by reading, live, where this version actually stands on
# each channel a person could install from -- the tag, the GitHub release
# page `install.sh` resolves, and the crates.io version `cargo install gage`
# would hand to anyone on a platform with no binary. `--audit` exits non-zero
# while any of them trails, which a plain run does not: at build time nothing
# is published yet, and failing then would fail every normal release.
#
# Builds here, then on each host given, and collects the binaries into dist/
# with their checksums. Every binary reports the commit it was built from
# (`gage --version`), and this refuses to build from a dirty tree: a binary
# that names a commit it does not match is worse than one with no version at
# all, and the journal freezes verdicts, so "which gage decided this" has to
# have an exact answer.
set -u
cd "$(dirname "$0")/.." || exit 2

# `--audit` answers "is this version actually out?" without building
# anything, and exits non-zero while any channel still trails. It exists
# because a plain run cannot answer that: at build time the tag is usually
# unpushed and nothing is published yet, so failing then would fail every
# normal release. The drift this catches is the opposite case -- a version
# built, tagged and forgotten on one channel for four releases.
AUDIT=
case ${1:-} in --audit) AUDIT=1; shift ;; esac
# Where the checkout lives on a remote builder. It is `~/ctx` on the machines
# this was written against, for historical reasons -- the project was called
# that -- so it is a variable rather than a surprise.
REMOTE_DIR=${GAGE_REMOTE_DIR:-'~/ctx'}
REPO=$PWD
OUT=$REPO/dist
fail() { echo "release: $*" >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || [ -n "$AUDIT" ] \
  || fail "the tree is dirty; commit or stash first"
# FULL hashes for comparison. Git auto-sizes abbreviated hashes as a repo
# grows, so the two machines returned 7 and 8 characters for the same commit
# and the string comparison below silently decided they were different
# commits. It had been working by luck.
REV=$(git rev-parse --short HEAD)
FULLREV=$(git rev-parse HEAD)
VER=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
echo "release: gage $VER at $REV"
mkdir -p "$OUT"

stamp() {   # <binary> <label>
  local b=$1 label=$2
  local got
  got=$("$b" --version 2>/dev/null)
  case "$got" in
    *"$REV"*) ;;
    *) fail "$label reports '$got', which does not name $REV" ;;
  esac
  case "$got" in
    *dirty*) fail "$label was built from a dirty tree" ;;
  esac
  echo "  $label: $got"
}

# Everything from here to the checksums is the build. `--audit` is a
# read-only question about an existing version, so it skips straight to the
# state report at the bottom.
if [ -z "$AUDIT" ]; then

# This machine.
echo "building here..."
cargo build --release >/dev/null 2>&1 || fail "the local build failed"
HOSTOS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOSTARCH=$(uname -m)
LOCAL=$OUT/gage-$VER-$HOSTOS-$HOSTARCH
cp target/release/gage "$LOCAL"
stamp "$LOCAL" "$HOSTOS-$HOSTARCH"

# Each remote machine builds its own: cross-compiling needs a C toolchain per
# target (rustls brings C), and a binary built on the machine it runs on is
# one fewer thing to be wrong about.
for h in "$@"; do
  echo "building on $h..."
  if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$h" "test -d $REMOTE_DIR" 2>/dev/null; then
    echo "  skipped: $h is unreachable or has no $REMOTE_DIR" >&2
    continue
  fi
  ssh -o BatchMode=yes "$h" "cd $REMOTE_DIR && git fetch -q origin 2>/dev/null; \
    git rev-parse HEAD" > "$OUT/.rev.$h" 2>/dev/null
  RREV=$(tr -d '[:space:]' < "$OUT/.rev.$h"); rm -f "$OUT/.rev.$h"
  if [ "$RREV" != "$FULLREV" ]; then
    echo "  skipped: $h is at ${RREV:-unknown}, not $FULLREV -- sync it first" >&2
    continue
  fi
  ssh -o BatchMode=yes "$h" "cd $REMOTE_DIR && . ~/.cargo/env 2>/dev/null; \
    cargo build --release >/dev/null 2>&1 && uname -s && uname -m" > "$OUT/.plat" 2>/dev/null \
    || { echo "  skipped: the build on $h failed" >&2; rm -f "$OUT/.plat"; continue; }
  ROS=$(sed -n 1p "$OUT/.plat" | tr '[:upper:]' '[:lower:]')
  RARCH=$(sed -n 2p "$OUT/.plat"); rm -f "$OUT/.plat"
  B=$OUT/gage-$VER-$ROS-$RARCH
  scp -q -o BatchMode=yes "$h:$REMOTE_DIR/target/release/gage" "$B" || { echo "  copy failed" >&2; continue; }
  chmod +x "$B"
  # Checked by asking the binary, not by trusting the path it came from.
  # A binary for another platform cannot run here -- so the host that built
  # it is asked instead, which is still the binary answering rather than the
  # build script assuming.
  if [ "$ROS-$RARCH" = "$HOSTOS-$HOSTARCH" ]; then
    stamp "$B" "$ROS-$RARCH"
  else
    RSTAMP=$(ssh -o BatchMode=yes "$h" "$REMOTE_DIR/target/release/gage --version" 2>/dev/null)
    case "$RSTAMP" in
      *dirty*) fail "$ROS-$RARCH was built from a dirty tree on $h" ;;
      *"$REV"*) echo "  $ROS-$RARCH: $RSTAMP (checked on $h)" ;;
      *) fail "$ROS-$RARCH reports '${RSTAMP:-nothing}', which does not name $REV" ;;
    esac
  fi
done

( cd "$OUT" && (sha256sum gage-"$VER"-* 2>/dev/null || shasum -a 256 gage-"$VER"-*) > SHA256SUMS )
echo
echo "dist/:"
ls -1sh "$OUT" | sed 's/^/  /'
echo
echo "Checksums are in dist/SHA256SUMS. Each binary reports its commit:"
echo "  gage --version   ->  gage $VER ($REV)"

fi   # end of the build

# ---------------------------------------------------------------------------
# Where this version actually is, per channel, read live.
#
# Building binaries is the part this script does; it is not the part that
# reaches anybody. `docs/install.sh` resolves GitHub's LATEST RELEASE, and
# tells every unsupported platform to `cargo install gage` -- so a tag with
# no release page, or a crates.io version left behind, is an installer handing
# out an older product while the docs describe this one.
#
# That is not hypothetical: crates.io sat at 0.3.0 while the project shipped
# 0.3.1, 0.3.2, 0.3.3 and 0.3.4, because nothing here ever mentioned it. The
# fix is not a reminder in a document somebody reads once -- it is this
# section, which runs on every release and says the number it found.
#
# A channel that cannot be checked is reported as unknown, never as done:
# silence is the failure mode this whole block exists to end.
# ---------------------------------------------------------------------------
echo
echo "release state for $VER:"
behind=0

# The tag, locally and on the remote. A page cannot exist without it.
if git rev-parse "v$VER" >/dev/null 2>&1; then
  if git ls-remote --tags origin "refs/tags/v$VER" 2>/dev/null | grep -q .; then
    printf '  %-17s %s\n' "tag v$VER" "pushed"
  else
    printf '  %-17s %s\n' "tag v$VER" "LOCAL ONLY   ->  git push origin v$VER"
    behind=$((behind+1))
  fi
else
  printf '  %-17s %s\n' "tag v$VER" "MISSING      ->  git tag -a v$VER -m 'gage $VER' && git push origin v$VER"
  behind=$((behind+1))
fi

# The GitHub release page, which is what install.sh resolves.
if command -v gh >/dev/null 2>&1; then
  LATEST=$(gh release view --json tagName -q .tagName 2>/dev/null)
  case "$LATEST" in
    "v$VER") printf '  %-17s %s\n' "github release" "v$VER" ;;
    "")      printf '  %-17s %s\n' "github release" "NONE        ->  gh release create v$VER dist/gage-$VER-* dist/SHA256SUMS"
             behind=$((behind+1)) ;;
    *)       printf '  %-17s %s\n' "github release" "$LATEST -- installers get THAT, not $VER"
             echo "                    ->  gh release create v$VER dist/gage-$VER-* dist/SHA256SUMS"
             behind=$((behind+1)) ;;
  esac
else
  printf '  %-17s %s\n' "github release" "unknown (no gh here)"
fi

# crates.io, via the sparse index: one JSON object per line, oldest first.
CIO=$(curl -fsS -m 10 https://index.crates.io/ga/ge/gage 2>/dev/null \
      | sed -n 's/.*"vers":"\([^"]*\)".*/\1/p' | tail -1)
if [ -z "$CIO" ]; then
  printf '  %-17s %s\n' "crates.io" "unknown (could not read the index)"
elif [ "$CIO" = "$VER" ]; then
  printf '  %-17s %s\n' "crates.io" "$VER"
else
  printf '  %-17s %s\n' "crates.io" "$CIO -- \`cargo install gage\` gives THAT"
  echo "                    ->  cargo publish        (needs cargo login; a real"
  echo "                        publish is irreversible, so it is a person's step)"
  behind=$((behind+1))
fi

if [ "$behind" -gt 0 ]; then
  echo
  echo "  $behind channel(s) behind: $VER is built, not released."
  [ -n "$AUDIT" ] && exit 1
fi
exit 0
