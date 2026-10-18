#!/usr/bin/env bash
# Build release binaries for every machine we can reach, and check them.
#
# The gap this closes: until now, giving gage to another person meant telling
# them to install Rust and compile it. That is a development workflow, not a
# product, and it is the step that decides whether a colleague ever starts.
#
#   scripts/release.sh [ssh-host ...]
#
# Builds here, then on each host given, and collects the binaries into dist/
# with their checksums. Every binary reports the commit it was built from
# (`gage --version`), and this refuses to build from a dirty tree: a binary
# that names a commit it does not match is worse than one with no version at
# all, and the journal freezes verdicts, so "which gage decided this" has to
# have an exact answer.
set -u
cd "$(dirname "$0")/.." || exit 2
# Where the checkout lives on a remote builder. It is `~/ctx` on the machines
# this was written against, for historical reasons -- the project was called
# that -- so it is a variable rather than a surprise.
REMOTE_DIR=${GAGE_REMOTE_DIR:-'~/ctx'}
REPO=$PWD
OUT=$REPO/dist
fail() { echo "release: $*" >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || fail "the tree is dirty; commit or stash first"
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
