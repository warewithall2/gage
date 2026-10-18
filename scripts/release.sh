#!/usr/bin/env bash
# Build release binaries for every machine we can reach, and check them.
#
# The gap this closes: until now, giving ctx to another person meant telling
# them to install Rust and compile it. That is a development workflow, not a
# product, and it is the step that decides whether a colleague ever starts.
#
#   scripts/release.sh [ssh-host ...]
#
# Builds here, then on each host given, and collects the binaries into dist/
# with their checksums. Every binary reports the commit it was built from
# (`ctx --version`), and this refuses to build from a dirty tree: a binary
# that names a commit it does not match is worse than one with no version at
# all, and the journal freezes verdicts, so "which ctx decided this" has to
# have an exact answer.
set -u
cd "$(dirname "$0")/.." || exit 2
REPO=$PWD
OUT=$REPO/dist
fail() { echo "release: $*" >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || fail "the tree is dirty; commit or stash first"
REV=$(git rev-parse --short HEAD)
VER=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
echo "release: ctx $VER at $REV"
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
LOCAL=$OUT/ctx-$VER-$HOSTOS-$HOSTARCH
cp target/release/ctx "$LOCAL"
stamp "$LOCAL" "$HOSTOS-$HOSTARCH"

# Each remote machine builds its own: cross-compiling needs a C toolchain per
# target (rustls brings C), and a binary built on the machine it runs on is
# one fewer thing to be wrong about.
for h in "$@"; do
  echo "building on $h..."
  if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$h" "test -d ~/ctx" 2>/dev/null; then
    echo "  skipped: $h is unreachable or has no ~/ctx" >&2
    continue
  fi
  ssh -o BatchMode=yes "$h" "cd ~/ctx && git fetch -q origin 2>/dev/null; \
    git rev-parse --short HEAD" > "$OUT/.rev.$h" 2>/dev/null
  RREV=$(tr -d '[:space:]' < "$OUT/.rev.$h"); rm -f "$OUT/.rev.$h"
  if [ "$RREV" != "$REV" ]; then
    echo "  skipped: $h is at ${RREV:-unknown}, not $REV -- sync it first" >&2
    continue
  fi
  ssh -o BatchMode=yes "$h" "cd ~/ctx && . ~/.cargo/env 2>/dev/null; \
    cargo build --release >/dev/null 2>&1 && uname -s && uname -m" > "$OUT/.plat" 2>/dev/null \
    || { echo "  skipped: the build on $h failed" >&2; rm -f "$OUT/.plat"; continue; }
  ROS=$(sed -n 1p "$OUT/.plat" | tr '[:upper:]' '[:lower:]')
  RARCH=$(sed -n 2p "$OUT/.plat"); rm -f "$OUT/.plat"
  B=$OUT/ctx-$VER-$ROS-$RARCH
  scp -q -o BatchMode=yes "$h:~/ctx/target/release/ctx" "$B" || { echo "  copy failed" >&2; continue; }
  chmod +x "$B"
  # Checked by asking the binary, not by trusting the path it came from.
  # A binary for another platform cannot run here -- so the host that built
  # it is asked instead, which is still the binary answering rather than the
  # build script assuming.
  if [ "$ROS-$RARCH" = "$HOSTOS-$HOSTARCH" ]; then
    stamp "$B" "$ROS-$RARCH"
  else
    RSTAMP=$(ssh -o BatchMode=yes "$h" "~/ctx/target/release/ctx --version" 2>/dev/null)
    case "$RSTAMP" in
      *dirty*) fail "$ROS-$RARCH was built from a dirty tree on $h" ;;
      *"$REV"*) echo "  $ROS-$RARCH: $RSTAMP (checked on $h)" ;;
      *) fail "$ROS-$RARCH reports '${RSTAMP:-nothing}', which does not name $REV" ;;
    esac
  fi
done

( cd "$OUT" && (sha256sum ctx-"$VER"-* 2>/dev/null || shasum -a 256 ctx-"$VER"-*) > SHA256SUMS )
echo
echo "dist/:"
ls -1sh "$OUT" | sed 's/^/  /'
echo
echo "Checksums are in dist/SHA256SUMS. Each binary reports its commit:"
echo "  ctx --version   ->  ctx $VER ($REV)"
