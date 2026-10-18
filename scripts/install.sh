#!/bin/sh
# Install gage: download a released binary, check it, put it on your PATH.
#
#   curl -fsSL https://gage.sh/install.sh | sh
#
# Or, better, read it first and then run it:
#
#   curl -fsSL https://gage.sh/install.sh -o install.sh
#   less install.sh && sh install.sh
#
# What it does, in order: work out this machine's OS and architecture, ask
# GitHub for the latest release, download the matching binary AND its
# SHA256SUMS, VERIFY the checksum, and only then install to ~/.local/bin.
#
# It never uses sudo and never writes outside PREFIX. If the checksum does not
# match it stops and deletes what it downloaded, because the whole point of
# this project is that you can tell where a binary came from.
#
#   PREFIX=/somewhere/else sh install.sh    # default: ~/.local
#
# POSIX sh on purpose: this has to run on a machine with nothing installed.
set -eu

REPO="warewithall2/gage"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

die() {
  printf '\ngage install: %s\n' "$1" >&2
  shift
  for l in "$@"; do printf '  %s\n' "$l" >&2; done
  exit 1
}

# ---- 1. what machine is this
os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
  Linux-x86_64)            TARGET=linux-x86_64 ;;
  Darwin-arm64|Darwin-aarch64) TARGET=darwin-arm64 ;;
  *)
    die "no released binary for $os on $arch." \
        "gage ships Linux x86_64 and macOS arm64 binaries." \
        "On anything else, build it from source -- it is one command and" \
        "needs no configuration:" \
        "" \
        "    cargo install gage" \
        "" \
        "(Rust: https://rustup.rs)"
    ;;
esac

# ---- 2. the tools this script itself needs
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsL "$1" -o "$2"; }   # no -S: a 404 is reported by this script, in words
  get() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
  get() { wget -qO- "$1"; }
else
  die "neither curl nor wget is installed, so this script cannot download anything." \
      "Install either one, or fetch the binary by hand from" \
      "https://github.com/$REPO/releases/latest"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "no sha256sum or shasum on this machine, so the download cannot be verified." \
      "Refusing to install something unchecked. Install coreutils (Linux) or" \
      "use the macOS system shasum, then run this again."
fi

# ---- 3. which release
printf 'gage install: looking up the latest release...\n'
TAG=$(get "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -1) || TAG=""
[ -n "$TAG" ] || die "could not find the latest release of $REPO." \
  "GitHub may be unreachable, or rate-limiting this address." \
  "You can download it by hand from https://github.com/$REPO/releases/latest" \
  "or build from source with: cargo install gage"
VERSION=${TAG#v}
ASSET="gage-$VERSION-$TARGET"
BASE="https://github.com/$REPO/releases/download/$TAG"
printf 'gage install: %s, %s\n' "$TAG" "$TARGET"

# ---- 4. download into a temp dir that always gets cleaned up
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

dl "$BASE/$ASSET" "$TMP/$ASSET" || die \
  "$TAG has no $ASSET." \
  "That release does not include a binary for this platform." \
  "Build from source instead -- one command, no configuration:" \
  "" \
  "    cargo install gage" \
  "" \
  "(Rust: https://rustup.rs)"

dl "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die \
  "$TAG has no SHA256SUMS, so the download cannot be verified." \
  "Refusing to install something unchecked. Report this at" \
  "https://github.com/$REPO/issues"

# ---- 5. verify BEFORE installing
WANT=$(grep " $ASSET\$" "$TMP/SHA256SUMS" | cut -d' ' -f1 | head -1)
[ -n "$WANT" ] || die "SHA256SUMS does not mention $ASSET, so there is nothing to check it against." \
  "Refusing to install something unchecked."
GOT=$(sum "$TMP/$ASSET")
if [ "$WANT" != "$GOT" ]; then
  die "CHECKSUM MISMATCH -- not installing." \
      "expected: $WANT" \
      "got     : $GOT" \
      "" \
      "The download does not match what the release says it should be. That is" \
      "either a corrupted transfer or something interfering. Nothing has been" \
      "installed and the download has been deleted."
fi
printf 'gage install: checksum ok (%s)\n' "$(printf '%s' "$GOT" | cut -c1-16)..."

# ---- 6. install
mkdir -p "$BINDIR" || die "cannot create $BINDIR." \
  "Pick somewhere you can write: PREFIX=~/somewhere sh install.sh"
chmod +x "$TMP/$ASSET"
mv "$TMP/$ASSET" "$BINDIR/gage" || die "cannot write $BINDIR/gage." \
  "Pick somewhere you can write: PREFIX=~/somewhere sh install.sh"

printf '\ngage install: installed %s\n' "$BINDIR/gage"
if "$BINDIR/gage" --version >/dev/null 2>&1; then
  printf 'gage install: %s\n' "$("$BINDIR/gage" --version)"
else
  die "installed, but $BINDIR/gage would not run." \
      "On macOS the first run of an unsigned binary is refused: open Finder," \
      "right-click it, choose Open, then Open again. Once only."
fi

# ---- 7. say what to do next, exactly
echo
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *)
    echo "First, $BINDIR is not on your PATH. Add it:"
    echo
    echo "    export PATH=\"\$PATH:$BINDIR\""
    echo
    echo "  and put that line in your shell's startup file (~/.bashrc, ~/.zshrc)"
    echo "  so it survives a new terminal."
    echo
    ;;
esac
# Asked, not assumed: `quickstart` is newer than the 0.1.0 binary this may
# have just installed, and telling someone to run a command their copy does
# not have is the worst possible first impression.
if "$BINDIR/gage" quickstart --help >/dev/null 2>&1; then
  echo "Then, one command walks you from nothing to a first handoff:"
  echo
  echo "    gage quickstart"
  echo
  echo "  It makes your identity, shows the four word-pairs a colleague reads"
  echo "  back to you, and offers to send one bundle. Every step is skippable."
  echo
  echo "If you would rather do it a step at a time:"
else
  echo "Then, three commands:"
fi
echo
echo "    gage init <a-name-for-yourself>     # your keypair"
echo "    gage whoami                         # the line you send a colleague"
echo "    gage add <their-name> <their-key>   # after confirming their word-pairs"
echo
echo "  Those word-pairs are the one step nothing can do for you: read them"
echo "  to each other on a call, not in the channel you sent the key through."
echo
echo "The whole tour: https://github.com/$REPO"
echo "Driving it from a script: https://github.com/$REPO/blob/master/docs/agents.md"
