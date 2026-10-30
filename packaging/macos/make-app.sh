#!/bin/sh
set -eu

# Build a relocatable Route B macOS application bundle from a locally built
# darwin gage binary. The binary is an explicit input; this script downloads
# nothing.
if [ "$#" -ne 2 ]; then
  echo "usage: $0 <darwin-gage-binary> <output-directory>" >&2
  exit 2
fi

SOURCE=$1
OUTPUT=$2
[ -f "$SOURCE" ] || { echo "gage binary not found: $SOURCE" >&2; exit 1; }

APP="$OUTPUT/Gage.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
mkdir -p "$MACOS" "$RESOURCES"
cp "$SOURCE" "$MACOS/gage"
cp "$(dirname "$0")/gage-launcher" "$MACOS/gage-launcher"
chmod 755 "$MACOS/gage" "$MACOS/gage-launcher"

# The version the bundle advertises is READ FROM Cargo.toml, never written
# here. It was written here, and on 23 October the app shipped as 0.3.1 with a
# 0.3.2 binary inside it, because a release bumped Cargo.toml and nobody
# remembered this file. A version string kept in two places is a version
# string that is wrong in one of them, and the half that is wrong is always
# the one a person reads in Finder.
#
# Read, not executed. The first version of this fix ran `"$SOURCE" --version`,
# which is the obvious way to ask and the wrong one twice over: a packaging
# script should not execute the thing it is packaging, and the packaging
# suite hands this script a stub whose catch-all branch is `exec sleep 600`.
# The build hung for ten minutes, failed the version check, never reached the
# icon step, and six checks went red on both machines.
MANIFEST="$(dirname "$0")/../../Cargo.toml"
VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$MANIFEST" 2>/dev/null | head -1)
[ -n "$VERSION" ] || { echo "no version in $MANIFEST" >&2; exit 1; }

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>gage-launcher</string>
  <key>CFBundleIdentifier</key><string>sh.gage.app</string>
  <key>CFBundleName</key><string>Gage</string>
  <key>CFBundleDisplayName</key><string>Gage</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <!-- Without this key the dock ignores Resources/Gage.icns entirely, which
       is how the app shipped with artwork that was never going to appear.
       No extension: the value names the file, and macOS adds .icns. -->
  <key>CFBundleIconFile</key><string>Gage</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# The icon. A zero-byte Gage.icns used to be written when the artwork was
# missing, which is worse than no file: the bundle looks complete, the plist
# points at it, and the dock silently falls back to a generic document. If
# there is no icon to copy, say so and leave the key pointing at nothing --
# the same visible result, but with a line in the build output about it.
ICON_SRC="$(dirname "$0")/Gage.icns"
if [ -s "$ICON_SRC" ]; then
  cp "$ICON_SRC" "$RESOURCES/Gage.icns"
else
  echo "make-app: no icon at $ICON_SRC (run packaging/icon/make-icons.sh)" >&2
fi

# The window, when this machine can build it. Route A.
#
# The SDK is named explicitly and that is the whole trick. The Command Line
# Tools ship a Swift 6.1.2 compiler beside a MacOSX26 SDK built with Swift
# 6.2, and swiftc picks the NEWEST SDK unless told otherwise, which fails
# with "this SDK is not supported by the compiler". Nothing is missing when
# that happens; installing Xcode is not the fix. So: pick the newest SDK the
# compiler actually accepts, by trying each from newest down and keeping the
# first that compiles. If none does -- or there is no swiftc, as on Linux --
# the bundle ships without a window and the launcher opens the browser
# instead, which is Route B and still a working app.
# `main.swift`, and the name is load-bearing: swiftc allows top-level
# statements only in a file called that, EXCEPT when it is compiling a single
# file, where any name works. So this source compiled fine for months as
# GageApp.swift and broke the moment a second file joined it -- with the
# error swallowed by the fallback below, which shipped a bundle with no
# window and said so only on stderr. Renaming it is the fix; the check in
# tests/packaging.sh is what makes the breakage loud.
WINDOW_SRC=$(dirname "$0")/main.swift
# GageURL.swift holds the two URL predicates, kept apart from AppKit so the
# suite can run them. Both files compile into the one executable.
WINDOW_URLSRC=$(dirname "$0")/GageURL.swift
if command -v swiftc >/dev/null 2>&1 && [ -f "$WINDOW_SRC" ] && [ -f "$WINDOW_URLSRC" ]; then
  SDK_ROOT=$(xcode-select -p 2>/dev/null)/SDKs
  built=
  for sdk in $(ls -d "$SDK_ROOT"/MacOSX*.sdk 2>/dev/null | sort -Vr); do
    case ${sdk##*/} in MacOSX.sdk) continue ;; esac
    if swiftc -O -sdk "$sdk" -target arm64-apple-macos13 \
         -o "$MACOS/GageWindow" "$WINDOW_SRC" "$WINDOW_URLSRC" >/dev/null 2>&1; then
      built=$sdk
      break
    fi
  done
  if [ -n "$built" ]; then
    chmod 755 "$MACOS/GageWindow"
    echo "  window: built against ${built##*/}"
  else
    rm -f "$MACOS/GageWindow"
    echo "warning: no SDK here compiles the window; the app will open a browser" >&2
  fi
else
  echo "  window: skipped (no swiftc); the app will open a browser" >&2
fi

if command -v codesign >/dev/null 2>&1; then
  codesign -s - --force --deep "$APP"
else
  echo "warning: codesign unavailable; leaving bundle unsigned" >&2
fi

echo "built $APP"
