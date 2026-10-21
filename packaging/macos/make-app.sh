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

cat > "$CONTENTS/Info.plist" <<'PLIST'
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
  <key>CFBundleShortVersionString</key><string>0.3.0</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# The icon pipeline is intentionally optional until the artwork is ready.
if [ -f "$(dirname "$0")/Gage.icns" ]; then
  cp "$(dirname "$0")/Gage.icns" "$RESOURCES/Gage.icns"
else
  : > "$RESOURCES/Gage.icns"
fi

if command -v codesign >/dev/null 2>&1; then
  codesign -s - --force --deep "$APP"
else
  echo "warning: codesign unavailable; leaving bundle unsigned" >&2
fi

echo "built $APP"
