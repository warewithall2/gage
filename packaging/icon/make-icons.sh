#!/usr/bin/env bash
# Render every icon gage ships from the two SVGs beside this script.
#
# Runs on Linux as well as macOS on purpose: the app is built on a Mac but
# the artwork is edited here, and `iconutil` is macOS-only. The .icns
# container is assembled directly instead -- it is a four-byte magic, a
# length, and one length-prefixed PNG per size, which is less machinery
# than keeping a second toolchain alive.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
# Defaults to the directory make-app.sh copies the icon FROM. It used to
# default to this script's own directory, so the documented "just run it"
# wrote an icns that nothing ever bundled.
OUT="${1:-$HERE/../macos}"
command -v rsvg-convert >/dev/null || { echo "need rsvg-convert" >&2; exit 2; }
mkdir -p "$OUT"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

for s in 16 32 64 128 256 512 1024; do
  rsvg-convert -w $s -h $s "$HERE/gage-icon.svg" -o "$TMP/icon_$s.png"
done

python3 - "$TMP" "$OUT/Gage.icns" <<'PY'
import struct, sys, os
tmp, dest = sys.argv[1], sys.argv[2]
# OSType -> pixel size. The @2x types carry the same pixels as the plain
# type of that size; macOS picks by display scale, not by content.
types = [("icp4",16),("icp5",32),("icp6",64),("ic07",128),("ic08",256),
         ("ic09",512),("ic10",1024),("ic11",32),("ic12",64),
         ("ic13",256),("ic14",512)]
chunks = b""
for ostype, size in types:
    with open(os.path.join(tmp, "icon_%d.png" % size), "rb") as f:
        data = f.read()
    chunks += ostype.encode("ascii") + struct.pack(">I", len(data) + 8) + data
with open(dest, "wb") as f:
    f.write(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)
print("%s (%d bytes, %d sizes)" % (dest, len(chunks) + 8, len(types)))
PY

# The viewer's tab icon needs no step here: the binary serves
# packaging/icon/gage-icon.svg directly, so the artwork and the favicon are
# the same file by construction. This used to copy gage-mark.svg to
# favicon.svg, which nothing read and which was not even the file being
# served -- two ways of being wrong about one icon.
rsvg-convert -w 512 -h 512 "$HERE/gage-icon.svg" -o "$OUT/gage-icon-512.png"
echo "wrote $OUT/gage-icon-512.png (for docs and listings)"
