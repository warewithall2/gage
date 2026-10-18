#!/usr/bin/env bash
# The restore drill: prove a backup actually brings an identity back.
#
# Separate from tests/attacks.sh on purpose. That suite asks what an attacker
# gets -- what leaks, what a tampered file does, what a refusal protects. This
# asks the plainer question the decision record insisted on: when someone
# needs this, does it work?
#
# "Restore is tested, not just export." An export path that is exercised and a
# restore path that is not is a backup that does not exist, and you find out on
# the one day it matters.
#
# Fixture homes only. Nothing here reads or writes a real gage home.
set -u
CTX="${CTX:-$PWD/target/release/gage}"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
PASS='correct horse battery staple'

# 1. An identity, and what it is.
CTX_HOME=$T/one $CTX init drillalice >/dev/null 2>&1
FP=$(CTX_HOME=$T/one $CTX fingerprint 2>&1 | head -1)
KEY=$(CTX_HOME=$T/one $CTX whoami 2>/dev/null | cut -f2)
if [ -n "$FP" ] && [ -n "$KEY" ]; then ok; else bad "could not create the fixture identity"; fi

# A correspondent who confirms that key BEFORE the export, so everything
# afterwards is checked against a list that predates the backup.
CTX_HOME=$T/two $CTX init drillbob >/dev/null 2>&1
CTX_HOME=$T/two $CTX add drillalice "$KEY" >/dev/null 2>&1
KEY2=$(CTX_HOME=$T/two $CTX whoami 2>/dev/null | cut -f2)
CTX_HOME=$T/one $CTX add drillbob "$KEY2" >/dev/null 2>&1

# Something signed before the loss, and mail sealed to the old encryption key.
printf 'written before the disk died\n' > "$T/before.md"
CTX_HOME=$T/one $CTX send --to drillbob --subject "before" --file "$T/before.md" \
  --out "$T/before" >/dev/null 2>&1
CTX_HOME=$T/two $CTX send --to drillalice --subject "sealed before" --file "$T/before.md" \
  --out "$T/tobealice" >/dev/null 2>&1
CTX_HOME=$T/two $CTX seal "$T/tobealice" --to drillalice --out "$T/sealed.gageb" >/dev/null 2>&1
if [ -f "$T/sealed.gageb" ]; then ok; else bad "could not seal to the fixture identity"; fi

# 2. Export.
printf '%s\n%s\n' "$PASS" "$PASS" | CTX_HOME=$T/one $CTX export-identity --out "$T/id.bak" >/dev/null 2>&1
if [ -f "$T/id.bak" ]; then ok; else bad "export produced no file"; fi

# 3. The machine is gone. Restore into a fresh, empty home.
rm -rf "$T/one"
printf '%s\n' "$PASS" | CTX_HOME=$T/one $CTX restore-identity "$T/id.bak" >/dev/null 2>&1
if [ $? = 0 ]; then ok; else bad "restore into an empty home failed"; fi

FP2=$(CTX_HOME=$T/one $CTX fingerprint 2>&1 | head -1)
KEYR=$(CTX_HOME=$T/one $CTX whoami 2>/dev/null | cut -f2)
if [ "$FP2" = "$FP" ]; then ok; else bad "fingerprint changed: '$FP' -> '$FP2'"; fi
if [ "$KEYR" = "$KEY" ]; then ok; else bad "both public halves did not come back identical"; fi
if [ "$(CTX_HOME=$T/one $CTX whoami 2>/dev/null | cut -f1)" = drillalice ]; then ok
else bad "the handle did not come back"; fi

# 4. The two things a backup exists for.
#
# A bundle signed BEFORE the export still verifies for the contact who
# confirmed that key -- which is the signing half surviving.
CTX_HOME=$T/two $CTX open "$T/before" > "$T/o1" 2>&1
if grep -qF "SENDER VERIFIED" "$T/o1"; then ok
else bad "a bundle signed before the backup no longer verifies"; fi
# And mail sealed to the old ENCRYPTION key still opens -- which is the half
# people forget is in here, and the half whose loss is irreversible.
CTX_HOME=$T/one $CTX unseal "$T/sealed.gageb" --out "$T/unsealed" >/dev/null 2>&1
if [ $? = 0 ] && [ -f "$T/unsealed/manifest.json" ]; then ok
else bad "mail sealed before the backup cannot be unsealed after the restore"; fi
# The restored identity can still sign something new that the contact accepts.
printf 'written after the restore\n' > "$T/after.md"
CTX_HOME=$T/one $CTX send --to drillbob --subject "after" --file "$T/after.md" \
  --out "$T/after" >/dev/null 2>&1
CTX_HOME=$T/two $CTX open "$T/after" > "$T/o2" 2>&1
if grep -qF "SENDER VERIFIED" "$T/o2"; then ok
else bad "the restored identity cannot sign something a contact accepts"; fi

# 5. Restore into an occupied home refuses and changes nothing.
LIVE=$(sha256sum "$T/one/identity.key" | cut -d' ' -f1)
printf '%s\n' "$PASS" | CTX_HOME=$T/one $CTX restore-identity "$T/id.bak" >/dev/null 2>&1
if [ $? != 0 ]; then ok; else bad "restore overwrote a live identity without being asked"; fi
if [ "$(sha256sum "$T/one/identity.key" | cut -d' ' -f1)" = "$LIVE" ]; then ok
else bad "a refused restore altered the key that was already there"; fi

# 6. A wrong passphrase fails clean and writes nothing.
printf 'this is not the passphrase\n' | CTX_HOME=$T/three $CTX restore-identity "$T/id.bak" >/dev/null 2>&1
if [ $? != 0 ]; then ok; else bad "a wrong passphrase was accepted"; fi
if [ -e "$T/three/identity.key" ]; then bad "a wrong passphrase still wrote an identity"; else ok; fi

# 7. A bit-flipped file fails authentication rather than producing garbage.
python3 - "$T" <<'PYD'
import base64, json, sys
T = sys.argv[1]
d = json.load(open(f"{T}/id.bak"))
raw = bytearray(base64.b64decode(d["ct"])); raw[7] ^= 0x01
d["ct"] = base64.b64encode(bytes(raw)).decode()
json.dump(d, open(f"{T}/flipped.bak", "w"))
PYD
printf '%s\n' "$PASS" | CTX_HOME=$T/four $CTX restore-identity "$T/flipped.bak" >/dev/null 2>&1
if [ $? != 0 ]; then ok; else bad "a bit-flipped backup restored anyway"; fi
if [ -e "$T/four/identity.key" ]; then bad "a bit-flipped backup wrote an identity"; else ok; fi

echo "restore drill: $((pass+fail)) checks, $fail failed"
[ "$fail" -eq 0 ]
