#!/usr/bin/env bash
# Load the inert M1 diagnostic module on the the arm64 target.
#
# What this does: insmods a module whose init function prints the running
# release, page size, online CPU count and sizeof(struct module), then returns 0.
# It registers no device node, allocates nothing, and cannot transfer control.
#
# What to expect on success:
#   /proc/modules lists handoff_diag, dmesg shows two HANDOFF_DIAG lines,
#   the phone does not reboot, and the module can be removed with rmmod.
#
# What to expect on ABI mismatch (the pre-load verifier exists to prevent this):
#   insmod fails with "disagrees about version of symbol ..." or
#   "version magic ... should be ..." and nothing is loaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KO="$ROOT/kernel/diag/handoff_diag.ko"
NAME=handoff_diag
REMOTE=/data/local/tmp/$NAME.ko

[ -f "$KO" ] || { echo "missing $KO" >&2; exit 1; }

echo "== pre-flight: device =="
adb get-state >/dev/null || { echo "no device attached" >&2; exit 1; }
adb shell 'su -c "cat /proc/version"' | sed 's/^/   /'

echo "== pre-flight: ABI =="
if command -v docker >/dev/null && docker inspect s26-gki-build >/dev/null 2>&1; then
    docker cp "$KO" s26-gki-build:/tmp/preflight.ko >/dev/null
    docker exec s26-gki-build python3 /lab/olverify.py verify /tmp/preflight.ko \
        /lab/kernel-symbol-crcs.json \
        "6.12.69-android16-6-pb4d3caf-abogkigeneric-4k SMP preempt mod_unload modversions aarch64" \
        | sed 's/^/   /'
else
    echo "   (container s26-gki-build unavailable; skipping CRC cross-check)"
fi

echo "== push =="
adb push "$KO" "$REMOTE" >/dev/null
echo "   $REMOTE"

echo "== insmod =="
if adb shell "su -c 'insmod $REMOTE' 2>&1" | sed 's/^/   /' | grep -q .; then
    echo "   (insmod produced output - see above)"
fi

echo "== after =="
adb shell "su -c \"grep -w $NAME /proc/modules || echo '! module not listed'\"" | sed 's/^/   /'
adb shell "su -c 'dmesg | grep HANDOFF_DIAG | tail -5'" | sed 's/^/   /'
adb shell 'uptime' | sed 's/^/   /'

echo
echo "To remove:  adb shell \"su -c 'rmmod $NAME'\""
echo "If the phone resets instead, the module never ran: read /proc/last_kmsg"
echo "after it comes back (see tools/xnu/lastkmsg_probe.sh)."
