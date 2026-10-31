#!/usr/bin/env bash
# M0: does the kernel log survive a crash-and-reset on this device?
#
# The whole module-handoff plan depends on having *some* feedback after we hand
# control to a payload that has no drivers.  There is no serial console
# (console=ttynull, no /dev/ttyMSM*), there is no ramoops node, and
# /sys/fs/pstore has never held a record.
#
# The candidate channel is /proc/last_kmsg.  Existing evidence says it is
# populated on the crash path, not on a clean reboot: the file currently holds
# the previous session's kernel log ending in
#
#     stop_on_panic is called, freezing...RAMDUMP BUILD @ 16:44:57 on Sep 28 2026
#
# followed by a fresh XBL log opening "** XBL(90, warm reset, valid magic) **".
#
# A module's printk() lands in the same ring buffer, and a handoff ends in a
# reset rather than a clean shutdown, so this script reproduces that exact path:
# write one marker line, force a controlled panic, then look for the marker.
#
# This script does NOT load a module and does not write to any block device.
# It does reset the phone, which is disruptive: unsynced data is lost, and the
# RAMDUMP path makes the next boot take noticeably longer.
set -uo pipefail

MARK="OLXNU-M0-$(date +%s)"
SERIAL=${SERIAL:-}

adb_cmd() { if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi; }

echo "== marker: $MARK"
adb_cmd shell 'su -c uptime'

# 1. Emit the marker into the kernel ring buffer and confirm it landed.
adb_cmd shell "su -c 'echo \"\$0: $MARK pre-crash marker\" > /dev/kmsg'"
echo "== marker present in live dmesg:"
adb_cmd shell "su -c 'dmesg | grep -a $MARK'" || echo "  (marker not visible in live dmesg -- report this)"

# 2. Flush filesystems before yanking the kernel out from under them.
adb_cmd shell 'su -c sync'
adb_cmd shell 'sync'

# 3. sysrq is disabled by default (sysrq=0) and writable as root; a crash
#    request is what exercises the stop_on_panic / RAMDUMP flush path.
adb_cmd shell 'su -c "cat /proc/sys/kernel/sysrq"'
adb_cmd shell 'su -c "echo 1 > /proc/sys/kernel/sysrq"'

echo "== forcing controlled kernel panic (phone will reset)"
adb_cmd shell 'su -c "echo c > /proc/sysrq-trigger"' || true
adb_cmd wait-for-device || true

# 4. RAMDUMP makes boot slower than usual; give it room.
for i in $(seq 1 90); do
  if adb_cmd shell 'su -c "test -r /proc/last_kmsg"' >/dev/null 2>&1; then break; fi
  sleep 3
done
sleep 10

echo "== uptime after:"
adb_cmd shell 'su -c uptime'

echo "== searching /proc/last_kmsg for the marker"
if adb_cmd shell "su -c 'grep -a $MARK /proc/last_kmsg'" | grep -q "$MARK"; then
  echo "RESULT: PASS - crash path persists printk; last_kmsg is a usable console"
  echo "  => M1 (inert module) is worth building; module printk will be readable after a jump."
else
  echo "RESULT: FAIL - marker absent from last_kmsg"
  echo "  Check whether the file changed at all (size/first line). If it did not, the"
  echo "  flush is conditional on something else and the next channel to try is the"
  echo "  preserved RAMDUMP region (/dev/block/by-name/rawdump), not the log buffer."
fi

echo "== last_kmsg size / first line:"
adb_cmd shell 'su -c "wc -l /proc/last_kmsg; head -c 120 /proc/last_kmsg"'
