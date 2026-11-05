#!/usr/bin/env bash
# Load the kexec-as-a-module pair on the the arm64 target.
#
# Loading is inert: /dev/kexec appears, but nothing leaves the running kernel
# until the exec ioctl is issued. This script stops before that on purpose.
#
# USB on this phone drops every few minutes, so every device interaction is
# wrapped in a reconnect-and-retry loop.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RETRIES=${RETRIES:-8}

say() { printf '%s\n' "$*"; }

wait_adb() { # wait_adb [max_attempts] - also waits for root to be usable
    local n=${1:-$RETRIES} i
    for ((i = 0; i < n; i++)); do
        if adb shell 'su -c true' >/dev/null 2>&1; then return 0; fi
        sleep 2
        adb reconnect >/dev/null 2>&1
        sleep 2
    done
    return 1
}

# run a command as root on the device, retrying through USB drops
adbsu() {
    local cmd="$1" out i
    for ((i = 0; i < RETRIES; i++)); do
        out=$(adb shell "su -c '$cmd'" 2>&1)
        if ! printf '%s' "$out" | grep -qE "no devices/emulators|device offline|error: closed|device not found"; then
            printf '%s\n' "$out"
            return 0
        fi
        wait_adb 1 || true
        sleep 2
    done
    printf 'USB: still disconnected after %d attempts\n' "$RETRIES" >&2
    return 1
}

push_retry() {
    local src="$1" dst="$2" i
    for ((i = 0; i < RETRIES; i++)); do
        wait_adb 1 || true
        if adb push "$src" "$dst" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    say "push failed: $src" >&2
    return 1
}

say "== device =="
wait_adb || { say "no device attached"; exit 1; }
adbsu 'uptime'

say "== push =="
push_retry "$ROOT/kernel/kexec/kexec_mod_arm64.ko" /data/local/tmp/kexec_mod_arm64.ko || exit 1
push_retry "$ROOT/kernel/kexec/kexec_mod.ko" /data/local/tmp/kexec_mod.ko || exit 1
say "   ok"

# detect_el2 defaults to 1, which makes the module hand-decode an ADRP/ADD pair
# out of set_cpu_boot_mode_flag to locate __boot_cpu_mode. That decode is wrong
# for 6.12 codegen and oopses (measured: panic_msg "Oops PC =
# machine_kexec_compat_load", misaligned pointer ending 0x...045). Linux runs at
# EL1 here (Gunyah holds EL2), which is exactly what detect_el2=0 asserts, so the
# correct setting skips the decoder instead of papering over it.
say "== insmod kexec_mod_arm64 (detect_el2=0) =="
adbsu 'insmod /data/local/tmp/kexec_mod_arm64.ko detect_el2=0 2>&1; echo "exit=$?"'

say "== insmod kexec_mod =="
adbsu 'insmod /data/local/tmp/kexec_mod.ko 2>&1; echo "exit=$?"'

# insmod returning without output means the kernel died mid-call: after a reset
# adb comes back but uptime is ~0, so compare it against the value seen above.

say "== verify =="
adbsu 'ls -l /dev/kexec 2>&1; echo ---; grep -wE "kexec_mod|kexec_mod_arm64" /proc/modules; echo ---; dmesg | grep -iE "kexec" | tail -8; echo ---; cat /sys/module/kexec_mod/parameters/* 2>/dev/null; uptime'

say ""
say "Nothing has jumped. The next step (M3) loads a segment and issues the exec"
say "ioctl; that resets the phone by design, so it is a separate, explicit action."
