#!/bin/sh
# Ask the payload module how large a window it can actually get.
#
# M24 needs the framebuffer and the VM to stop sharing pages, and the cheap way
# to do that is a larger payload window: the kernel image occupies the first
# 32 MB, and a 64 MB window leaves only 14.5 MB for the VM once the 18.4 MB
# framebuffer is carved out.  The module's allocation is a cascade of
# strategies (own the range, CMA, dma_alloc_coherent) and a size it cannot get
# falls back to a *smaller* window without failing, which is worse than a clear
# error: hw/m279 asked for 256 MB and was handed 16 MB.
#
# This loads the module once per size, prints what `/info` reports, and unloads
# it again.  No jump, no reboot.
#
#   usage: tools/xnu/payload_window_probe.sh [size_mb ...]

set -u

MODULE=${MODULE:-/data/local/tmp/olxnu/olxnu_payload2_mod_v14.ko}
FROM=${FROM:-0xAE0000000}

if [ "$#" -eq 0 ]; then
	set -- 64 96 128 192 256
fi

adb devices | sed -n '2p' | sed 's/^/device: /'

for mb in "$@"; do
	printf '\n=== %s MB ===\n' "$mb"
	# The module registers as olxnu_payload2_mod, not as its proc_name.
	for name in olxnu_payload2_mod olxnu_payload2; do
		adb shell "su 0 sh -c \"rmmod $name 2>/dev/null; true\"" >/dev/null 2>&1
	done
	adb shell "su 0 sh -c \"insmod $MODULE proc_name=olxnu_payload2 payload_size_mb=$mb target_pa=$FROM auto_base=1\"" 2>&1
	adb shell "su 0 sh -c \"cat /proc/olxnu_payload2/info\"" 2>&1 | sed -n '1,6p'
	for name in olxnu_payload2_mod olxnu_payload2; do
		adb shell "su 0 sh -c \"rmmod $name 2>/dev/null; true\"" >/dev/null 2>&1
	done
done

echo
echo "Pick the largest size that reports the same value as requested; then set"
echo "payload_size_mb and --mem-size in tools/xnu/run_sm8850_jump.py to match."
