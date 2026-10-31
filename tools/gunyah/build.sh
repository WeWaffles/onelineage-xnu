#!/bin/sh
# Build the Gunyah probes for the phone.
#
# The phone's kernel is 6.12.69-android16-6, so an Android NDK clang targeting
# API 34 produces a binary the device loader accepts.  Static, so nothing has
# to be pushed beside it.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
NDK=${NDK:-/opt/homebrew/share/android-commandlinetools/ndk/27.2.12479018/toolchains/llvm/prebuilt/darwin-x86_64/bin}
CC=${CC:-$NDK/aarch64-linux-android34-clang}
OUT=${OUT:-$HERE/out}
PROBE=${1:-gunyah_lend_start}

mkdir -p "$OUT"

if [ ! -x "$CC" ]; then
	echo "no cross compiler at $CC" >&2
	echo "set NDK or CC to an Android NDK llvm bin directory" >&2
	exit 1
fi

# probe.dtb is embedded, so the guest config image is reproducible from source.
dtc -q -I dts -O dtb -o "$OUT/probe.dtb" "$HERE/probe.dts"
xxd -i -n probe_dtb "$OUT/probe.dtb" > "$OUT/probe_dtb.h"

"$CC" -static -O2 -Wall -Wextra -I"$OUT" \
	-o "$OUT/$PROBE" "$HERE/$PROBE.c"

echo "built $OUT/$PROBE"
