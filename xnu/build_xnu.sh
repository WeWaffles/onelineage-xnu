#!/usr/bin/env bash
# Build the OneLineage QEMU-milestone XNU kernel from the pinned patch series.
#
# macOS only: the build needs Xcode, Kernel.framework private headers, mig, and
# blacktop/darwin-xnu-build. The output is a kernel image for offline QEMU work.
# Nothing here touches a phone, a boot partition, or a running Android kernel.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERIES="$ROOT/xnu/series.json"
PATCH_DIR="$ROOT/xnu/patches"
TOOLS="$ROOT/tools/xnu"
WORK="${ONELINEAGE_XNU_WORK:-$ROOT/build/xnu-build}"
OUT="$ROOT/build/xnu"
LOG="$WORK/build.log"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || die "XNU is built on macOS only (this host is $(uname -s))"
command -v git >/dev/null 2>&1 || die "git is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

pin() {
  python3 - "$SERIES" "$1" <<'PY'
import json
import sys

series = json.load(open(sys.argv[1], encoding="utf-8"))
print(series["build"][sys.argv[2]])
PY
}

DXB_REPO="$(pin dxb_repo)"
DXB_SHA="$(pin dxb_sha)"
MACOS_VERSION="$(pin macos_version)"
KERNEL_CONFIG="$(pin kernel_config)"
MACHINE_CONFIG="$(pin machine_config)"
ARCH_CONFIG="$(pin arch_config)"

say "verifying the vendored series against its manifest"
python3 "$TOOLS/verify_xnu_series.py" --verify-only

[[ -n "$(xcode-select -p 2>/dev/null || true)" ]] || die "select an Xcode installation with xcode-select"
xcrun --sdk macosx --find mig >/dev/null 2>&1 || die "mig was not found in the selected SDK"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
[[ -d "$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers" ]] \
  || die "Kernel.framework headers are missing; install Xcode or the matching KDK"

mkdir -p "$WORK"
DXB="$WORK/dxb"
if [[ ! -d "$DXB/.git" ]]; then
  say "fetching darwin-xnu-build at $DXB_SHA"
  git init -q "$DXB"
fi
git -C "$DXB" fetch -q --depth 1 "$DXB_REPO" "$DXB_SHA"
git -C "$DXB" checkout -q FETCH_HEAD
HEAD_SHA="$(git -C "$DXB" rev-parse HEAD)"
[[ "$HEAD_SHA" == "$DXB_SHA" ]] || die "darwin-xnu-build is at $HEAD_SHA, expected $DXB_SHA"

say "installing the pinned series into the build harness"
cp "$PATCH_DIR"/*.patch "$DXB/patches/"
# libfirehose_kernel is built arm64e-only; the ported kernel is plain arm64.
sed -i '' 's/ARCHS="x86_64 arm64e" VALID_ARCHS="x86_64 arm64e"/ARCHS="x86_64 arm64e arm64" VALID_ARCHS="x86_64 arm64e arm64"/' "$DXB/build.sh"
grep -q 'VALID_ARCHS="x86_64 arm64e arm64"' "$DXB/build.sh" \
  || die "could not widen libfirehose_kernel architectures in build.sh"

say "building $KERNEL_CONFIG $ARCH_CONFIG $MACHINE_CONFIG on macOS $MACOS_VERSION (log: $LOG)"
set +e
( cd "$DXB" && MACOS_VERSION="$MACOS_VERSION" KERNEL_CONFIG="$KERNEL_CONFIG" \
    ARCH_CONFIG="$ARCH_CONFIG" MACHINE_CONFIG="$MACHINE_CONFIG" bash build.sh ) 2>&1 | tee "$LOG"
STATUS="${PIPESTATUS[0]}"
set -e

# build.sh silently skips a patch it cannot apply, so a kernel can be produced
# with part of the series missing. Treat that as a failed build, not a warning.
say "confirming that the whole series was applied"
MISSING=""
for patch in "$PATCH_DIR"/*.patch; do
  name="$(basename "$patch")"
  grep -qF "Applying patch: " "$LOG" && grep -qF "$name" "$LOG" || MISSING="$MISSING $name"
done
[[ -z "$MISSING" ]] || die "these patches never applied, so the build is invalid:$MISSING"

[[ "$STATUS" -eq 0 ]] || die "build.sh exited $STATUS; see $LOG"

KERNEL=""
for candidate in "$DXB/fakeroot/System/Library/Kernels"/kernel.*; do
  if [[ -f "$candidate" ]]; then
    KERNEL="$candidate"
    break
  fi
done
[[ -n "$KERNEL" ]] || die "build.sh produced no kernel image under fakeroot/System/Library/Kernels"

mkdir -p "$OUT"
TARGET="$OUT/$(basename "$KERNEL")"
cp "$KERNEL" "$TARGET"

say "structure check"
python3 "$TOOLS/inspect_macho.py" "$TARGET" || die "the produced kernel is not an inspectable ARM64 Mach-O image"

say "kernel: $TARGET"
shasum -a 256 "$TARGET"
say "next: generate the QEMU ADT, pack it with tools/xnu/build_payload.py, then run the QEMU harness"
