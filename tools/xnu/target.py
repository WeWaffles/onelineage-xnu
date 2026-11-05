#!/usr/bin/env python3
"""Switch the kernel build between the phone and QEMU, and rebuild.

The same source tree produces both kernels, but two switches in
pexpert/arm64/SWEET.h must disagree between the targets:

  SWEET_QEMU_LOG      log region at 0x8F000000 (QEMU RAM) instead of
                      0x8883F0000 (the vendor region the phone's bootloader
                      preserves).  Getting this wrong is not subtle but it is
                      confusing: a phone build run under QEMU takes a data abort
                      on its first log store, lands in the entry stub's fault
                      vector at PC=0x200, and looks like a broken payload.
                      (build/qemu-out-v94)

  SWEET_SKIP_CPACR    the phone must NOT write CPACR_EL1 (Gunyah takes the VM
                      down over it), while QEMU starts at reset with
                      CPACR_EL1 = 0 and must have it written or the first SIMD
                      instruction traps.

Flipping these by hand is what made an offline verification loop expensive;
this does it idempotently, rebuilds, and (for qemu) builds the ADT and payload.

Usage:
  python3 tools/xnu/target.py show
  python3 tools/xnu/target.py phone [--no-build]
  python3 tools/xnu/target.py qemu  [--no-build] [--ramdisk build/sweet_init_v8.macho]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "build/xnu-src/source"
SWEET_H = SRC / "pexpert/pexpert/arm64/SWEET.h"
SYM = REPO / "build/xnu-build/sym"

RE_QEMU_LOG = re.compile(r"^(\s*)(/\*\s*)?#\s*define\s+SWEET_QEMU_LOG(\s*\*/)?\s*$", re.M)
RE_SKIP_CPACR = re.compile(r"^(\s*)(/\*\s*)?#\s*define\s+SWEET_SKIP_CPACR(\s*\*/)?\s*$", re.M)


def _matches(text: str, rx: re.Pattern) -> list[tuple[bool, str]]:
    """Return (is_active, line) for each match."""
    out = []
    for m in rx.finditer(text):
        out.append((m.group(2) is None, m.group(0)))
    return out


def state() -> dict[str, bool]:
    text = SWEET_H.read_text()
    qlog = _matches(text, RE_QEMU_LOG)
    cpacr = _matches(text, RE_SKIP_CPACR)
    return {
        "qemu_log": any(active for active, _ in qlog),
        "skip_cpacr": any(active for active, _ in cpacr),
    }


def apply(target: str) -> bool:
    """Rewrite the two switches for `target`.  Returns True if the file changed."""
    text = SWEET_H.read_text()
    before = text

    want_qlog = target == "qemu"
    want_skip = target == "phone"

    def setter(rx: re.Pattern, active: bool, macro: str) -> None:
        nonlocal text
        # Normalise whichever form is present into the requested one.
        text = rx.sub(lambda m: f"{m.group(1)}{'' if active else '/* '}#define {macro}"
                                f"{'' if active else ' */'}", text)

    setter(RE_QEMU_LOG, want_qlog, "SWEET_QEMU_LOG")
    setter(RE_SKIP_CPACR, want_skip, "SWEET_SKIP_CPACR")

    if text != before:
        SWEET_H.write_text(text)
        return True
    return False


def build(jobs: int = 8) -> int:
    cmd = ["make", f"-j{jobs}", "ARCH_CONFIGS=ARM64", "KERNEL_CONFIGS=DEVELOPMENT",
           "MACHINE_CONFIGS=SWEET", "BUILD_WERROR=0"]
    p = subprocess.run(cmd, cwd=SRC, capture_output=True, text=True)
    #
    # Only the compiler's own diagnostics count.  Matching a bare "error:" is
    # useless here: the kernel's log strings are full of them ("Returned with
    # error: %d", "... returned an error: %d"), so a clean build looks broken.
    errs = [ln for ln in (p.stdout + p.stderr).splitlines()
            if re.search(r"^\s*\S+:\d+:\d+: error: ", ln)]
    if p.returncode != 0 or errs:
        print("build failed:")
        print("\n".join(errs[:20]) or (p.stdout + p.stderr)[-2000:])
        return 1
    src = SRC / "BUILD/obj/DEVELOPMENT_ARM64_SWEET/kernel.development.sweet"
    if not src.exists():
        print(f"build produced no kernel at {src}")
        return 1
    SYM.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, SYM / src.name)
    print(f"kernel -> {SYM / src.name}")
    return 0


def publish_kernel() -> int:
    """Copy the kernel `make` produced into the tree the payload builders read.

    The same trap the phone driver documents: `make` writes BUILD/obj/, payloads
    are built from build/xnu-build/sym/, and nothing used to copy between them,
    so a "rebuild" could measure a kernel from an hour ago.
    """
    src = SRC / "BUILD/obj/DEVELOPMENT_ARM64_SWEET/kernel.development.sweet"
    if not src.exists():
        print(f"no built kernel at {src}")
        return 1
    SYM.mkdir(parents=True, exist_ok=True)
    for name in ("kernel.development.sweet", "kernel.development.sweet.dSYM"):
        s = SRC / "BUILD/obj/DEVELOPMENT_ARM64_SWEET" / name
        if not s.exists():
            continue
        d = SYM / name
        if d.exists():
            shutil.rmtree(d) if d.is_dir() else d.unlink()
        if s.is_dir():
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)
    print(f"kernel -> {SYM / src.name} "
          f"({time.strftime('%H:%M:%S', time.localtime(src.stat().st_mtime))})")
    return 0


def build_qemu_payload(ramdisk: str, outdir: pathlib.Path) -> int:
    outdir = (REPO / outdir).resolve() if not outdir.is_absolute() else outdir
    adt = REPO / "build/qemu_target.adt"
    payload = REPO / "build/qemu_target.bin"
    if publish_kernel():
        return 1
    cmds = [
        ["python3", "tools/xnu/mk_m3q_adt.py",
         "kernel/device-hardware/generic-arm64.json", str(adt),
         "--mode", "qemu", "--ramdisk", ramdisk],
        ["python3", "tools/xnu/build_payload.py",
         "build/xnu-build/sym/kernel.development.sweet", str(adt), str(payload),
         "--target", "qemu",
         "--cmdline", "debug=0xc serial=3 cpus=1 keepsyms=1 rd=md0 "
                      "cs_enforcement_disable=1"],
    ]
    for c in cmds:
        p = subprocess.run(c, cwd=REPO, capture_output=True, text=True)
        if p.returncode != 0:
            print(f"{' '.join(c[:3])} failed:\n{p.stdout[-800:]}{p.stderr[-800:]}")
            return 1
    print(f"payload -> {payload}")
    print(f"run:  python3 tools/xnu/run_qemu.py {payload.relative_to(REPO)} "
          f"{outdir.relative_to(REPO)} --secs 90 --ramdisk {ramdisk}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=("show", "phone", "qemu"))
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--ramdisk", default="build/sweet_init_v8.macho")
    ap.add_argument("--outdir", default="build/qemu-out-target")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    s = state()
    which = "qemu" if s["qemu_log"] else "phone"
    print(f"SWEET.h: target={which} (QEMU_LOG={s['qemu_log']}, "
          f"SKIP_CPACR={s['skip_cpacr']})")
    if args.target == "show":
        return 0

    changed = apply(args.target)
    print(f"switched to {args.target}" + (" (file changed)" if changed else " (already)"))
    if args.no_build:
        # --no-build only skips the kernel make; the payload is cheap and must
        # still be regenerated, otherwise QEMU boots an ADT that predates the
        # ramdisk and reads zeros from md0.
        if args.target == "qemu":
            return build_qemu_payload(args.ramdisk, pathlib.Path(args.outdir))
        return 0
    rc = build(args.jobs)
    if rc:
        return rc
    if args.target == "qemu":
        return build_qemu_payload(args.ramdisk, pathlib.Path(args.outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
