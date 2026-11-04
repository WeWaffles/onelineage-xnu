#!/usr/bin/env python3
"""Pull the previous boot's last_kmsg as soon as the phone is back, and summarise it.

The stage channel (SWEET_LOG_BASE) is a reserved region the bootloader carries
into /proc/last_kmsg, so a run's evidence exists in exactly one file, in one
boot, and is overwritten by the next reset.  hw/m81_run lost its fault report
because the capture happened a boot too late; this tool exists so that cannot
happen again: it waits for the device, pulls immediately, and prints what the
channel actually contained.

Usage:  python3 tools/xnu/pull_crash.py hw/m90_run [--timeout 900]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import time

STAMP = re.compile(rb"XN[A-Z0-9]{2,}")


def adb(args: list[str], timeout: int = 60) -> bytes:
    try:
        p = subprocess.run(["adb", *args], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return b""
    return p.stdout


def wait_for_device(deadline: float) -> bool:
    while time.time() < deadline:
        if b"\tdevice" in adb(["devices"], timeout=20):
            return True
        time.sleep(2)
    return False


def printable(chunk: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 or c == 10 else "." for c in chunk)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--grab-timeout", type=int, default=180)
    ap.add_argument("--after-reset", action="store_true",
                    help="ignore the dump that already exists; capture only the next boot")
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)
    baseline = b""
    if args.after_reset:
        # The previous boot's channel is readable right up to the jump, and it
        # carries XNUKRN1 too, so the tag alone cannot tell the runs apart.
        # hw/m390 was decoded from exactly that: the dump was byte-identical to
        # hw/m389 and had been grabbed before the jump had even reset the phone.
        baseline = adb(["exec-out", "su", "0", "sh", "-c", "cat /proc/last_kmsg"],
                       timeout=30)
        print(f"baseline {len(baseline)} bytes", flush=True)
        off_deadline = time.time() + min(args.timeout, 120)
        while time.time() < off_deadline:
            if b"\tdevice" not in adb(["devices"], timeout=10):
                print("device left (jump taken)", flush=True)
                break
            time.sleep(1)

    if not wait_for_device(time.time() + args.timeout):
        print("device never came back", file=sys.stderr)
        return 1
    print("device is back", flush=True)

    # last_kmsg can still be the pre-crash boot for a few seconds after the
    # device enumerates, so pull repeatedly until the channel content is there
    # or the budget is spent.
    #
    # "XNU" is not the test: the jump module's own messages contain it on every
    # boot that ever loaded the module, so a dump from the boot we jumped *from*
    # passes it too.  hw/m256..m258 were decoded from such a dump and reported
    # "no evidence snapshot", which reads exactly like a boot that produced no
    # evidence at all.  The entry stub's ring tag (XNUKRN1) is written by the
    # stub at the instant of the jump, so a dump holding it is the run we want.
    best = b""
    deadline = time.time() + args.grab_timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        data = adb(["exec-out", "su", "0", "sh", "-c", "cat /proc/last_kmsg"],
                   timeout=30)
        tagged = b"XNUKRN1" in data
        if baseline and data == baseline:
            tagged = False   # still the boot we jumped from
        if tagged or len(data) > len(best):
            best = data
            print(f"  attempt {attempt}: {len(best)} bytes"
                  + (" (XNUKRN1)" if b"XNUKRN1" in best else ""), flush=True)
            # Save as soon as there is something: a run killed by an outer
            # timeout must not lose the only copy of this boot's channel.
            (args.outdir / "last_kmsg.txt").write_bytes(best)
        if tagged:
            break
        time.sleep(2)

    out = args.outdir / "last_kmsg.txt"
    out.write_bytes(best)
    print(f"pulled {len(best)} bytes in {attempt} attempt(s) -> {out}")
    if b"XNUKRN1" not in best:
        print("WARNING: no XNUKRN1 tag - this dump is not the jump's boot "
              "(device probably rebooted again); evidence will be missing",
              file=sys.stderr)

    tags = sorted({m.group(0).decode() for m in STAMP.finditer(best)})
    print("stamps: " + (" ".join(tags) if tags else "(none)"))
    if b"XNUFAULT" in best:
        print("FAULT REPORT PRESENT")

    # Show what surrounds each stamp and each stage-channel record: the region
    # is copied verbatim, so a record reads as tag plus the values after it.
    for m in re.finditer(rb"XN[A-Z0-9]{2,}", best):
        start = max(0, m.start() - 16)
        ctx = best[start:m.start() + 96]
        print(f"  @{m.start():#08x} {printable(ctx).splitlines()[0][:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
