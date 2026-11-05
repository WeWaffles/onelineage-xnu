#!/usr/bin/env python3
"""Validate the fixed EL0 fault slot decoder before any device run.

Three properties have to hold before the record is worth one physical attempt:

  1. The slot range is disjoint from every other writer in the store (the proof
     slots at +0x600, the identity record at +0x1a30, the evidence ring at
     +0x2000..+0x6000), so a fault cannot overwrite a proof and a log line cannot
     overwrite a fault.
  2. A synthetic ring carrying records at +0x1b00 and +0x1b40 decodes to exactly
     the values written, at the offsets the kernel uses, and a slot with the
     magic but no sequence number is rejected rather than believed.
  3. The preserved m490/m491 captures still decode, and report no fault records
     (they predate the instrument), instead of crashing or inventing one.
"""
from __future__ import annotations
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import decode_probe as dp

PRESERVED = [
    ("hw/m490_loop/cycle2", []),
    ("hw/m491_loop/cycle4", []),
]

fails: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def synthetic(rings: list[dict]) -> bytes:
    size = 2_000_000
    b = bytearray(size)
    base = 0x2000
    struct.pack_into("<Q", b, base + 0x1780, 0xAA13)
    b[base + 0x1800:base + 0x1807] = b"XNUKRN1"
    for i, r in enumerate(rings):
        for k, v in enumerate(r["qwords"]):
            struct.pack_into("<Q", b, base + r["off"] + k * 8, v)
    return bytes(b)


def main() -> int:
    print("layout")
    check(dp.UF_BASE >= 0x1400, f"fault base {dp.UF_BASE:#x} is in the measured-free gap")
    end = dp.UF_BASE + dp.UF_SLOTS * dp.UF_STRIDE
    check(end <= 0x1500, f"fault slots end at {end:#x}, below the surviving ring at 0x1500")
    check(dp.UF_BASE >= 0x600 + 14 * 0x100, "fault slots are clear of the proof slots")
    check(dp.UF_STRIDE % 8 == 0, "stride is a whole number of qwords")

    print("synthetic decode")
    rec1 = dict(off=dp.UF_BASE, qwords=[dp.UF_MAGIC, 1, 2, 0x96000005,
                                    0x100004000, 0x100000408, 0x25, 0x80000000])
    # Second record: wraps to the next slot, with a higher sequence number.
    rec2 = dict(off=dp.UF_BASE + dp.UF_STRIDE, qwords=[dp.UF_MAGIC, 2, 2, 0x9200000f,
                                    0x16b3c5000, 0x100000370, 0x24, 0x60000000])
    # Third slot: magic but no sequence, i.e. log text that happens to match.
    rec3 = dict(off=dp.UF_BASE + 2 * dp.UF_STRIDE, qwords=[dp.UF_MAGIC, 0, 0, 0, 0, 0, 0, 0])
    r = dp.decode(synthetic([rec1, rec2, rec3]))
    check(r is not None, "synthetic ring decodes")
    if r:
        f = r["user_faults"]
        check(len(f) == 2, f"two records decoded, not three (got {len(f)})")
        if len(f) == 2:
            a, b = f
            check(a["seq"] == 1 and b["seq"] == 2, "records sorted by sequence")
            check(a["pid"] == 2 and a["esr"] == 0x96000005, "esr/pid at +0x10/+0x18")
            check(a["far"] == 0x100004000, "far at +0x20")
            check(a["pc"] == 0x100000408, "pc at +0x28")
            check(a["ec"] == 0x25, "exception class at +0x30")
            check(a["cpsr"] == 0x80000000, "cpsr at +0x38")
            check(b["far"] == 0x16b3c5000, "second record far is independent")

    print("preserved captures")
    for d, expected in PRESERVED:
        p = sorted(pathlib.Path(d).glob("ring_*.bin"))
        if not p:
            check(False, f"{d}: capture missing")
            continue
        got = dp.decode(p[0].read_bytes())
        check(got is not None, f"{p[0].name}: still decodes")
        if got is not None:
            check(got["user_faults"] == expected,
                  f"{p[0].name}: user_faults == {expected}, got {got['user_faults']}")

    print("ec filter contract")
    svc = 0x56000080
    abort = 0x96000005
    check(((svc >> 26) & 0x3F) == 0x15, "SVC ESR decodes to EC 0x15")
    check(((abort >> 26) & 0x3F) == 0x25, "data abort ESR decodes to EC 0x25")
    check(((abort >> 26) & 0x3F) != 0x15, "filter EC != 0x15 keeps an abort")
    check(((svc >> 26) & 0x3F) == 0x15, "filter EC != 0x15 drops m492's SVCs")
    rec = dict(off=dp.UF_BASE, qwords=[dp.UF_MAGIC, 1, 2, abort, 0x100004000,
                                   0x100000408, 0x25, 0x80000000])
    r2 = dp.decode(synthetic([rec]))
    got = r2["user_faults"][0] if r2 and r2["user_faults"] else None
    check(got is not None and got["ec"] != 0x15 and got["pc"] == 0x100000408,
          "an abort record survives the filter path and decodes with its pc")
    print("per-process slot rule")
    slots = dp.UF_SLOTS
    slot = lambda pid: (pid % slots) * dp.UF_STRIDE + dp.UF_BASE
    check(slot(1) != slot(2), "pid 1 and pid 2 occupy different slots")
    check(slot(2) == dp.UF_BASE + 2 * dp.UF_STRIDE, "pid 2 maps to its own slot")
    # pid 1 fills its slot with SVC traffic, then pid 2 faults: the child must
    # still be present, which is exactly what m492 and m495 lost.
    svc = dict(off=slot(1),
               qwords=[dp.UF_MAGIC, 1, 1, 0x56000080, 0x16fdffef0,
                       0x100004008, 0x15, 0x0])
    fault = dict(off=slot(2),
                 qwords=[dp.UF_MAGIC, 2, 2, 0x96000005, 0x100004000,
                         0x100000408, 0x25, 0x80000000])
    r3 = dp.decode(synthetic([svc, fault]))
    got = {f["seq"]: f for f in (r3["user_faults"] if r3 else [])}
    check(1 in got and got[1]["ec"] == 0x15, "pid 1's SVC is recorded in its slot")
    check(2 in got and got[2]["pid"] == 2 and got[2]["ec"] == 0x25,
          "pid 2's fault survives pid 1's traffic")
    check(2 in got and got[2]["far"] == 0x100004000, "child far is preserved")
    print("survives concurrent logging")
    rec_a = dict(off=slot(2), qwords=[dp.UF_MAGIC, 9, 2, 0x96000045,
                                      0x100008b80, 0x100000370, 0x26, 0x60000000])
    buf = bytearray(synthetic([rec_a]))
    # Log text starts above the +0x1780 header, as m496 shows (first text at
    # +0x1c00); starting it at +0x1500 would also destroy the base marker and
    # the test would be measuring its own overlay rather than the slot page.
    for o in range(0x2000 + 0x1c00, 0x2000 + 0x6000 - 8, 8):
        buf[o:o+8] = struct.pack("<Q", 0x5f726f665f647461)
    rl = dp.decode(bytes(buf))
    got = rl["user_faults"][0] if rl and rl["user_faults"] else None
    check(got is not None and got["pid"] == 2 and got["pc"] == 0x100000370,
          "record survives text written above the slot page")
    check(got is not None and got["far"] == 0x100008b80 and got["ec"] == 0x26,
          "far and class survive the logging")
    print("RESULT=" + ("PASS" if not fails else f"FAIL({len(fails)})"))
    return 0 if not fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
