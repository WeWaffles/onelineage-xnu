#!/usr/bin/env python3
"""Decode OLXNCNY1 channel-canary records from a /proc/last_kmsg dump.

Record (8 x u64): magic, offset index, path, seq, CNTPCT, payload, readback, stage.
A copy whose readback equals its payload proves that path's store reached memory.
"""
import struct
import sys

MAGIC = 0x31594E434E584C4F  # "OLXNCNY1"
OFF_NAMES = {0: "low  +0x1500", 1: "mid  +0x80000", 2: "tail +0xFE000"}
PATH_NAMES = {0: "alias (Normal-NC TTBR1)", 1: "ml_phys_write_double_64", 2: "identity V=P"}


def main(argv):
    if len(argv) < 2:
        print("usage: canary.py <dump>")
        return 2
    data = open(argv[1], "rb").read()
    pat = struct.pack("<Q", MAGIC)
    hits, start = [], 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1

    print(f"{argv[1]}: {len(data)} bytes, {len(hits)} canary record(s)")
    if not hits:
        print("  NO CANARY: neither offset nor path survived, or the writer never ran")
        return 1

    seen = {}
    for off in hits:
        w = struct.unpack("<8Q", data[off:off + 64])
        _, oi, path, seq, tick, payload, rb, stage = w
        if oi > 2 or path > 2:
            continue  # text that happens to match the magic
        ok = "LANDED" if rb == payload else "NOT LANDED"
        seen.setdefault(oi, set()).add(path)
        print(f"  @{off:#08x} {OFF_NAMES.get(oi, oi):16} {PATH_NAMES.get(path, path):26} "
              f"seq={seq:5} ticks={tick:#x} stage={stage:#04x}  {ok}"
              f"{'' if rb == payload else f' (read {rb:#x})'}")

    print("\n  survivors by offset:")
    for oi in (0, 1, 2):
        paths = seen.get(oi)
        print(f"    {OFF_NAMES[oi]:16} {'- none' if not paths else ', '.join(PATH_NAMES[p].split(' ')[0] for p in sorted(paths))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
