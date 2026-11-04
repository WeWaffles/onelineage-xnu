#!/usr/bin/env python3
"""Read the two-copy proof ring out of a /proc/last_kmsg dump.

The ring lives near the start of the console store, which is the part of the
2 MiB region the next boot preserves (hw/m310, m312, m316), so it is read by
offset from the channel base rather than by scanning for magic: a scan cannot
tell the kernel's records from a stale copy, and the base moves with every dump
because the store is a rotated circular buffer.

    python3 tools/xnu/proof_ring.py hw/m318_run/last_kmsg.txt

Layout (sweet_early.c): SWEET_PROOF_BASE, 14 slots of 0x100 bytes.
    0..11    rotation: 0xd6, 0xd7, 0xec, 0xe2, 0xad - two copies each
    12, 13   0xad syscall heartbeat, outside the rotation (m321 and later)

0xad carries its own clock: milliseconds = ticks * 1000 / cntfrq.
"""
from __future__ import annotations
import pathlib, struct, sys

MAGIC = 0x313053534E584C4F  # "OLXNS01"
BASE, SLOTS, STRIDE = 0x600, 14, 0x100
STAGES = {
    0xac: "kernel reached the startup hook (registered, fb base, chars)",
    0xad: "heartbeat from the syscall path (syscalls, ticks, cntfrq, pets)",
    0xae: "watchdog pet probe (PA, value written, value read back, pets)",
    0xd6: "pipe0 format/stride", 0xd7: "pipe1 format/stride",
    0xec: "fetch source address (run IOVA, p0 0x04c, p1 0x04c, meta)",
    0xe2: "unpack-pattern group, both pipes",
}

def main(argv):
    path = argv[1] if len(argv) > 1 else "hw/last_kmsg.txt"
    dump = pathlib.Path(path).read_bytes()
    tag = dump.find(b"XNUKRN1")
    base = tag if tag >= 0 else 0
    rows = []
    for i in range(SLOTS):
        pos = (base + BASE + i * STRIDE) % len(dump)
        try:
            magic, idx, seq, stage, a, b, c, d = struct.unpack("<8Q", dump[pos:pos + 0x40])
        except struct.error:
            continue
        rows.append((i, magic == MAGIC, idx, seq, stage, a, b, c, d))
    good = [r for r in rows if r[1]]
    print(f"{path}: {len(dump)} bytes, tag {tag:#x}, intact slots {len(good)}/{SLOTS}")
    if not good:
        print("  EMPTY: no records. Either XNU never wrote the ring, or the next boot overwrote")
        print("  the store entirely (hw/m314, m317 both did this).")
    for i, ok, idx, seq, stage, a, b, c, d in rows:
        extra = ""
        if ok and stage == 0xad and c:
            extra = f"  -> {a} syscalls, {b * 1000 / c:.0f} ms, {d} pets"
        if ok and stage == 0xae:
            extra = f"  -> wrote {b:#x}, read back {c:#x}; functional pet not established by readback"
        print(f"  slot {i:2} {'ok' if ok else '--':2} seq={seq:8} stage={stage:#5x} "
              f"a={a:#x} b={b:#x} c={c:#x} d={d:#x}  {STAGES.get(stage,'?')}{extra}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
