#!/usr/bin/env python3
"""Census of every run dump: which markers exist and how far the history ring got.

Answers one question per dump: did the boot die before it wrote anything, or did
it write and lose it?  The history ring is emitted from the first STARTUP hook, so
a dump with zero intact copies never reached a hook.
"""
import glob
import struct
import sys

HIST = 0x313053534E584C4F   # "OLXNSS01"
CANARY = 0x31594E434E584C4F  # "OLXNCNY1"

STAGES = {
    0x95: "STARTUP entry", 0x96: "STARTUP returned", 0x98: "hook phase",
    0xaa: "bsd_init entered", 0xe0: "IOFindBSDRoot returned",
    0xad: "syscall heartbeat", 0xd6: "display fmt p0", 0xd7: "display fmt p1",
    0xec: "display addr", 0xe2: "display unpack",
}


def census(path):
    d = open(path, "rb").read()
    out = {"size": len(d), "tag": d.count(b"XNUKRN1"), "jmp3": d.count(b"XNUJMP3"),
           "jmp5": d.count(b"XNUJMP5"), "hist": 0, "maxseq": -1, "stage": None,
           "canary": 0, "olxnu": d.count(b"OLXNU:")}
    pat = struct.pack("<Q", HIST)
    i = d.find(pat)
    while i >= 0:
        try:
            w = struct.unpack("<8Q", d[i:i + 64])
        except struct.error:
            break
        if w[1] < 64 and w[2] < (1 << 40):
            out["hist"] += 1
            if w[2] > out["maxseq"]:
                out["maxseq"], out["stage"] = w[2], w[3]
        i = d.find(pat, i + 1)
    out["canary"] = d.count(struct.pack("<Q", CANARY))
    return out


def main():
    rows = []
    for path in sorted(glob.glob("hw/m3*_run/last_kmsg.txt")):
        run = path.split("/")[1]
        rows.append((run, census(path)))
    print(f"{'run':10} {'hist':>5} {'maxseq':>8} {'stage':>6} {'tag':>4} {'jmp3':>5} {'jmp5':>5} {'canary':>6}  stage name")
    for run, c in rows:
        st = c["stage"]
        name = STAGES.get(st, "") if st is not None else ""
        print(f"{run:10} {c['hist']:5} {c['maxseq']:8} "
              f"{('0x%02x' % st) if st is not None else '-':>6} "
              f"{c['tag']:4} {c['jmp3']:5} {c['jmp5']:5} {c['canary']:6}  {name}")
    empty = [r for r, c in rows if c["hist"] == 0]
    print(f"\nruns: {len(rows)}, with no history record at all: {len(empty)} -> {', '.join(empty)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
