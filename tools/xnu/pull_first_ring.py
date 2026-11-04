#!/usr/bin/env python3
"""Pull the bootloader-preserved pmsg ring and never discard it.

Earlier runs stored the ring only when AA13 was present, so a run without AA13
left no bytes at all and "no AA13" could not be told apart from "device not
readable".  This always writes what it read, prints a marker census, and
decodes rings only when AA13 validates the buffer as ours.

Exit: 0 = AA13 present, 2 = saved but no AA13, 3 = nothing read.
"""
from __future__ import annotations
import argparse, pathlib, struct, subprocess, time

RING_OFFSET = 0x1780
PROOF_MAGIC = 0x313053534E584C4F   # "OLXNS01"
SYS_MAGIC = 0x4F4C584E
MARKERS = ("AA13", "XNUKRN1", "XNULE01", "XNUJMP5", "XNUJMP3", "XNUJMP2",
           "OLXNS01", "SWEET", "sweet-")


def read_ring(timeout=25):
    try:
        r = subprocess.run(["adb", "exec-out", "su", "0", "sh", "-c",
                            "cat /proc/last_kmsg"], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return b""
    return r.stdout if r.returncode == 0 else b""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--tries", type=int, default=20)
    ap.add_argument("--sleep", type=int, default=3)
    a = ap.parse_args()
    a.outdir.mkdir(parents=True, exist_ok=True)
    aa = (0xAA13).to_bytes(8, "little")
    raw, found = b"", False
    for _ in range(a.tries):
        d = read_ring()
        if d:
            raw = d
            if aa in d:
                found = True
                break
        time.sleep(a.sleep)
    (a.outdir / "last_kmsg_raw.bin").write_bytes(raw)
    (a.outdir / "last_kmsg_raw.txt").write_text(raw.decode("latin1", errors="replace"))
    print(f"saved {len(raw)} bytes")
    if not raw:
        print("NOTHING READ")
        return 3
    print("markers: " + " ".join(f"{m}={raw.count(m.encode())}" for m in MARKERS))
    if not found:
        print(f"no AA13; XNUKRN1 at {raw.find(b'XNUKRN1')} of {len(raw)}")
        return 2
    base = raw.find(aa) - RING_OFFSET
    g = lambda o: struct.unpack_from("<Q", raw, base + o)[0]

    def slot(n):
        b = 0x600 + n * 0x100
        return None if g(b) != PROOF_MAGIC else (g(b+0x18), g(b+0x20), g(b+0x28), g(b+0x30), g(b+0x38))

    for n in (17, 24, 25):
        r = slot(n)
        if r:
            st, fd, fl, er, pw = r
            ps = pw.to_bytes(8, "little").split(b"\x00")[0].decode("latin1")
            print(f"console slot={n} stage={st:#x} fd={fd:#x} flags={fl:#x} "
                  f"FREAD={fl&1} FWRITE={(fl>>1)&1} err={er} path~{ps!r}")
    for n in (16, 22):
        r = slot(n)
        if r:
            print(f"slot={n} stage={r[0]:#x} a={r[1]:#x} b={r[2]:#x} c={r[3]:#x} d={r[4]:#x}")
    for k in range(12):
        b = 0x8400 + k * 0x30
        if g(b) != SYS_MAGIC:
            continue
        print(f"sys code={g(b+8)} err={g(b+16)} pid={g(b+24)} arg0={g(b+32)} fdafter={g(b+40)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
