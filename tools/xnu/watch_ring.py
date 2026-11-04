#!/usr/bin/env python3
"""Poll /proc/last_kmsg through a jump and preserve the first marked ring.

Started BEFORE the jump so it covers the reset window: it keeps polling across
the disconnect and re-enumeration, ignores Android-only rings, and the moment a
buffer contains XNUKRN1 or any XNUJMP marker it is written to disk whole - even
without AA13.  Read-only: it only cats /proc/last_kmsg.
"""
from __future__ import annotations
import argparse, hashlib, pathlib, re, struct, subprocess, sys, time

MARKS = (b"AA13", b"XNUKRN1", b"XNULE01", b"XNUJMP5", b"XNUJMP3", b"XNUJMP2")
PROOF = 0x313053534E584C4F
SYS = 0x4F4C584E


def read(timeout=15):
    try:
        r = subprocess.run(["adb", "exec-out", "su", "0", "sh", "-c",
                            "cat /proc/last_kmsg"], capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return b""
    return r.stdout if r.returncode == 0 else b""


def decode(d: bytes) -> list[str]:
    out = []
    out.append("markers: " + " ".join(f"{m.decode()}={d.count(m)}" for m in MARKS))
    aa = (0xAA13).to_bytes(8, "little")
    if aa in d:
        base = d.find(aa) - 0x1780
        g = lambda o: struct.unpack_from("<Q", d, base + o)[0]

        def slot(n):
            b = 0x600 + n * 0x100
            return None if g(b) != PROOF else (g(b+0x18), g(b+0x20), g(b+0x28), g(b+0x30), g(b+0x38))

        for n in (17, 24, 25):
            r = slot(n)
            if r:
                st, fd, fl, er, pw = r
                ps = pw.to_bytes(8, "little").split(b"\x00")[0].decode("latin1")
                out.append(f"console slot={n} stage={st:#x} fd={fd:#x} flags={fl:#x} "
                           f"FREAD={fl&1} FWRITE={(fl>>1)&1} err={er} path~{ps!r}")
        for n in (16, 22):
            r = slot(n)
            if r:
                out.append(f"slot={n} stage={r[0]:#x} a={r[1]:#x} b={r[2]:#x} c={r[3]:#x} d={r[4]:#x}")
        for k in range(12):
            b = 0x8400 + k * 0x30
            if g(b) == SYS:
                out.append(f"sys code={g(b+8)} err={g(b+16)} pid={g(b+24)} "
                           f"arg0={g(b+32)} fdafter={g(b+40)}")
    else:
        i = d.find(b"XNUKRN1")
        if i >= 0:
            seg = re.sub(rb"[^\x20-\x7e\n]", b".", d[i:i+700]).decode("latin1")
            out.append("after XNUKRN1: " + seg)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--arm-file", type=pathlib.Path, default=None,
                    help="only accept rings after this file contains --arm-text")
    ap.add_argument("--arm-text", default="jumping")
    a = ap.parse_args()
    a.outdir.mkdir(parents=True, exist_ok=True)
    log = a.outdir / "watch.log"
    cap = a.outdir / "decode.txt"
    deadline = time.time() + a.timeout
    seen: set[str] = set()
    polls = saved = 0
    baseline: str | None = None
    armed = a.arm_file is None
    with log.open("w") as fh:
        while time.time() < deadline:
            d = read()
            polls += 1
            #
            # Only trust a buffer produced by this run.  A watcher started
            # before the jump will otherwise re-read the previous boot's ring
            # (m447 did exactly that: it accepted the m446 buffer, same hash,
            # because the harness had refused to jump).  So: ignore everything
            # until the driver log says the jump was issued, and never accept a
            # buffer identical to the pre-jump baseline.
            #
            if not armed and a.arm_file is not None:
                try:
                    if a.arm_text in a.arm_file.read_text(errors="replace"):
                        armed = True
                        fh.write("armed after jump was issued\n")
                except OSError:
                    pass
            if d and baseline is None:
                baseline = hashlib.sha256(d).hexdigest()[:12]
                fh.write(f"baseline pre-jump ring {baseline} ({len(d)} bytes)\n")
            if (armed and d and any(m in d for m in MARKS)
                    and hashlib.sha256(d).hexdigest()[:12] != baseline):
                h = hashlib.sha256(d).hexdigest()[:12]
                if h not in seen:
                    seen.add(h)
                    p = a.outdir / f"ring_{saved}_{h}.bin"
                    p.write_bytes(d)
                    saved += 1
                    lines = decode(d)
                    fh.write(f"[{time.strftime('%H:%M:%S')}] saved {p.name} ({len(d)} bytes)\n")
                    fh.write("\n".join(lines) + "\n")
                    cap.write_text("\n".join(lines) + "\n")
                    fh.flush()
                    if any(m in d for m in (b"AA13",)):
                        fh.write("AA13 present - stopping\n")
                        return 0
                    fh.write("marked ring without AA13 - continuing to poll\n")
                    fh.flush()
            time.sleep(a.interval)
        fh.write(f"timeout after {polls} polls, {saved} marked buffers saved\n")
    return 2 if saved else 3


if __name__ == "__main__":
    raise SystemExit(main())
