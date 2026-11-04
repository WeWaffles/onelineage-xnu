#!/usr/bin/env python3
"""Capture the first changed ring after a jump, once, with a hard deadline.

The m459/m463 losses came from pulling on a busy device with no deadline and
from re-reading stale buffers.  This tool:
  * takes an immutable pre-jump baseline hash before arming,
  * waits for the driver log to say the jump was issued,
  * accepts only a buffer whose hash differs from that baseline,
  * writes the raw bytes atomically (tmp + rename) before any decoding,
  * never re-reads a hash it has already saved,
  * stops at a strict overall deadline.
Success (exit 0) needs one LE 0xAA13 plus XNUKRN1 in the accepted buffer; every
other changed buffer is still saved so nothing is discarded.
"""
from __future__ import annotations
import argparse, hashlib, os, pathlib, subprocess, time


def read_ring(timeout: float = 8.0) -> bytes | None:
    try:
        r = subprocess.run(["adb", "exec-out", "su", "0", "sh", "-c",
                            "cat /proc/last_kmsg"], capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return r.stdout if r.returncode == 0 and r.stdout else None


def save(path: pathlib.Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--arm-file", type=pathlib.Path, required=True)
    ap.add_argument("--arm-text", default="jumping")
    ap.add_argument("--timeout", type=float, default=150.0)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--min-bytes", type=int, default=1_000_000)
    # Do not touch adb during the jump/reconnect window: polling there competes
    # with the harness on the same channel and hung m468's harness at 95 s.
    ap.add_argument("--post-jump-delay", type=float, default=60.0)
    a = ap.parse_args()
    a.outdir.mkdir(parents=True, exist_ok=True)
    aa = (0xAA13).to_bytes(8, "little")

    base = read_ring()
    # A baseline is only meaningful if the device actually answered: an empty
    # read would make every later buffer look "changed" and defeat the gate.
    if base is None or len(base) < a.min_bytes:
        print("PREFLIGHT_FAIL no baseline ring (device absent or unreadable)", flush=True)
        return 3
    baseline = hashlib.sha256(base).hexdigest()
    print(f"baseline {baseline[:12]} bytes={len(base)}", flush=True)

    deadline = time.time() + a.timeout
    seen: set[str] = set()
    reads = 0
    delayed_done = False
    while time.time() < deadline:
        try:
            armed = a.arm_file.exists() and a.arm_text in a.arm_file.read_text(errors="replace")
        except OSError:
            armed = False
        if not armed:
            time.sleep(a.interval)
            continue
        if not delayed_done:
            time.sleep(a.post_jump_delay)
            delayed_done = True
            continue
        d = read_ring()
        reads += 1
        # A device mid-reset answers with a truncated buffer (m464 saw 46 bytes)
        # and rc=0, which is not a ring; require a full-size read.
        if d is None or len(d) < a.min_bytes:
            time.sleep(a.interval)
            continue
        h = hashlib.sha256(d).hexdigest()
        if h == baseline or h in seen:
            time.sleep(a.interval)
            continue
        seen.add(h)
        p = a.outdir / f"ring_{len(seen):02d}_{h[:12]}.bin"
        save(p, d)
        fresh = d.count(aa) == 1 and b"XNUKRN1" in d
        print(f"read {reads}: changed {h[:12]} bytes={len(d)} AA13={d.count(aa)} "
              f"XNUKRN1={d.count(b'XNUKRN1')} saved={p.name} fresh={fresh}", flush=True)
        if fresh:
            print(f"ACCEPTED {p}", flush=True)
            return 0
        time.sleep(a.interval)
    print("DEADLINE no accepted ring", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
