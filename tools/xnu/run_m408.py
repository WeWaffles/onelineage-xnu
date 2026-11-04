#!/usr/bin/env python3
"""m408: one bounded RAM-only jump, read through the validated ring channel.

m407 proved XNUPT01 written at 0x8883F0068 (the XNUJMP5 slot) is present in the
next boot's /proc/last_kmsg. So the first dump after the device returns is the
jumped boot's ring, and the markers that matter there are XNUJMP3/4 (module)
and XNUJMP2/5 (stub).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("h", REPO / "tools/xnu/run_sm8850_jump.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

out = REPO / "hw/m408"
out.mkdir(parents=True, exist_ok=True)

print("[1] harness (normal jump)", flush=True)
t0 = time.time()
p = subprocess.run([sys.executable, str(REPO / "tools/xnu/run_sm8850_jump.py"), str(out)],
                   capture_output=True, text=True, timeout=200)
print("    rc=%d in %.1fs" % (p.returncode, time.time() - t0), flush=True)
print("    " + (p.stdout or "").strip().splitlines()[-3:].__str__()[:300], flush=True)

print("[2] first dump after the device returns", flush=True)
data = b""
first = None
for i in range(40):
    try:
        r = subprocess.run(["adb", "exec-out", "su", "0", "sh", "-c", "cat /proc/last_kmsg"],
                           capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        r = None
    if r and len(r.stdout) > 1024:
        data = r.stdout
        first = i
        break
    time.sleep(2)
(out / "last_kmsg_first.txt").write_bytes(data)

tags = ("XNUJMP1", "XNUJMP2", "XNUJMP3", "XNUJMP4", "XNUJMP5", "XNUJMP6",
        "XNUKRN1", "XNUPT01", "olxnu", "OLXNU")
counts = {t: data.count(t.encode()) for t in tags}
reached = [t for t in ("XNUJMP3", "XNUJMP4", "XNUJMP2", "XNUJMP5", "XNUJMP6", "XNUKRN1") if counts[t]]
print("[3] dump %d bytes (attempt %s) %s" % (len(data), first, counts), flush=True)
print("[4] MARKERS PRESENT:", reached or "none", flush=True)

pathlib.Path("RUNLOG.md").write_text(pathlib.Path("RUNLOG.md").read_text() + f"""
### m408: first bounded jump read through the validated ring channel (2026-11-04)

m407 proved the channel by writing `XNUPT01` at `0x8883F0068` (the `XNUJMP5` slot) and finding it in the next boot's
`last_kmsg` (count 2). m408 uses that channel for a real jump, taking the **first** dump after the device returns so
the jumped boot's ring is what gets read.

    harness rc              : {p.returncode} ({time.time()-t0:.1f}s)
    first post-reset dump   : {len(data)} bytes (attempt index {first})
    counts                  : {counts}
    markers present         : {', '.join(reached) if reached else 'none'}
""")
json.dump({"rc": p.returncode, "size": len(data), "counts": counts, "reached": reached},
          open("/tmp/m408.json", "w"), indent=2)
print("[5] recorded", flush=True)
