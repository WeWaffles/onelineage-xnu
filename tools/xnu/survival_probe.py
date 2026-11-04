#!/usr/bin/env python3
"""Prove whether the post-reset evidence channel works, without jumping.

The module offers two no-jump marker writes:

  echo mark > /proc/.../jump   -> "XNUJMP1" at 0x888900000 + 0x100000 (sec_pmsg)
  echo poke > /proc/.../jump   -> "XNUPT01" at probe_pa (settable via sysfs)

Both are plain physical stores, which is what the stub's own markers are
(XNUJMP2 at 0x8883F0028, XNUJMP5 at 0x8883F0068).  So writing them, rebooting,
and grepping the next boot's /proc/last_kmsg measures the channel itself:
if XNUJMP1/XNUPT01 survive, their absence after a real jump means something
about the jump; if they do not survive, no jump marker was ever readable.
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

out = REPO / "hw/m404_mark"
out.mkdir(parents=True, exist_ok=True)
result = {}

print("[1] load-only run (reboots, insmods, never jumps)", flush=True)
p = subprocess.run([sys.executable, str(REPO / "tools/xnu/run_sm8850_jump.py"),
                    str(out), "--load-only"], capture_output=True, text=True, timeout=200)
print("    harness rc=%d" % p.returncode, flush=True)
result["load_rc"] = p.returncode

rc, txt = h.adb("ls /proc/olxnu_jump2/")
print("[2] proc dir rc=%d %r" % (rc, txt[:80]), flush=True)
result["proc"] = txt[:200]

rc, txt = h.adb("echo mark > /proc/olxnu_jump2/jump")
print("[3] mark rc=%d %r" % (rc, txt[:80]), flush=True)

rc, txt = h.adb("echo 0x8883f0068 > /sys/module/olxnu_jump2/parameters/probe_pa")
print("[4] set probe_pa rc=%d %r" % (rc, txt[:80]), flush=True)

rc, txt = h.adb("cat /sys/module/olxnu_jump2/parameters/probe_pa")
print("    probe_pa now %r" % txt.strip(), flush=True)
result["probe_pa"] = txt.strip()

rc, txt = h.adb("echo poke > /proc/olxnu_jump2/jump")
print("[5] poke rc=%d %r" % (rc, txt[:80]), flush=True)

rc, txt = h.adb("dmesg | grep -e sec_pmsg -e 'poke: wrote' -e sec_pmsg")
(out / "dmesg_markers.txt").write_text(txt + "\n")
print("[6] dmesg:\n" + txt, flush=True)
result["dmesg_has_sec_pmsg"] = "sec_pmsg" in txt
result["dmesg_has_poke"] = "poke: wrote" in txt

h.sh("adb reboot", timeout=30)
deadline = time.time() + 200
while time.time() < deadline:
    r = h.adb("true", timeout=15)
    if r[0] == 0:
        break
    time.sleep(2)
print("[7] device back, pulling last_kmsg", flush=True)

data = b""
for _ in range(90):
    try:
        r = subprocess.run(["adb", "exec-out", "su", "0", "sh", "-c", "cat /proc/last_kmsg"],
                           capture_output=True, timeout=40)
    except subprocess.TimeoutExpired:
        r = None
    if r and len(r.stdout) > 1024:
        data = r.stdout
        break
    time.sleep(2)

(out / "last_kmsg.txt").write_bytes(data)
counts = {t: data.count(t.encode()) for t in
          ("XNUJMP1", "XNUPT01", "XNUJMP3", "XNUJMP5", "XNUKRN1", "sec_pmsg", "poke: wrote")}
result["bytes"] = len(data)
result["counts"] = counts
result["head"] = data[:40].decode("latin-1")
print("[8] dump %d bytes %s head=%r" % (len(data), counts, result["head"]), flush=True)

pathlib.Path("/tmp/m404_result.json").write_text(json.dumps(result, indent=2))
print("[9] veredict:",
      "channel WORKS (marker survived)" if counts["XNUJMP1"] or counts["XNUPT01"]
      else "channel DEAD (no PA marker survived this reboot)", flush=True)
