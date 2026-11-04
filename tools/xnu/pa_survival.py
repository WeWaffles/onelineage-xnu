#!/usr/bin/env python3
"""Does a physical store survive a reboot, read back with peek (not via last_kmsg)?

Phase A: load the module, poke XNUPT01 at the sec_pmsg marker PA, reboot.
Phase B: insmod again in the new boot and `cat peek` that PA.

Right sysfs name matters: insmod proc_name=olxnu_jump2 only names the proc
entry; the module's sysfs directory is the .ko name, olxnu_jump2_mod.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("h", REPO / "tools/xnu/run_sm8850_jump.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

SEC_PMSG = 0x888A00000
out = REPO / "hw/m405_peek"
out.mkdir(parents=True, exist_ok=True)
res = {}

p = subprocess.run([sys.executable, str(REPO / "tools/xnu/run_sm8850_jump.py"),
                    str(out), "--load-only"], capture_output=True, text=True, timeout=220)
print("[A1] harness rc=%d" % p.returncode, flush=True)

log = (out / "driver.log").read_text() if (out / "driver.log").exists() else ""
m = re.search(r"base=(0x[0-9a-f]+) entry=(0x[0-9a-f]+) ba=(0x[0-9a-f]+) fb=(0x[0-9a-f]+) fb_size=(0x[0-9a-f]+) size=(0x[0-9a-f]+)", log)
params = ""
if m:
    base, entry, ba, fb, fbs, size = m.groups()
    params = (f"proc_name=olxnu_jump2 payload_pa={base} payload_size={size} "
              f"entry_pa={entry} boot_args_pa={ba} fb_pa={fb} fb_size={fbs}")
    res["params"] = params
print("[A2] params %r" % (params[:90] + "..."), flush=True)

for path in ("/sys/module/olxnu_jump2_mod/parameters/probe_pa",
             "/sys/module/olxnu_jump2/parameters/probe_pa"):
    rc, txt = h.adb(f"echo {SEC_PMSG} > {path}")
    print("[A3] set %s rc=%d %r" % (path, rc, txt[:60]), flush=True)
    if rc == 0:
        res["sysfs_path"] = path
        break

rc, txt = h.adb("echo poke > /proc/olxnu_jump2/jump")
print("[A4] poke rc=%d %r" % (rc, txt[:60]), flush=True)
rc, txt = h.adb("dmesg | grep poke")
(out / "dmesg_poke.txt").write_text(txt + "\n")
print("[A5] dmesg poke: %r" % txt[:160], flush=True)
res["poke_logged"] = "wrote" in txt

h.sh("adb reboot", timeout=30)
deadline = time.time() + 200
while time.time() < deadline:
    if h.adb("true", timeout=15)[0] == 0:
        break
    time.sleep(2)
print("[B1] back; loading module directly (no harness reboot)", flush=True)
time.sleep(5)

rc, txt = h.adb(f"insmod /data/local/tmp/olxnu/olxnu_jump2_mod_v20.ko {params} probe_pa=0x{SEC_PMSG:x}")
print("[B2] insmod rc=%d %r" % (rc, txt[:120]), flush=True)
res["insmod_rc"] = rc

rc, txt = h.adb("cat /proc/olxnu_jump2/peek")
(out / "peek.txt").write_text(txt + "\n")
print("[B3] peek rc=%d %r" % (rc, txt[:200]), flush=True)
res["peek"] = txt[:200]
res["marker_survived"] = "XNUPT01" in txt

pathlib.Path("/tmp/m405.json").write_text(json.dumps(res, indent=2))
print("[B4] VERDICT:", "PA store SURVIVED reboot" if res["marker_survived"]
      else "PA store did NOT survive reboot (or poke never wrote)", flush=True)
