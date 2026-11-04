#!/usr/bin/env bash
# One reproducible m468 attempt: preflight, prearmed capture with a post-jump
# quiet period, one bounded jump, then classify/decode.  Touches hardware only
# if every preflight passes, and never polls adb during the jump window.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
OUT="${1:-hw/m468}"
CAPTURE_TIMEOUT="${CAPTURE_TIMEOUT:-200}"
POST_JUMP_DELAY="${POST_JUMP_DELAY:-60}"
HARNESS_TIMEOUT="${HARNESS_TIMEOUT:-120}"
LOG=/tmp/m468_drv.log
CAP=/tmp/m468_cap.log

echo "[1/5] preflight (bounded)"
python3 - "$CAPTURE_TIMEOUT" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("rj", "tools/xnu/run_sm8850_jump.py")
rj = importlib.util.module_from_spec(spec); spec.loader.exec_module(rj)
idx = subprocess.run(["timeout", "8", "adb", "devices"], capture_output=True, text=True)
if not any(l.endswith("device") for l in idx.stdout.splitlines()):
    print("PREFLIGHT_FAIL no adb device on the USB bus"); sys.exit(10)
rc, txt = rj.adb("cat /proc/modules | grep -ci olxnu", timeout=15)
n = (txt or "").strip().splitlines()[-1:] or ["?"]
if n[0].strip() not in ("0", ""):
    rj.adb("rmmod olxnu_payload2_mod_v21", timeout=20)
    rc, txt = rj.adb("cat /proc/modules | grep -ci olxnu", timeout=15)
    n = (txt or "").strip().splitlines()[-1:] or ["?"]
    if n[0].strip() not in ("0", ""):
        print("PREFLIGHT_FAIL payload module stuck (needs a device reboot)"); sys.exit(11)
rc, base = rj.adb("cat /proc/last_kmsg | wc -c", timeout=20)
print("baseline_bytes:", (base or "").strip().splitlines()[-1:] or ["?"])
PY
if [ $? -ne 0 ]; then echo "OUTCOME=NO_RUN preflight_failed"; exit 0; fi

echo "[2/5] arm capture (quiet ${POST_JUMP_DELAY}s after the jump line, window ${CAPTURE_TIMEOUT}s)"
rm -rf "$OUT"; mkdir -p "$OUT"; : > "$LOG"
python3 tools/xnu/capture_ring.py "$OUT" --arm-file "$LOG" --arm-text jumping \
  --timeout "$CAPTURE_TIMEOUT" --interval 2.0 --min-bytes 1000000 \
  --post-jump-delay "$POST_JUMP_DELAY" > "$CAP" 2>&1 &
CP=$!
sleep 2

echo "[3/5] one jump attempt (bounded ${HARNESS_TIMEOUT}s)"
python3 - "$LOG" "$OUT" "$HARNESS_TIMEOUT" <<'PY'
import importlib.util, os, signal, subprocess, sys
log, out, h_t = sys.argv[1], sys.argv[2], float(sys.argv[3])
spec = importlib.util.spec_from_file_location("rj", "tools/xnu/run_sm8850_jump.py")
rj = importlib.util.module_from_spec(spec); spec.loader.exec_module(rj)
rj.adb("rmmod olxnu_payload2_mod_v21", timeout=20)
with open(log, "w") as f:
    # Own session: on timeout, kill the whole group.  Killing only the harness
    # leaves its adb children polling the device while capture is reading the
    # ring -- the contention that hung m468 at 95 s.
    p = subprocess.Popen([sys.executable, "tools/xnu/run_sm8850_jump.py", out,
                          "--module", "olxnu_jump2_mod_v21.ko"],
                         stdout=f, stderr=subprocess.STDOUT,
                         start_new_session=True)
    try:
        p.wait(timeout=h_t)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        print("harness timed out; process group killed")
PY

echo "[4/5] wait for capture"
if grep -q "jumping" "$LOG" 2>/dev/null; then
  wait $CP; echo "capture_rc=$?"
else
  # No jump line means no ring can be evidence; do not sit out the whole
  # capture window waiting for a buffer that cannot be attributed to a jump.
  kill "$CP" 2>/dev/null
  wait "$CP" 2>/dev/null
  echo "capture stopped early: no jump line was written"
fi

echo "[5/5] classify and decode"
python3 tools/xnu/decode_probe.py --ring-dir "$OUT" --jump-log "$LOG" --capture-log "$CAP"
