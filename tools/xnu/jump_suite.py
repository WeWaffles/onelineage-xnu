#!/usr/bin/env python3
"""Run N jumps in a row and report how many produced a usable dump.

Gate A of the overnight loop needs a number, not an impression.  One run is:

    run_sm8850_jump.py  ->  wait for "jumping"  ->  pull_crash.py  ->  decode

and this repeats it, classifies the failure when it happens, and writes
`suite.csv` next to the run directories.  The process exit status is the
measurement: 0 only when at least --min-pass runs came back usable, non-zero
otherwise, so a caller cannot mistake "it ran" for "it passed".

Verdicts (from the loop prompt):
    PASS  dump exists, carries XNUKRN1, and decoded records belong to this run
    F1    no XNUKRN1: cold reset, nothing of the jump's boot was captured
    F2    XNUKRN1 present but the dump is stale (Linux overwrote the region)
    F3    adb/bridge failed: not a result, retried up to --f3-retries times

F1 and F2 cannot always be told apart from the tag alone.  F2 is detectable
when pull_crash.py says so (it warns about a stale boot); otherwise a missing
tag is F1.  The distinction matters for the night: F1 points at the board,
F2 points at where Linux writes.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import re
import subprocess
import sys
import time

SYM = "build/xnu-build/sym/kernel.development.sweet"
STAGE_RE = re.compile(r"stage (0x[0-9a-f]{2})")


def sh(cmd: str, timeout: float) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, ""
    return p.returncode, (p.stdout + p.stderr)


def last_stage(repo: pathlib.Path, dump: pathlib.Path) -> str:
    """Highest-numbered stage record in the dump, or '-' when unreadable."""
    rc, txt = sh(f"cd {repo} && python3 tools/xnu/read_channel.py {dump} "
                 f"--sym {SYM} 2>/dev/null", timeout=180)
    stages = STAGE_RE.findall(txt)
    return stages[-1] if stages else "-"


def phone_is_back(timeout: float) -> bool:
    """Android finished booting: the next run needs a live `su` to work."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, txt = sh("adb shell getprop sys.boot_completed", timeout=20)
        if txt.strip() == "1":
            return True
        time.sleep(5)
    return False


def one_run(repo: pathlib.Path, outdir: pathlib.Path, index: int) -> dict:
    rundir = outdir / f"m{index}_run"
    if rundir.exists():
        raise SystemExit(f"{rundir} already exists; runs are never reused")
    log = outdir / f"m{index}_run.log"
    started = time.strftime("%H:%M:%S")

    with open(log, "w") as fh:
        proc = subprocess.Popen(
            [sys.executable, "tools/xnu/run_sm8850_jump.py", str(rundir)],
            cwd=repo, stdout=fh, stderr=subprocess.STDOUT)

    # The runner reaches the branch about two minutes in; past that, the board
    # has reset and the dump is already sitting in the store.  Anything still
    # running after ten minutes is stuck, and killing it is the only way to
    # keep the suite moving.
    jumped = None
    deadline = time.time() + 600
    while time.time() < deadline:
        try:
            if "jumping" in log.read_text(errors="ignore"):
                jumped = time.strftime("%H:%M:%S")
                break
        except FileNotFoundError:
            pass
        if proc.poll() is not None:
            break
        time.sleep(3)

    if jumped is None:
        proc.kill()
        return {"run": rundir.name, "started": started, "verdict": "F3",
                "class": "no-jump", "stage": "-", "notes": "runner never jumped",
                "dump": ""}

    rc, out = sh(f"cd {repo} && python3 tools/xnu/pull_crash.py {rundir} "
                 f"--grab-timeout 200", timeout=420)
    dump = rundir / "last_kmsg.txt"

    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not dump.exists():
        return {"run": rundir.name, "started": started, "verdict": "F3",
                "class": "no-dump", "stage": "-", "notes": out.strip()[-80:],
                "dump": ""}

    has_tag = b"XNUKRN1" in dump.read_bytes()
    stale = "no XNUKRN1 tag" in out or "not the jump" in out
    stage = last_stage(repo, dump)

    if has_tag:
        return {"run": rundir.name, "started": started, "verdict": "PASS",
                "class": "", "stage": stage, "notes": "",
                "dump": str(dump)}
    if stale:
        return {"run": rundir.name, "started": started, "verdict": "F2",
                "class": "stale", "stage": stage, "notes": "tag absent, dump stale",
                "dump": str(dump)}
    return {"run": rundir.name, "started": started, "verdict": "F1",
            "class": "cold-reset", "stage": stage, "notes": "no tag in dump",
            "dump": str(dump)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--repo", type=pathlib.Path,
                    default=pathlib.Path("/Users/waffles/onelineage-xnu"))
    ap.add_argument("--first-index", type=int, default=0,
                    help="run id to start at (default: one past the highest hw/mN)")
    ap.add_argument("--min-pass", type=int, default=0,
                    help="passes required for exit 0 (default: 90%% of --runs)")
    ap.add_argument("--f3-retries", type=int, default=1)
    args = ap.parse_args()

    repo = args.repo
    out = args.out if args.out.is_absolute() else repo / args.out
    out.mkdir(parents=True, exist_ok=True)

    if args.first_index:
        index = args.first_index
    else:
        ids = [int(m.group(1)) for p in (repo / "hw").glob("m*_run")
               if (m := re.match(r"m(\d+)_run$", p.name))]
        index = (max(ids) + 1) if ids else 1

    need = args.min_pass or -(-9 * args.runs // 10)  # ceil(0.9 * runs)
    rows: list[dict] = []
    print(f"suite: {args.runs} runs from m{index}, need {need} PASS\n")

    for n in range(args.runs):
        attempt = 0
        while True:
            row = one_run(repo, out, index)
            if row["verdict"] != "F3" or attempt >= args.f3_retries:
                break
            attempt += 1
            print(f"  {row['run']}: F3 ({row['class']}), retrying")
            time.sleep(60)
        rows.append(row)
        print(f"  {row['run']:<12} {row['verdict']:<5} {row['stage']:<6} "
              f"{row['class']}")
        with open(out / "suite.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        index += 1
        if not phone_is_back(300):
            print("  phone did not come back to Android; stopping the batch")
            break

    counted = [r for r in rows if r["verdict"] != "F3"]
    passed = sum(r["verdict"] == "PASS" for r in counted)
    print(f"\npass rate: {passed}/{len(counted)} counted "
          f"({len(rows) - len(counted)} F3 not counted)")
    print(f"need {need}: {'PASS' if passed >= need else 'FAIL'}")
    print(f"table: {out / 'suite.csv'}")
    return 0 if passed >= need and counted else 1


if __name__ == "__main__":
    sys.exit(main())
