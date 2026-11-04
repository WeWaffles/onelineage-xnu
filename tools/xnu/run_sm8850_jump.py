#!/usr/bin/env python3
"""Drive one SM8850 XNU run from the host, recording each step's output.

Sequence: reboot -> wait for su -> owned window -> build image for that base
-> stream it -> load the jump module -> dump the prepared stub -> jump
-> wait for the reset -> pull last_kmsg.

Everything lands in the output directory so a run can be read back later.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import struct
import subprocess
import sys
import time

# The payload base is a precondition, not a preference.  Every run whose CMA
# allocation landed at 0xb7404000 (the aligned base + 0x4000) produced no
# records at all -- m306, m307, m311, m313, m314, m317, m318, m323 -- while 8 of
# 9 runs at 0xb7400000 did (RUNLOG.md, 2026-11-03).  Spending a jump on a shifted
# window measures nothing, so refuse unless the caller says otherwise.
EXPECTED_BASE = 0xB7400000
REGION_LO = 0xB7400000
REGION_HI = 0xBC000000


def sh(cmd: str, timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, ""
    return p.returncode, (p.stdout + p.stderr).strip()


def adb(cmd: str, timeout: int = 120) -> tuple[int, str]:
    """Run a command as root on the device (cmd must not contain double quotes)."""
    assert '"' not in cmd, cmd
    return sh("adb shell 'su 0 sh -c \"" + cmd + "\"'", timeout=timeout)


def wait_for_su(deadline: float) -> bool:
    while time.time() < deadline:
        rc, _ = adb("true", timeout=20)
        if rc == 0:
            return True
        time.sleep(1)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--repo", type=pathlib.Path,
                    default=pathlib.Path("/Users/waffles/onelineage-xnu"))
    ap.add_argument("--allow-any-base", action="store_true",
                    help="jump even if the payload base is not 2 MB aligned")
    args = ap.parse_args()

    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)
    repo = args.repo
    log = []

    def note(msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        print(line, flush=True)
        log.append(line)

    note("rebooting")
    sh("adb reboot", timeout=30)
    time.sleep(20)
    sh("adb wait-for-device", timeout=180)

    #
    # KernelSU's su only becomes reachable once the boot finishes (ksud sets it
    # up from post-fs-data), and on this board that is roughly two minutes after
    # adb answers.  Waiting a flat 120s from `adb reboot` was not enough: the
    # m124_run attempt gave up while the phone was still booting.
    #
    deadline = time.time() + 300
    while time.time() < deadline:
        rc, txt = sh("adb shell getprop sys.boot_completed", timeout=20)
        if txt.strip() == "1":
            break
        time.sleep(5)

    if not wait_for_su(time.time() + 180):
        note("su never became available")
        (out / "driver.log").write_text("\n".join(log) + "\n")
        return 1
    note("su available")

    #
    # Keep the panel awake for the run.
    #
    # hw/m241..m255 print characters (the counter climbs every run, and the
    # glyph stores complete) but nothing has ever appeared on the phone, and
    # the two description that fits every run is a screen that is not lit:
    # hw/m238 showed probe colours while the phone was still awake, and later
    # runs were described as "the frozen Android screen, then blank" - a
    # display that has stopped being refreshed and then gone to sleep scans
    # nothing, so repointing the SMMU at our buffer cannot show up on it.
    #
    # stayon plus a long screen-off timeout keeps it lit through the jump.
    #
    for cmd, what in (
        ("input keyevent KEYCODE_WAKEUP", "wake"),
        ("wm dismiss-keyguard", "unlock"),
        ("svc power stayon true", "stayon"),
        ("settings put system screen_off_timeout 1800000", "timeout"),
    ):
        rc, txt = adb(cmd)
        note(f"display {what} rc={rc} {txt.strip()[:80]}")

    rc, txt = adb(
        "dumpsys power | grep -E 'mWakefulness=|Display Power'")
    note(f"display state: {txt.strip().replace(chr(10), ' | ')}")

    rc, txt = adb(
        "insmod /data/local/tmp/olxnu/olxnu_payload2_mod_v21.ko "
        "proc_name=olxnu_payload2 payload_size_mb=128 target_pa=0xAE0000000 "
        "auto_base=1")
    note(f"payload insmod rc={rc} {txt}")
    time.sleep(1)
    rc, info = adb("cat /proc/olxnu_payload2/info")
    (out / "payload_info.txt").write_text(info + "\n")
    note("payload info:\n" + info)

    m = re.search(r"^payload_pa=(0x[0-9a-f]+)", info, re.M)
    if not m:
        note("no payload_pa")
        (out / "driver.log").write_text("\n".join(log) + "\n")
        return 1
    base = int(m.group(1), 16)

    #
    # Alignment is the precondition, not the exact address.  Every run whose
    # window started 0x4000 into a 2 MB block produced no records (8 of 8),
    # while aligned runs worked -- but the image builder takes --phys-base and
    # derives boot_args, entry, framebuffer and the ADT from it (checked below
    # at "payload phys_base"), so any aligned address is self-consistent.
    # olxnu_payload2_mod_v21 shifts its block up to a 2 MB boundary, which is
    # what makes this hold for whatever CMA hands back.
    #
    #
    # Region as well as alignment.  hw/m327 fell back to alloc_contig_range()
    # and handed back 0xabd000000 -- aligned, but nowhere near the CMA area the
    # working runs use -- and in that window the evidence ring never formed at
    # all (no OLXNSS01 tag), so the jump answered nothing while still costing
    # one.  The window has only ever worked inside these bounds.
    #
    aligned = not (base & ((2 << 20) - 1))
    in_region = REGION_LO <= base < REGION_HI
    from_cma = "alloc_method=cma_alloc" in info
    if not (aligned and in_region and from_cma):
        if not args.allow_any_base:
            note(f"ERROR: payload base {base:#x} is not usable "
                 f"(aligned={aligned}, in_region={in_region}, cma={from_cma}); "
                 f"rerun, or pass --allow-any-base")
            (out / "driver.log").write_text("\n".join(log) + "\n")
            return 1
        note(f"WARNING: payload base {base:#x} is not the usual window "
             f"(aligned={aligned}, in_region={in_region}, cma={from_cma}); "
             f"continuing because --allow-any-base")
    elif base != EXPECTED_BASE:
        note(f"NOTE: payload base {base:#x} is aligned and differs from the "
             f"historical {EXPECTED_BASE:#x}; every address derives from it")

    #
    # Publish the kernel that was just built.
    #
    # `make` writes BUILD/obj/DEVELOPMENT_ARM64_SWEET/, but the payload is built
    # from build/xnu-build/sym/, and nothing used to copy between them: hw/m158
    # ran a kernel an hour older than the source being measured, which showed up
    # as "the new stamps never appear".  Copy here, so a run always measures what
    # was compiled, and fail loudly if the build output is missing.
    built = repo / "build/xnu-src/source/BUILD/obj/DEVELOPMENT_ARM64_SWEET"
    for src, dst in ((built / "kernel.development.sweet",
                      repo / "build/xnu-build/sym/kernel.development.sweet"),
                     (built / "kernel.development.sweet.dSYM",
                      repo / "build/xnu-build/sym/kernel.development.sweet.dSYM")):
        if not src.exists():
            note(f"ERROR: missing build output {src}")
            (out / "driver.log").write_text("\n".join(log) + "\n")
            return 1
        rc, txt = sh(f"rm -rf '{dst}' && cp -R '{src}' '{dst}'", timeout=180)
        if rc:
            note(f"ERROR: publishing {src.name}: {txt}")
            (out / "driver.log").write_text("\n".join(log) + "\n")
            return 1
    note(f"published kernel {time.strftime('%H:%M:%S', time.localtime((built / 'kernel.development.sweet').stat().st_mtime))}")

    note("building image")
    for cmd in (
        f"python3 tools/xnu/mk_sm8850_adt.py build/sm8850_xnu_v22.adt "
        f"--ramdisk build/sweet_init_v26.macho --phys-base 0x{base:x} "
        f"--mem-size 0x8000000",
        f"python3 tools/xnu/build_payload.py "
        f"build/xnu-build/sym/kernel.development.sweet "
        f"build/sm8850_xnu_v22.adt build/sweet_sm8850_v22.bin --target phone "
        f"--cmdline 'debug=0xc serial=3 cpus=1 keepsyms=1 rd=md0 "
        f"cs_enforcement_disable=1'",
        f"python3 tools/xnu/build_sm8850_image.py build/sweet_sm8850_v22.bin "
        f"build/sm8850_image_v22.bin --ramdisk build/sweet_init_v26.macho",
    ):
        rc, txt = sh(f"cd {repo} && {cmd}", timeout=300)
        if rc:
            note(f"build failed: {cmd}\n{txt}")
            (out / "driver.log").write_text("\n".join(log) + "\n")
            return 1

    # Derive the jump parameters from the payload itself: the kernel's entry
    # (and boot_args placement) move whenever the kernel is rebuilt, so they
    # must never be hardcoded here.
    image = repo / "build/sm8850_image_v22.bin"
    blob = image.read_bytes()
    payload = (repo / "build/sweet_sm8850_v22.bin").read_bytes()
    virt_base, entry_va, _adt_off, adt_size, kernel_end, pbase, _mem = \
        struct.unpack_from("<7Q", payload, 0x10)
    if pbase != base:
        note(f"ERROR: payload phys_base 0x{pbase:x} != window 0x{base:x}")
        (out / "driver.log").write_text("\n".join(log) + "\n")
        return 1
    adt_off = kernel_end - virt_base
    ba = pbase + ((adt_off + adt_size + 0x3FFF) & ~0x3FFF)
    entry = pbase + (entry_va - virt_base)
    #
    # The framebuffer sits right past the image, not at +48 MB: the panel's
    # geometry (1472x3120 at 5888) needs 18.4 MB, which does not fit after 48 MB
    # in a 64 MB window.  Must match mk_sm8850_adt.py and build_sm8850_image.py.
    fb = pbase + 0x2000000
    fb_size = 5888 * 3120
    size = len(blob)

    # Skip leading all-zero pages so dd only moves real data.
    first_data = 0
    while first_data * 4096 < size and not any(
            blob[first_data * 4096:(first_data + 1) * 4096]):
        first_data += 1

    note(f"base=0x{base:x} entry=0x{entry:x} ba=0x{ba:x} fb=0x{fb:x} "
         f"fb_size=0x{fb_size:x} size=0x{size:x} skip={first_data}")

    rc, txt = sh(f"adb push {image} /data/local/tmp/olxnu/", timeout=180)
    note(f"push rc={rc}")

    rc, txt = adb(f"dd if=/data/local/tmp/olxnu/sm8850_image_v22.bin "
                  f"of=/proc/olxnu_payload2/data bs=4096 "
                  f"skip={first_data} seek={first_data} 2>&1 | tail -1")
    note(f"dd rc={rc} {txt[-200:]}")

    rc, txt = adb(                f"insmod /data/local/tmp/olxnu/olxnu_jump2_mod_v20.ko "
        f"proc_name=olxnu_jump2 payload_pa=0x{base:x} payload_size=0x{size:x} "
        f"entry_pa=0x{entry:x} boot_args_pa=0x{ba:x} fb_pa=0x{fb:x} "
        f"fb_size=0x{fb_size:x}")
    note(f"jump insmod rc={rc} {txt}")

    rc, txt = adb("cat /proc/olxnu_jump2/stub")
    (out / "stub_before.txt").write_text(txt + "\n")
    note("stub pre-check:\n" + txt)

    rc, txt = adb("dmesg | grep OLXNU-STUB; dmesg | grep OLXNU-IDMAP")
    (out / "dmesg_before_jump.txt").write_text(txt + "\n")
    note("dmesg:\n" + txt)

    #
    # Leave the APSS watchdog armed.
    #
    # The jump module pets it once, which is one bark period: measured at
    # hw/m179, a jump at 03:54:45 and a reset at 03:55:03 — eighteen seconds,
    # which was the whole budget the kernel had.  Disabling it instead
    # (/sys/bus/platform/devices/17600000.qcom,wdt/disable really does disarm
    # the hardware: hw/m180 ran past two minutes without a reset) leaves no way
    # to end a stuck run, and a stuck run is the only way to get its log.
    #
    # So it stays armed, and the kernel pets it from sweet_early_evidence():
    # progress buys time, a stop is reset by the hardware, and the frontier
    # survives in the log either way.
    _, txt2 = adb("cat /sys/bus/platform/devices/17600000.qcom,wdt/disable")
    note(f"WDT disable state {txt2.strip()!r} (0 = armed, pet by the kernel)")
    if txt2.strip() != "0":
        #
        # Never jump with the watchdog disarmed.  hw/m180 did exactly that as an
        # experiment to measure the window, ran past two minutes without a
        # reset, and left the board parked in a hung XNU with adbd gone: no
        # log, and no way to reset it from the host, because the only thing
        # that can still reset this board is the watchdog we just turned off.
        # Recovery needs a physical power + volume-down press.
        adb("echo 0 > /sys/bus/platform/devices/17600000.qcom,wdt/disable")
        _, again = adb("cat /sys/bus/platform/devices/17600000.qcom,wdt/disable")
        note(f"WDT re-arm attempted, state now {again.strip()!r}")
        if again.strip() != "0":
            note("ERROR: watchdog is disarmed and would not re-arm - refusing to "
                 "jump, because a hung run could not be reset")
            (out / "driver.log").write_text("\n".join(log) + "\n")
            return 1

    #
    # Deliberately NOT pinned to a CPU.
    #
    # Pinning the jump to core 0 (taskset 1) was tried to make the CPU-affinity
    # panic reproducible-free: the ADT's topology holds one CPU with affinity 0,
    # so only a jump from core 0 matched (hw/m99, m101, m106, m109, m110 panicked;
    # hw/m102, m104, m112 ran on).
    #
    # It made things worse, not better: five consecutive pinned attempts
    # (hw/m115..m117) all died in the stub's M=0 -> M=1 -> M=0 transition, with
    # no XNUJMP5, while unpinned runs land about half the time.  Whatever that
    # toggle depends on is disturbed by running the whole handoff on core 0, and
    # the affinity panic is the cheaper problem of the two.
    #
    # The real fix for the affinity panic is to give the topology every core
    # (cpus=8 with a single state=running node, or patching the ADT at jump time
    # with the MPIDR the stub actually sees), not to constrain the core.
    note("jumping")
    rc, txt = adb("echo go > /proc/olxnu_jump2/jump")
    note(f"go rc={rc} {txt}")

    (out / "driver.log").write_text("\n".join(log) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
