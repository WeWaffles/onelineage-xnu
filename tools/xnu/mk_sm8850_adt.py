#!/usr/bin/env python3
"""Generate an SM8850 (the arm64 target / canoe) ADT for physical XNU boot.

Physical constants:
  GIC: GICD=0x17000000 GICR=0x17080000 (from sm8850_device.dts)
  Timer: 19.2 MHz = 19200000 Hz (arm,armv8-timer, fdt confirmed)
  Payload PA: 0x8c0000000 (olxnu_payload.ko linear-map allocation)
  Memory size: 0x10000000 (256 MB — enough for XNU boot, avoids reserved sub-regions)

The ramdisk is placed at phys_base + 0x800000 (8 MB into the window), inside the
empty 16 MB __PAGEZERO hole at the bottom of the payload image.  Its physical
address is stored in the ADT RAMDisk property so XNU can find /dev/md0.
"""
from __future__ import annotations

import argparse
import os
import hashlib
import json
from pathlib import Path
import struct

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
import adt

U32 = lambda *values: struct.pack("<%dI" % len(values), *values)
U64 = lambda *values: struct.pack("<%dQ" % len(values), *values)
CSTR = lambda value: value.encode("ascii") + b"\0"

# ── SM8850 physical constants ────────────────────────────────────────────────
SM8850_GICD_PA    = 0x17000000
SM8850_GICR_PA    = 0x17080000
SM8850_GICD_SIZE  = 0x10000
SM8850_GICR_SIZE  = 0x200000
SM8850_TIMER_HZ   = 19200000  # 19.2 MHz physical timer

# Payload PA — high end of System RAM 9.25 GB block (0x8c0000000-0xaffffffff).
# 0xAFC000000 is 64 MB before the end: only user-mode anonymous pages live here,
# not kernel code or module text.  Load both modules BEFORE writing so their
# physical pages are allocated in the lower portion of the block.
# Jump immediately after the write so Android has no time to panic.
PHYS_BASE         = 0xAE0000000  # safe: within 9FF000000-AEAB0DFFF non-reserved gap
MEMORY_SIZE       = 0x4000000   # 64 MB — ends at 0xAE4000000, well inside safe zone

# Ramdisk within the window, after the kernel virtual span + margin
# 8 MB from PHYS_BASE: inside the 16 MB __PAGEZERO hole at the bottom of the
# payload image, which is empty, and inside the part of the window that is known
# to take the streamed image (hw/m192: the ramdisk at the old 36 MB offset read
# back as stale DRAM, not the Mach-O).
RAMDISK_PA_OFFSET = 0x800000
RAMDISK_PA        = PHYS_BASE + RAMDISK_PA_OFFSET

# Framebuffer: put it in our RAM region (XNU writes framebuffer here at boot)
# We use a VA of virt_base + fb_offset; build_sm8850_payload.py computes the VA.
#
# These are the *panel's* numbers, not the old Redmi ones: 1472x3120 at a 5888
# byte pitch (XNU_PROGRESS.md, M18).  5888 * 3120 = 18,370,560 bytes, so the area
# is 18.4 MB and has to start right after the 32 MB image rather than at 48 MB.
#
# 1472x3120 at 5888 and 3120x1472 at 12480 are the same 18,370,560 bytes, and
# hw/m270 (drawn at the former) and hw/m272 (drawn at the latter) produced the
# same uniform vertical bars - a pitch mismatch aliases the same way in both
# directions, so the panels do not say which pitch is real (M23).  This stays at
# the spelling that printed 3,816 characters in hw/m265 until a band test at
# byte offsets 0x1700 and 0x30C0 measures it.
FB_W, FB_H = 1472, 3120
FB_DEPTH = int(os.environ.get("OLXNU_FB_DEPTH", "32"))
if FB_DEPTH not in (16, 32):
    raise SystemExit("OLXNU_FB_DEPTH must be 16 or 32")
FB_STRIDE = FB_W * (FB_DEPTH // 8)
# Using a plain RAM address just past the image (0x1FF0000) so writes land in
# memory that is ours, and 2 MB aligned so SMMU block descriptors stay legal.
FB_PA      = PHYS_BASE + 0x2400000  # 32 MB from PHYS_BASE (ends at +52 MB)


def make_node(name: str, props=(), children=()) -> adt.Node:
    return adt.Node([("name", 0, CSTR(name)), *[(k, 0, v) for k, v in props]], list(children))


def build_sm8850(ramdisk_size: int = 0) -> adt.Node:
    phandles = iter(range(1, 256))
    ph = lambda: ("AAPL,phandle", U32(next(phandles)))
    seed = hashlib.sha512(b"sm8850-physical-xnu").digest()

    # /chosen — tells XNU where DRAM is
    memmap_props: list = [ph()]
    if ramdisk_size > 0:
        memmap_props.append(("RAMDisk", U64(RAMDISK_PA, ramdisk_size)))

    chosen = make_node("chosen", [
        ph(),
        ("dram-base", U64(PHYS_BASE)),
        ("dram-size", U64(MEMORY_SIZE)),
        ("random-seed", seed),
        ("debug-enabled", U32(1)),
        ("firmware-version", CSTR("OneLineage-sm8850-phys")),
        ("system-firmware-version", CSTR("OneLineage-sm8850-phys")),
        ("source-device", CSTR("vendor,e3q")),
    ], [make_node("memory-map", memmap_props)])

    #
    # cpus — the real SM8850 affinities, not just cpu0.
    #
    # ml_parse_cpu_topology() takes each CPU's ``phys_id`` from this node's
    # ``reg`` property, and ml_get_cpu_number() masks MPIDR to AFF0|AFF1 and
    # scans for a match.  A topology holding only ``cpu0`` (reg 0) therefore
    # matches only when the jump executes on the core whose affinity is 0, and
    # Linux schedules the shell that writes ``go`` on any of the eight cores.
    #
    # When the lookup misses, ml_get_cpu_number() returns -1,
    # ml_get_cpu_number_local() stores that into an *unsigned* and asserts
    #
    #   machine_routines.c:1228 Assertion failed:
    #     cpu_id <= (unsigned int)ml_get_max_cpu_number()
    #
    # which is the panic hw/m109_run finally printed, and the reason identical
    # kernels appeared to stop at different stages (hw/m99, m101, m106, m109,
    # m110 panicked there; hw/m102, m104, m112 jumped from core 0 and ran on).
    #
    # Values come from kernel/device-hardware/generic-arm64.json
    # (cpu.mpidr_affinities).  XNU identifies a CPU by AFF0|AFF1 only, so the
    # two cores in the second cluster (0x10000, 0x10100) collapse onto the
    # first two — that is upstream behaviour, and harmless here because boot
    # args still say cpus=1.
    #
    # Exactly ONE node may say ``state = "running"``.  ml_parse_cpu_topology()
    # treats that property as "this is the boot CPU" (ml_is_boot_cpu() only
    # compares it against the string, never against MPIDR) and asserts that the
    # boot CPU has not been seen yet:
    #
    #   machine_routines.c:1087  assert(topology_info.boot_cpu == NULL);
    #
    # so marking two nodes running panics, and marking none leaves
    # topology_info.boot_cpu NULL (asserted at 1117).  With every node running
    # and cpus=1, the first node was taken as the boot CPU and the loop then
    # broke — leaving a topology whose only entry is affinity 0 whatever core
    # the jump actually ran on.
    #
    # The jump is pinned to core 0 (run_sm8850_jump.py), so cpu0 is the honest
    # answer here.  A future real boot loader would mark whichever core it
    # entered on.
    #
    affinity = [0x00000, 0x00100, 0x00200, 0x00300,
                0x00400, 0x00500, 0x10000, 0x10100]
    cpu_nodes = []
    for cpu_id, mpidr in enumerate(affinity):
        cpu_nodes.append(make_node(f"cpu{cpu_id}", [
            ph(),
            ("device_type", CSTR("cpu")),
            ("compatible", CSTR("qcom,oryon") + CSTR("ARM,v9")),
            ("reg", U32(mpidr)),
            ("cpu-id", U32(cpu_id)),
            # SweetCPU::start matches on this and ml_parse_cpu_topology()'s
            # boot_cpu; without it no CPU platform driver claims the boot CPU,
            # so ml_set_max_cpus() is never called and ml_wait_max_cpus()
            # (kperf_init_early, startup.c) sleeps forever.
            ("logical-cpu-id", U32(cpu_id)),
            ("state", CSTR("running" if cpu_id == 0 else "halted")),
            ("timebase-frequency", U32(SM8850_TIMER_HZ)),
            ("fixed-frequency", U32(SM8850_TIMER_HZ)),
        ]))
    cpus = make_node("cpus", [ph(), ("#address-cells", U32(1)), ("#size-cells", U32(0))], cpu_nodes)

    # arm-io with GICv3
    # pe_fiq.c: ml_io_map(soc_base + reg[0], reg[1]) for GICD
    #           ml_io_map(soc_base + reg[2], reg[3]) for GICR
    # soc_base = ranges[1] = SM8850_GICD_PA
    GICD_OFF = 0
    GICR_OFF = SM8850_GICR_PA - SM8850_GICD_PA  # 0x80000
    gic = make_node("gic", [
        ph(),
        ("compatible", CSTR("arm,gic-v3")),
        ("interrupt-controller", b""),
        ("virtual-timer-intid", U32(27)),
        # The device tree on the phone publishes this; XNU's GICv3 walk has its
        # own default of 0x20000, and the two must agree or the walk leaves the
        # decoded window (SM8850 spaces redistributor frames 256K apart).
        ("redistributor-stride", U32(0x40000)),
        ("reg", U64(GICD_OFF, SM8850_GICD_SIZE, GICR_OFF, SM8850_GICR_SIZE)),
    ])
    arm_io = make_node("arm-io", [
        ph(),
        ("device_type", CSTR("onelineage-io")),
        ("compatible", CSTR("onelineage,sm8850-phys") + CSTR("arm-io")),
        ("#address-cells", U32(2)),
        ("#size-cells", U32(2)),
        # ranges[1] = gPESoCBasePhys = SM8850_GICD_PA; must be non-zero
        ("ranges", U64(0) + U64(SM8850_GICD_PA) + U64(0x1000000)),
    ], [gic, make_node("wdt", [ph(), ("no-pmu", U32(1))])])

    # Framebuffer node matching sweet_fbcon expected by XNU
    fb_size = FB_STRIDE * FB_H
    sweet_fbcon = make_node("sweet-fbcon", [
        ph(),
        ("reg", U64(FB_PA, fb_size)),
        ("width", U32(FB_W)),
        ("height", U32(FB_H)),
        ("stride", U32(FB_STRIDE)),
        ("depth", U32(FB_DEPTH)),
    ])

    defaults = make_node("defaults", [ph()])

    return make_node("device-tree", [
        ph(),
        ("model", CSTR("OneLineage SM8850 XNU physical")),
        # "xiaomi,sweet" must match: SweetPlatformExpert IONameMatch
        ("compatible", CSTR("xiaomi,sweet") + CSTR("vendor,e3q") + CSTR("qcom,sm8850") + CSTR("AppleARM")),
        ("#address-cells", U32(2)),
        ("#size-cells", U32(2)),
        ("platform-name", CSTR("OneLineage-sm8850-phys")),
        ("clock-frequency", U32(SM8850_TIMER_HZ)),
    ], [chosen, cpus, arm_io, sweet_fbcon, defaults])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=Path)
    ap.add_argument("--ramdisk", type=Path, default=None,
                    help="Raw init binary to embed as ramdisk")
    ap.add_argument("--phys-base", type=lambda v: int(v, 0), default=None,
                    help="Override PHYS_BASE — use the payload_pa reported by "
                         "/proc/olxnu_payload/info when the payload was allocated "
                         "by dma_alloc_coherent instead of the static window")
    ap.add_argument("--mem-size", type=lambda v: int(v, 0), default=None,
                    help="Override MEMORY_SIZE (default 64 MB)")
    args = ap.parse_args()

    global PHYS_BASE, MEMORY_SIZE, RAMDISK_PA, FB_PA
    if args.mem_size is not None:
        MEMORY_SIZE = args.mem_size
    if args.phys_base is not None:
        PHYS_BASE = args.phys_base
        RAMDISK_PA = PHYS_BASE + RAMDISK_PA_OFFSET
        FB_PA = PHYS_BASE + 0x2400000

    # The framebuffer sits at +32 MB and must end inside the window.
    fb_bytes = FB_STRIDE * FB_H
    if FB_PA + fb_bytes > PHYS_BASE + MEMORY_SIZE:
        raise SystemExit(
            f"framebuffer (0x{FB_PA:x}+0x{fb_bytes:x}) does not fit in the "
            f"{MEMORY_SIZE >> 20} MB window at 0x{PHYS_BASE:x}")

    ramdisk_size = 0
    if args.ramdisk:
        ramdisk_size = args.ramdisk.stat().st_size
        print(f"ramdisk: {args.ramdisk} ({ramdisk_size:#x} bytes at {RAMDISK_PA:#x})")

    encoded = adt.serialize(build_sm8850(ramdisk_size))
    parsed, end = adt.parse(encoded)
    if end != len(encoded) or adt.serialize(parsed) != encoded:
        raise SystemExit("ADT round-trip validation failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"wrote SM8850 ADT: {args.output} ({len(encoded)} bytes)")
    print(f"  dram-base=0x{PHYS_BASE:x} dram-size=0x{MEMORY_SIZE:x}")
    print(f"  GIC: GICD=0x{SM8850_GICD_PA:x} GICR=0x{SM8850_GICR_PA:x}")
    print(f"  Timer: {SM8850_TIMER_HZ} Hz")
    if ramdisk_size:
        print(f"  Ramdisk: {ramdisk_size} bytes at PA=0x{RAMDISK_PA:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
