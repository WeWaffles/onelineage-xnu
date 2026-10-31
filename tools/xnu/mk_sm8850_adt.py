#!/usr/bin/env python3
"""Generate an SM8850 (Galaxy S26 Ultra / canoe) ADT for physical XNU boot.

Physical constants:
  GIC: GICD=0x17000000 GICR=0x17080000 (from sm8850_device.dts)
  Timer: 19.2 MHz = 19200000 Hz (arm,armv8-timer, fdt confirmed)
  Payload PA: 0x8c0000000 (olxnu_payload.ko linear-map allocation)
  Memory size: 0x10000000 (256 MB — enough for XNU boot, avoids reserved sub-regions)

The ramdisk is placed at phys_base + 0x2400000 (36 MB into the 256 MB window),
safely past the 32 MB kernel virtual span.  Its physical address is stored in
the ADT RAMDisk property so XNU can find /dev/md0.
"""
from __future__ import annotations

import argparse
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

# Payload PA (must match olxnu_payload.ko target_pa)
PHYS_BASE         = 0x8c0000000
MEMORY_SIZE       = 0x10000000  # 256 MB; covers all of XNU's bootstrap needs

# Ramdisk within the 256 MB window, after the 32 MB kernel virtual span + margin
RAMDISK_PA_OFFSET = 0x2400000   # 36 MB from PHYS_BASE
RAMDISK_PA        = PHYS_BASE + RAMDISK_PA_OFFSET

# Framebuffer: put it in our RAM region (XNU writes framebuffer here at boot)
# We use a VA of virt_base + fb_offset; build_sm8850_payload.py computes the VA.
FB_W, FB_H = 1080, 2400
FB_STRIDE  = FB_W * 4
# Using a plain RAM address just past the ramdisk so writes don't crash XNU.
FB_PA      = PHYS_BASE + 0x4000000  # 64 MB from PHYS_BASE


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
        ("source-device", CSTR("samsung,e3q")),
    ], [make_node("memory-map", memmap_props)])

    # cpus — single Oryon CPU
    cpu = make_node("cpu0", [
        ph(),
        ("device_type", CSTR("cpu")),
        ("compatible", CSTR("qcom,oryon") + CSTR("ARM,v9")),
        ("reg", U32(0)),
        ("cpu-id", U32(0)),
        ("state", CSTR("running")),
        ("timebase-frequency", U32(SM8850_TIMER_HZ)),
        ("fixed-frequency", U32(SM8850_TIMER_HZ)),
    ])
    cpus = make_node("cpus", [ph(), ("#address-cells", U32(1)), ("#size-cells", U32(0))], [cpu])

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
    fb_size = FB_W * FB_H * 4
    sweet_fbcon = make_node("sweet-fbcon", [
        ph(),
        ("reg", U64(FB_PA, fb_size)),
        ("width", U32(FB_W)),
        ("height", U32(FB_H)),
        ("stride", U32(FB_STRIDE)),
    ])

    defaults = make_node("defaults", [ph()])

    return make_node("device-tree", [
        ph(),
        ("model", CSTR("OneLineage SM8850 XNU physical")),
        # "xiaomi,sweet" must match: SweetPlatformExpert IONameMatch
        ("compatible", CSTR("xiaomi,sweet") + CSTR("samsung,e3q") + CSTR("qcom,sm8850") + CSTR("AppleARM")),
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
    args = ap.parse_args()

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
