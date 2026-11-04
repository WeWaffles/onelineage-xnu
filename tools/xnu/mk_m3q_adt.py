#!/usr/bin/env python3
"""Generate a deterministic, QEMU-only ADT from the sanitized m3q manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

import adt

U32 = lambda *values: struct.pack("<%dI" % len(values), *values)
U64 = lambda *values: struct.pack("<%dQ" % len(values), *values)
CSTR = lambda value: value.encode("ascii") + b"\0"

QEMU_PHYS_BASE = 0x42000000   # 32 MB past QEMU virt RAM base (must be 32MB-aligned for XNU L2 block mapping)
QEMU_MEMORY_SIZE = 0x7e000000  # 2 GB - 32 MB (end = 0xC0000000, exactly at QEMU 2GB RAM limit)
QEMU_RAMDISK_BASE = 0x50000000  # well past kernel (~15 MB at phys_base+0) and boot_args
QEMU_GICD = 0x08000000
QEMU_GICR = 0x080A0000
QEMU_GICD_SIZE = 0x10000
QEMU_GICR_SIZE = 0x200000
QEMU_TIMER_HZ = 62500000
QEMU_FB_BASE = 0x9c000000   # sweet_early.c / start.s hardcode this address
QEMU_FB_W = 1080
QEMU_FB_H = 2400
QEMU_FB_STRIDE = QEMU_FB_W * 4  # 32 bpp


def make_node(name: str, props=(), children=()) -> adt.Node:
    return adt.Node([("name", 0, CSTR(name)), *[(key, 0, value) for key, value in props]], list(children))


def validate_manifest(manifest: dict) -> None:
    required = ("device", "board", "soc", "cpu", "timer", "gic", "handoff_status")
    missing = [name for name in required if name not in manifest]
    if missing:
        raise ValueError("hardware manifest is missing: " + ", ".join(missing))
    if manifest["handoff_status"].get("execution_authorized") is not False:
        raise ValueError("manifest must explicitly keep execution_authorized=false")
    if int(manifest["cpu"].get("count", 0)) < 1:
        raise ValueError("manifest has no CPUs")


def build_qemu(manifest: dict, ramdisk_size: int = 0) -> adt.Node:
    validate_manifest(manifest)
    phandles = iter(range(1, 128))
    ph = lambda: ("AAPL,phandle", U32(next(phandles)))
    seed = hashlib.sha512(json.dumps(manifest, sort_keys=True).encode()).digest()

    # RAMDisk property: [phys_addr (uint64), size_bytes (uint64)]
    # IOFindBSDRoot reads /chosen/memory-map/RAMDisk and calls
    # mdevadd(-1, ml_static_ptovirt(ramdParms[0])>>12, ramdParms[1]>>12, 0)
    # to create /dev/md0.  boot-args must include rd=md0.
    memmap_props = [ph()]
    if ramdisk_size > 0:
        memmap_props.append(("RAMDisk", U64(QEMU_RAMDISK_BASE, ramdisk_size)))

    chosen = make_node("chosen", [
        ph(),
        ("dram-base", U64(QEMU_PHYS_BASE)),
        ("dram-size", U64(QEMU_MEMORY_SIZE)),
        ("random-seed", seed),
        ("debug-enabled", U32(1)),
        ("firmware-version", CSTR("OneLineage-m3q-qemu")),
        ("system-firmware-version", CSTR("OneLineage-m3q-qemu")),
        ("source-device", CSTR(manifest["device"])),
    ], [make_node("memory-map", memmap_props)])

    cpu = make_node("cpu0", [
        ph(),
        ("device_type", CSTR("cpu")),
        ("compatible", CSTR("qcom,kryo470") + CSTR("ARM,v8")),
        ("reg", U32(0)),
        ("cpu-id", U32(0)),
        ("state", CSTR("running")),
        ("timebase-frequency", U32(QEMU_TIMER_HZ)),
        ("fixed-frequency", U32(QEMU_TIMER_HZ)),
    ])
    cpus = make_node("cpus", [ph(), ("#address-cells", U32(1)), ("#size-cells", U32(0))], [cpu])

    # pe_fiq.c maps GIC via: ml_io_map(soc_base_phys + reg[0], reg[1]) for GICD,
    # and ml_io_map(soc_base_phys + reg[2], reg[3]) for GICR.
    # soc_base_phys = ranges[1] = QEMU_GICD, so reg values must be offsets from it.
    # GICD offset = QEMU_GICD - QEMU_GICD = 0; GICR offset = QEMU_GICR - QEMU_GICD.
    QEMU_GICD_OFF = 0
    QEMU_GICR_OFF = QEMU_GICR - QEMU_GICD   # 0xA0000
    gic = make_node("gic", [
        ph(),
        ("compatible", CSTR("arm,gic-v3")),
        ("interrupt-controller", b""),
        ("virtual-timer-intid", U32(27)),
        ("reg", U64(QEMU_GICD_OFF, QEMU_GICD_SIZE, QEMU_GICR_OFF, QEMU_GICR_SIZE)),
    ])
    arm_io = make_node("arm-io", [
        ph(),
        ("device_type", CSTR("onelineage-io")),
        ("compatible", CSTR("onelineage,qemu-virt") + CSTR("arm-io")),
        ("#address-cells", U32(2)),
        ("#size-cells", U32(2)),
        # pe_arm_get_soc_base_phys reads ranges[1] (parent-bus-addr) as gPESoCBasePhys.
        # Must be nonzero: pe_identify_machine returns early if gPESoCBasePhys==0, which
        # leaves gPEClockFrequencyInfo zeroed, causing wfe_timeout_configure to call
        # flsll(0)-1 = 0xFFFFFFFF >= 64 and panic.  We use the QEMU GIC base as a
        # stand-in SoC base; it responds to MMIO reads so later gSocPhys-based lookups
        # fail gracefully (missing DTB entries → kprintf + return) rather than crashing.
        ("ranges", U64(0) + U64(QEMU_GICD) + U64(0x10000000)),
    ], [gic, make_node("wdt", [ph(), ("no-pmu", U32(1))])])

    # patch 0003 reads a "sweet-fbcon" node for the late serial console;
    # the address must match sweet_early.c's EARLY_FB (0x9c000000) and start.s's
    # bootstrap block mapping.  With 2 GB QEMU RAM the address is backed by plain RAM.
    fb_size = QEMU_FB_W * QEMU_FB_H * 4
    sweet_fbcon = make_node("sweet-fbcon", [
        ph(),
        ("reg", U64(QEMU_FB_BASE, fb_size)),
        ("width", U32(QEMU_FB_W)),
        ("height", U32(QEMU_FB_H)),
        ("stride", U32(QEMU_FB_STRIDE)),
    ])

    # /defaults node required by pmap_compute_max_asids (pmap.c assert err==kSuccess).
    # pmap-max-asids is optional; omitting it makes pmap fall back to MAX_ASIDS.
    defaults = make_node("defaults", [ph()])

    return make_node("device-tree", [
        ph(),
        ("model", CSTR("OneLineage m3q XNU QEMU validation")),
        # "xiaomi,sweet" must be present: patch 0016 matches IONameMatch='xiaomi,sweet'
        # against the root node to instantiate SweetPlatformExpert.
        ("compatible", CSTR("xiaomi,sweet") + CSTR("samsung,m3q") + CSTR(manifest["soc"]) + CSTR("AppleARM")),
        ("#address-cells", U32(2)),
        ("#size-cells", U32(2)),
        ("platform-name", CSTR("OneLineage-m3q-qemu")),
        ("clock-frequency", U32(QEMU_TIMER_HZ)),
    ], [chosen, cpus, arm_io, sweet_fbcon, defaults])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mode", choices=("qemu", "phone"), default="qemu")
    parser.add_argument("--ramdisk", type=Path, default=None,
                        help=f"Raw HFS+ ramdisk image to embed at QEMU_RAMDISK_BASE ({QEMU_RAMDISK_BASE:#x})")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest)
    if args.mode == "phone":
        status = manifest["handoff_status"]
        raise SystemExit(
            "refusing phone ADT: execution is not authorized; "
            f"safe payload region is {status.get('safe_payload_region', 'unknown')}; "
            f"framebuffer is {status.get('framebuffer', 'unknown')}"
        )
    ramdisk_size = 0
    if args.ramdisk:
        ramdisk_size = args.ramdisk.stat().st_size
        print(f"ramdisk: {args.ramdisk} ({ramdisk_size:#x} bytes at {QEMU_RAMDISK_BASE:#x})")
    encoded = adt.serialize(build_qemu(manifest, ramdisk_size=ramdisk_size))
    parsed, end = adt.parse(encoded)
    if end != len(encoded) or adt.serialize(parsed) != encoded:
        raise SystemExit("internal ADT round-trip validation failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"wrote validated QEMU ADT: {args.output} ({len(encoded)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

