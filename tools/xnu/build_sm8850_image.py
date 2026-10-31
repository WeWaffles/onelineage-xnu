#!/usr/bin/env python3
"""Build a flat physical RAM image from an ONELXNU payload for the SM8850.

The image has all kernel segments, ADT, and boot_args placed at their correct
offsets from physical_base, zero-filled in between.  The ramdisk (if supplied)
is placed at offset 0x2400000 (matches mk_sm8850_adt.py RAMDISK_PA_OFFSET).

Output can be streamed directly to the olxnu_payload procfs node:
  adb shell 'su -c dd if=/data/local/tmp/sm8850_image.bin \
             of=/proc/olxnu_payload/data bs=1M'
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = b"ONELXNU\0"
PAGE  = 0x4000
BOOT_LINE_LENGTH = 608

FB_W, FB_H = 1080, 2400
FB_STRIDE  = FB_W * 4

# Ramdisk offset from phys_base (must match mk_sm8850_adt.py RAMDISK_PA_OFFSET)
RAMDISK_PA_OFFSET = 0x2400000


def build_image(payload: bytes, ramdisk: bytes | None) -> tuple[bytes, int, int, int]:
    """Return (flat_image, phys_base, boot_args_pa, entry_pa)."""
    magic, ver, nsegs = struct.unpack_from("<8sII", payload, 0)
    if magic != MAGIC or ver != 1:
        raise ValueError(f"not an ONELXNU v1 payload (magic={magic!r} ver={ver})")
    virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = (
        struct.unpack_from("<7Q", payload, 0x10)
    )
    cmdline = payload[0x48 : 0x48 + BOOT_LINE_LENGTH]

    # Compute PA offsets
    adt_pa_off = kernel_end - virt_base
    ba_pa_off  = (adt_pa_off + adt_size + PAGE - 1) & ~(PAGE - 1)
    ba_pa      = phys_base + ba_pa_off
    entry_pa   = phys_base + (entry_va - virt_base)

    # Image spans from PA offset 0 to end of boot_args page
    img_size   = ba_pa_off + PAGE
    if ramdisk:
        img_size = max(img_size, RAMDISK_PA_OFFSET + len(ramdisk))
    img = bytearray(img_size)

    # Place kernel segments
    for i in range(nsegs):
        vmaddr, _vmsize, foff, fsize = struct.unpack_from("<4Q", payload, 0x2A8 + 32 * i)
        pa_off = vmaddr - virt_base
        img[pa_off : pa_off + fsize] = payload[foff : foff + fsize]

    # Place ADT
    img[adt_pa_off : adt_pa_off + adt_size] = payload[adt_off : adt_off + adt_size]

    # Build boot_args
    adt_va  = virt_base + adt_pa_off
    fb_va   = virt_base + 0x4000000   # framebuffer VA in XNU space
    top     = ba_pa + PAGE

    ba = struct.pack(
        "<HH4x4Q6QI4xQI",
        2, 2,
        virt_base, phys_base, mem_size, top,
        fb_va, 1, FB_STRIDE, FB_W, FB_H, 32,
        0,
        adt_va,
        adt_size,
    )
    ba += cmdline + b"\0" * 4 + struct.pack("<QQ", 0, mem_size)
    assert len(ba) == 736

    img[ba_pa_off : ba_pa_off + len(ba)] = ba

    # Place ramdisk
    if ramdisk:
        img[RAMDISK_PA_OFFSET : RAMDISK_PA_OFFSET + len(ramdisk)] = ramdisk

    return bytes(img), phys_base, ba_pa, entry_pa


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("payload", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--ramdisk", type=Path, default=None)
    args = ap.parse_args()

    payload = args.payload.read_bytes()
    rd      = args.ramdisk.read_bytes() if args.ramdisk else None

    img, phys_base, ba_pa, entry_pa = build_image(payload, rd)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(img)

    print(f"wrote flat image: {args.output} ({len(img):#x} bytes = {len(img)/1024/1024:.1f} MB)")
    print(f"  phys_base    = 0x{phys_base:x}")
    print(f"  entry_pa     = 0x{entry_pa:x}")
    print(f"  boot_args_pa = 0x{ba_pa:x}")
    print(f"  payload_size = 0x{len(img):x}")
    print(f"")
    print(f"Device load sequence (after reboot):")
    print(f"  # 1. Load payload module:")
    print(f"  insmod /data/local/tmp/olxnu_payload.ko payload_size_mb=64 target_pa=0x{phys_base:x}")
    print(f"  # 2. Stream image to physical memory:")
    print(f"  dd if=/data/local/tmp/sm8850_image.bin of=/proc/olxnu_payload/data bs=1M")
    print(f"  # 3. Load jump module:")
    print(f"  insmod /data/local/tmp/olxnu_jump_mod.ko \\")
    print(f"    payload_pa=0x{phys_base:x} \\")
    print(f"    payload_size=0x{len(img):x} \\")
    print(f"    entry_pa=0x{entry_pa:x} \\")
    print(f"    boot_args_pa=0x{ba_pa:x}")
    print(f"  # 4. Jump!")
    print(f"  echo 'go' > /proc/olxnu_jump/jump")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
