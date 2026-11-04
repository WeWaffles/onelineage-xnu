#!/usr/bin/env python3
"""Build a flat physical RAM image from an ONELXNU payload for the SM8850.

The image has all kernel segments, ADT, and boot_args placed at their correct
offsets from physical_base, zero-filled in between.  The ramdisk (if supplied)
is placed at offset 0x800000 (matches mk_sm8850_adt.py RAMDISK_PA_OFFSET), inside
the empty 16 MB __PAGEZERO hole at the bottom of the image.

Output can be streamed directly to the olxnu_payload procfs node:
  adb shell 'su -c dd if=/data/local/tmp/sm8850_image.bin \
             of=/proc/olxnu_payload/data bs=1M'
"""
from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

MAGIC = b"ONELXNU\0"
PAGE  = 0x4000
BOOT_LINE_LENGTH = 608

# The panel's geometry (XNU_PROGRESS.md, M18): 1472x3120 at a 5888 byte pitch,
# i.e. 18,370,560 bytes.  These must match mk_sm8850_adt.py's sweet-fbcon node,
# which is also where arm_vm_init sizes the early I/O mapping from.
# 1472x3120 at 5888.  The 3120x1472/12480 spelling is the same 18,370,560 bytes
# and hw/m272 drew with it to the same uniform bars, so neither the panel nor the
# size check distinguishes them (M23); this is the one that printed in hw/m265.
FB_W, FB_H = 1472, 3120
FB_DEPTH = int(os.environ.get("OLXNU_FB_DEPTH", "32"))
if FB_DEPTH not in (16, 32):
    raise SystemExit("OLXNU_FB_DEPTH must be 16 or 32")
FB_STRIDE = FB_W * (FB_DEPTH // 8)

# Ramdisk offset from phys_base (must match mk_sm8850_adt.py RAMDISK_PA_OFFSET)
RAMDISK_PA_OFFSET = 0x800000


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
    #
    # Framebuffer: hand XNU the *physical* address with bit 0 set, which is how
    # video_console.c marks "this needs a mapping" (initialize_screen's
    # makeMapping).  The old value here was virt_base + 0x4000000, an address
    # nothing maps: the first progress-meter blit took a level 3 translation
    # fault on it (build/lk_m146_a1.bin, far 0xfffffff0256726bc, pc in
    # vc_blit_rect_32).  A VA cannot work here anyway, because the frame is at    #    phys_base + 0x2400000 — 43 GB up, far outside the kernel's V=P physmap —
    #    so it has to go through ml_io_map_unmappable() like any other device.
    # FB_PA must match mk_sm8850_adt.py's sweet-fbcon "reg".
    fb_va   = (phys_base + 0x2400000) | 1
    top     = ba_pa + PAGE

    #
    # topOfKernelData has to sit *above* the framebuffer, not below it.
    #
    # arm_vm_init() takes everything between topOfKernelData and physBase +
    # memSize as free memory for the VM (arm_vm_init.c:2060 avail_start,
    # vm_page_bootstrap), and the framebuffer was inside that range: it is at
    # +32 MB of a 64 MB window whose topOfKernelData was only ~+19 MB.  So the
    # pmap and the kernel zones were allocating page tables out of the very
    # memory the console draws into, and hw/m275..m277 die within one 64 KB
    # chunk of the first full-buffer paint, with no panic text and nothing
    # after 0xc3 - a corrupted page table, not a bad mapping.
    #
    # Raising topOfKernelData over the framebuffer declares it booter-owned
    # static memory, which is what it is: the panel scans it, so the VM must
    # never hand those pages out.  It stays in the V=P physmap, so phystokv()
    # and the console's cached alias keep working; only the free-page range
    # shrinks (to the ~14.5 MB above the framebuffer).
    fb_end  = phys_base + 0x2400000 + ((FB_STRIDE * FB_H + 0x1fffff) & ~0x1fffff)
    if top < fb_end:
        top = fb_end
    if top > phys_base + mem_size:
        raise SystemExit(
            f"framebuffer 0x{fb_end:x} does not fit under physBase+memSize "
            f"0x{phys_base + mem_size:x}")
    top     = (top + PAGE - 1) & ~(PAGE - 1)

    ba = struct.pack(
        "<HH4x4Q6QI4xQI",
        2, 2,
        virt_base, phys_base, mem_size, top,
        fb_va, 1, FB_STRIDE, FB_W, FB_H, FB_DEPTH,
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
