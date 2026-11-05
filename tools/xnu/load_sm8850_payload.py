#!/usr/bin/env python3
"""Load an ONELXNU payload onto the physical the arm64 target and print jump parameters.

Usage:
  python3 load_sm8850_payload.py PAYLOAD [--ramdisk RAMDISK] [--proc PATH]

Reads the ONELXNU v1 payload, reconstructs the physical memory layout
(same algorithm as run_qemu.py:build_image), and streams each chunk to the
olxnu_payload procfs device via seek+write so each byte lands at the correct
PA offset from physical_base.

After loading, prints the parameters to configure olxnu_jump_mod:
  payload_pa    = physical_base
  payload_size  = (end of boot_args page - physical_base)
  entry_pa      = physical_base + (entry_va - virt_base)
  boot_args_pa  = physical_base + (ba_offset)

The jump module jump_stub must pass x0=boot_args_pa to XNU's arm_init.
"""
from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

MAGIC = b"ONELXNU\0"
PAGE  = 0x4000
BOOT_LINE_LENGTH = 608

# boot_args Video fields for the SM8850 — framebuffer mapped in our RAM region
# PA = phys_base + 0x4000000; VA = virt_base + 0x4000000
FB_W, FB_H = 1080, 2400
FB_STRIDE  = FB_W * 4


def parse_payload(data: bytes) -> dict:
    magic, ver, nsegs = struct.unpack_from("<8sII", data, 0)
    if magic != MAGIC or ver != 1:
        raise ValueError(f"not an ONELXNU v1 payload (magic={magic!r} ver={ver})")
    virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = (
        struct.unpack_from("<7Q", data, 0x10)
    )
    cmdline = data[0x48 : 0x48 + BOOT_LINE_LENGTH]
    segs = []
    for i in range(nsegs):
        vmaddr, vmsize, foff, fsize = struct.unpack_from("<4Q", data, 0x2A8 + 32 * i)
        segs.append((vmaddr, vmsize, foff, fsize))
    return {
        "virt_base": virt_base, "entry_va": entry_va,
        "adt_off": adt_off, "adt_size": adt_size,
        "kernel_end": kernel_end, "phys_base": phys_base, "mem_size": mem_size,
        "cmdline": cmdline, "segments": segs,
    }


def build_layout(p: dict, ramdisk: bytes | None) -> list[tuple[int, bytes]]:
    """Return list of (pa_offset_from_phys_base, data) chunks to write."""
    phys_base = p["phys_base"]
    virt_base = p["virt_base"]
    kernel_end = p["kernel_end"]
    adt_off = p["adt_off"]
    adt_size = p["adt_size"]
    mem_size = p["mem_size"]
    cmdline = p["cmdline"]
    entry_va = p["entry_va"]

    chunks: list[tuple[int, bytes]] = []

    # Kernel segments: each at (vmaddr - virt_base) offset from phys_base
    for vmaddr, vmsize, foff, fsize in p["segments"]:
        seg_pa_off = vmaddr - virt_base
        seg_data = data[foff : foff + fsize]
        chunks.append((seg_pa_off, seg_data))

    # ADT: at (kernel_end - virt_base) offset
    adt_pa_off = kernel_end - virt_base
    adt_data   = data[adt_off : adt_off + adt_size]
    chunks.append((adt_pa_off, adt_data))

    adt_pa    = phys_base + adt_pa_off
    ba_pa_off = (adt_pa_off + adt_size + PAGE - 1) & ~(PAGE - 1)
    ba_pa     = phys_base + ba_pa_off

    # boot_args deviceTreeP: VA of ADT
    adt_va = virt_base + adt_pa_off

    # Framebuffer VA: virt_base + 0x4000000 (matches FB_PA = phys_base+0x4000000 in ADT)
    fb_va  = virt_base + 0x4000000

    top = ba_pa + PAGE  # top-of-kernel-data

    ba = struct.pack(
        "<HH4x4Q6QI4xQI",
        2, 2,                                  # revision, version
        virt_base, phys_base, mem_size, top,   # virtBase, physBase, memSize, topOfKernelData
        fb_va, 1, FB_STRIDE, FB_W, FB_H, 32,   # Video: baseAddr, display, rowBytes, w, h, depth
        0,                                     # machineType
        adt_va,                                # deviceTreeP (VA)
        adt_size,                              # deviceTreeLength
    )
    ba += cmdline + b"\0" * 4 + struct.pack("<QQ", 0, mem_size)
    assert len(ba) == 736, f"boot_args wrong size: {len(ba)}"
    chunks.append((ba_pa_off, ba))

    # Ramdisk (if provided): at phys_base + 0x2400000 (matches mk_sm8850_adt.py RAMDISK_PA_OFFSET)
    if ramdisk:
        rd_pa_off = 0x2400000
        chunks.append((rd_pa_off, ramdisk))

    return chunks, ba_pa_off, entry_va - virt_base


data: bytes = b""  # module-level for segment loader access


def write_to_device(proc_data: str, chunks: list[tuple[int, bytes]]) -> None:
    fd = os.open(proc_data, os.O_RDWR)
    try:
        total = 0
        for pa_off, chunk_data in sorted(chunks):
            os.lseek(fd, pa_off, os.SEEK_SET)
            written = 0
            while written < len(chunk_data):
                n = os.write(fd, chunk_data[written:])
                if n <= 0:
                    raise RuntimeError(f"write failed at offset {pa_off + written:#x}")
                written += n
            total += len(chunk_data)
            print(f"  wrote {len(chunk_data):#8x} bytes at PA_off={pa_off:#010x}", flush=True)
        print(f"total written: {total:#x} bytes ({total / 1024 / 1024:.1f} MB)")
    finally:
        os.close(fd)


def main() -> int:
    global data
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("payload", type=Path)
    ap.add_argument("--ramdisk", type=Path, default=None)
    ap.add_argument("--proc", default="/proc/olxnu_payload/data",
                    help="procfs data node (default: /proc/olxnu_payload/data)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print layout without writing to device")
    args = ap.parse_args()

    data = args.payload.read_bytes()
    p = parse_payload(data)
    rd = args.ramdisk.read_bytes() if args.ramdisk else None

    chunks, ba_pa_off, entry_pa_off = build_layout(p, rd)

    phys_base = p["phys_base"]
    ba_pa     = phys_base + ba_pa_off
    entry_pa  = phys_base + entry_pa_off

    print(f"Payload: {args.payload.name} ({len(data):#x} bytes)")
    print(f"  phys_base=0x{phys_base:x}  mem_size=0x{p['mem_size']:x}")
    print(f"  virt_base=0x{p['virt_base']:x}  entry_va=0x{p['entry_va']:x}")
    print(f"  kernel_end=0x{p['kernel_end']:x}")
    print(f"  adt_size={p['adt_size']} bytes")
    print(f"")
    print(f"Physical layout:")
    for pa_off, chunk_data in sorted(chunks):
        print(f"  PA=0x{phys_base+pa_off:x}  size=0x{len(chunk_data):x}")
    print(f"")
    print(f"Jump parameters:")
    print(f"  payload_pa   = 0x{phys_base:x}")
    print(f"  payload_size = 0x{ba_pa + PAGE - phys_base:x}")
    print(f"  entry_pa     = 0x{entry_pa:x}")
    print(f"  boot_args_pa = 0x{ba_pa:x}")
    print(f"")
    print(f"olxnu_jump_mod commands (run on device):")
    print(f"  insmod /data/local/tmp/olxnu_jump_mod.ko \\")
    print(f"    payload_pa=0x{phys_base:x} \\")
    print(f"    payload_size=0x{ba_pa + PAGE - phys_base:x} \\")
    print(f"    entry_pa=0x{entry_pa:x} \\")
    print(f"    boot_args_pa=0x{ba_pa:x}")

    if args.dry_run:
        print("\n[dry-run] skipping write to device")
        return 0

    print(f"\nWriting payload to {args.proc} ...")
    write_to_device(args.proc, chunks)
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
