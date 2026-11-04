#!/usr/bin/env python3
"""Assemble the two-image ramdisk mockfs serves.

Layout, and the reason for each part:

    0x00000  init image (sweet_init)      served as /launchd and /sbin/launchd
    0x40000  prog2 (clang-built Mach-O)   served as /prog

MOCKFS_PROG_OFFSET in mockfs_fsnode.h is the same 0x40000, so kernel and
ramdisk cannot disagree.  The init image is padded into its slot, the whole
file is padded to a 512-byte block, and every embedded image is hashed into the
output so a run can be tied to the bytes it actually booted.
"""
from __future__ import annotations
import argparse, hashlib, pathlib, sys

SLOT = 0x40000          # must equal MOCKFS_PROG_OFFSET
BLOCK = 512


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=pathlib.Path)
    ap.add_argument("--init", type=pathlib.Path, required=True)
    ap.add_argument("--prog", type=pathlib.Path, required=True)
    a = ap.parse_args()
    init = a.init.read_bytes()
    prog = a.prog.read_bytes()
    if not init or not prog:
        sys.exit("mk_ramdisk: an input image is empty")
    if len(init) > SLOT:
        sys.exit(f"mk_ramdisk: init image {len(init)} bytes exceeds its {SLOT:#x} slot")
    if len(prog) % BLOCK:
        prog += b"\0" * (BLOCK - len(prog) % BLOCK)
    image = init + b"\0" * (SLOT - len(init)) + prog
    image += b"\0" * (-len(image) % BLOCK)
    a.out.write_bytes(image)
    print(f"mk_ramdisk: {a.out} {len(image)} bytes "
          f"(init {len(init)} at 0x0, prog {len(prog)} at {SLOT:#x})")
    print(f"mk_ramdisk: init sha256={sha(init)[:16]} prog sha256={sha(prog)[:16]} "
          f"ramdisk sha256={sha(image)[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
