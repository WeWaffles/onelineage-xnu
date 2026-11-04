#!/usr/bin/env python3
"""Build prog2 with the local iPhoneOS toolchain and verify what it produced.

The deliverable must be a static arm64 Mach-O that XNU's loader can enter with
no dyld present: LC_UNIXTHREAD supplies the initial PC, __TEXT sits at
0x100000000, and there is no dynamic-linker command.  The checks fail closed --
an image that would need dyld or that claims a different base is not packaged.

iOS SDK availability is a property of this machine, not of the repository, so a
missing SDK is reported as such rather than worked around.
"""
from __future__ import annotations
import hashlib, pathlib, struct, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "tools/xnu/prog2.c"
OUT = ROOT / "build/prog2.macho"
PAGE = 0x4000

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
LC_UNIXTHREAD = 0x5
LC_LOAD_DYLINKER = 0xE
LC_ID_DYLINKER = 0xF
LC_MAIN = 0x80000028
ARM_THREAD_STATE64 = 6


def check(path: pathlib.Path) -> dict:
    d = path.read_bytes()
    magic, cputype, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", d, 0)
    if magic != MH_MAGIC_64 or filetype != MH_EXECUTE:
        sys.exit(f"prog2: not a 64-bit MH_EXECUTE (magic={magic:#x} type={filetype})")
    if cputype != 0x0100000C:
        sys.exit(f"prog2: cputype {cputype:#x} is not arm64")
    off, entry, text_va, text_vmsize, dylinker, main = 32, None, None, None, False, False
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == LC_UNIXTHREAD:
            flavor, count = struct.unpack_from("<II", d, off + 8)
            if flavor != ARM_THREAD_STATE64 or count < 68:
                sys.exit(f"prog2: unexpected thread state flavor={flavor} count={count}")
            entry = struct.unpack_from("<Q", d, off + 16 + (29 + 3) * 8)[0]
        elif cmd == 0x19:  # LC_SEGMENT_64
            name = d[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize = struct.unpack_from("<QQ", d, off + 24)
            if name == "__TEXT":
                text_va, text_vmsize = vmaddr, vmsize
        elif cmd in (LC_LOAD_DYLINKER, LC_ID_DYLINKER):
            dylinker = True
        elif cmd == LC_MAIN:
            main = True
        off += cmdsize
    if entry is None:
        sys.exit("prog2: no LC_UNIXTHREAD; the SWEET loader enters through it")
    if text_va != 0x100000000:
        sys.exit(f"prog2: __TEXT at {text_va:#x}, expected 0x100000000")
    if dylinker or main:
        sys.exit("prog2: dynamic linker or LC_MAIN present; this boot has no dyld")
    return dict(size=len(d), entry=entry, text_vmsize=text_vmsize,
                sha256=hashlib.sha256(d).hexdigest())


def main() -> int:
    rc = subprocess.run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                        capture_output=True, text=True)
    if rc.returncode or not rc.stdout.strip():
        sys.exit("prog2: no iPhoneOS SDK installed; cannot build a real arm64 Mach-O")
    sdk = rc.stdout.strip()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["xcrun", "--sdk", "iphoneos", "clang",
           "-target", "arm64-apple-ios16.0", "-isysroot", sdk,
           "-O2", "-nostdlib", "-static",
           "-Wl,-e,__start", "-Wl,-segaddr,__TEXT,0x100000000",
           "-o", str(OUT), str(SRC)]
    rc = subprocess.run(cmd, capture_output=True, text=True)
    if rc.returncode:
        sys.exit(f"prog2: clang failed:\n{rc.stderr}")
    info = check(OUT)
    raw = OUT.read_bytes()
    # The ramdisk is a memory device, and the loader rejects an image whose
    # segments extend past the device's idea of the file: pad to whole pages,
    # which is what the device size is rounded to.  The hash is taken after
    # padding, so it describes the bytes that are actually packaged.
    if len(raw) % PAGE:
        raw += b"\0" * (PAGE - len(raw) % PAGE)
        OUT.write_bytes(raw)
    info["size"] = len(raw)
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    print(f"prog2: {OUT} {info['size']} bytes entry={info['entry']:#x} "
          f"__TEXT vmsize={info['text_vmsize']:#x} sha256={info['sha256'][:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
