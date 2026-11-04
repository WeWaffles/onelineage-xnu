#!/usr/bin/env python3
"""Boot an ONELXNU payload in QEMU's virt board.

  run_qemu.py PAYLOAD OUTDIR [--secs N] [--gdb] [--live-serial]

Reads an ONELXNU v1 payload (tools/xnu/build_payload.py), reconstructs the
physical RAM image, places the kernel segments, ADT and boot_args, writes a
6-instruction entry stub, and launches qemu-system-aarch64 -M virt,gic-version=3.

virt RAM starts at 0x40000000.  With 2 GB it covers the sweet early-console
framebuffer at 0x9c000000 as plain RAM, which is what start.s's bootstrap block
mapping writes through.

After N seconds (or when the guest exits) it writes into OUTDIR:
  fb.png     the 1080x2400 framebuffer snapshot
  regs.txt   QEMU CPU register state
  qemu.log   guest exceptions (ESR/FAR/ELR) from -d int,guest_errors
  result.json  {status, ...}

With --kernel KERNEL (the unstripped Mach-O), also decode the framebuffer via
the kernel's iso_font and write fb.txt.  --fail-on-panic returns 2 for a visible
panic or 3 for an undecodable/blank screen.

Adapted from dipa-studio/ios-sweet tools/qemu-sweet.py (MIT).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
import zlib

MAGIC = b"ONELXNU\0"
PAGE = 0x4000
BOOT_LINE_LENGTH = 608
QEMU_PHYS_BASE = 0x42000000  # payload phys_base; must be 32MB-aligned for XNU bootstrap L2 block mapping
# Physical address the ramdisk image is loaded at.  It is verified present in
# guest RAM (0xfeedfacf at this address via the monitor), but md0 still pages in
# zeros for it, so QEMU cannot yet reach EL0 -- see XNU_PROGRESS.md.
QEMU_RAMDISK_BASE = 0x50000000
FB_BASE = 0x9c000000   # sweet_early.c EARLY_FB
FB_W = 1080
FB_H = 2400
FB_STRIDE = FB_W * 4


def _make_empty_fdt() -> bytes:
    """Return a minimal valid FDT blob with a bare root node.

    Passed to QEMU via -machine dtb= so the virt board does not auto-generate
    its own device tree at phys_base (0x40000000), which would overlap our
    payload's RAM image.  XNU uses the Apple ADT embedded in the payload, not
    the Linux FDT, so the FDT content is irrelevant beyond structural validity.
    """
    FDT_MAGIC      = 0xd00dfeed
    FDT_BEGIN_NODE = 0x00000001
    FDT_END_NODE   = 0x00000002
    FDT_PROP       = 0x00000003
    FDT_NOP        = 0x00000004
    FDT_END        = 0x00000009

    # String table: just the two cell-size property names
    strings_addr = b"#address-cells\x00"
    strings_size = b"#size-cells\x00"
    str_table = strings_addr + strings_size
    off_addr = 0
    off_size = len(strings_addr)

    def u32b(v): return struct.pack(">I", v)
    def pad4(b): return b + b"\x00" * ((-len(b)) & 3)

    # Structure: begin-node "/" + two uint32 props + end-node + END
    dt_struct = (
        u32b(FDT_BEGIN_NODE) + pad4(b"\x00")  # name="" (root)
        + u32b(FDT_PROP) + u32b(4) + u32b(off_addr) + u32b(1)   # #address-cells = 1
        + u32b(FDT_PROP) + u32b(4) + u32b(off_size)  + u32b(1)  # #size-cells = 1
        + u32b(FDT_END_NODE)
        + u32b(FDT_END)
    )

    HEADER_SIZE    = 40
    off_mem_rsvmap = HEADER_SIZE
    off_dt_struct  = off_mem_rsvmap + 16   # one all-zero reservation entry
    off_dt_strings = off_dt_struct + len(dt_struct)
    totalsize      = off_dt_strings + len(str_table)

    header = struct.pack(
        ">IIIIIIII",
        FDT_MAGIC,
        totalsize,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        17,   # version
        16,   # last_comp_version
        0,    # boot_cpuid_phys
    ) + struct.pack(">II", len(str_table), len(dt_struct))  # size_dt_strings, size_dt_struct

    return header + b"\x00" * 16 + dt_struct + str_table


def check_qemu(cpu: str = "cortex-a76") -> bool:
    qemu_bin = shutil.which("qemu-system-aarch64")
    if not qemu_bin:
        print("[!] qemu-system-aarch64 not found in PATH", file=sys.stderr)
        print("    macOS: brew install qemu", file=sys.stderr)
        return False
    try:
        ver = subprocess.check_output([qemu_bin, "--version"], text=True).splitlines()[0]
        print(f"[*] Found QEMU: {ver}", file=sys.stderr)
    except Exception as exc:
        print(f"[!] Could not query QEMU version: {exc}", file=sys.stderr)
        return False
    return True


def llvm_nm() -> str | None:
    """Locate llvm-nm.

    Homebrew's llvm is often not on PATH even when installed, and Xcode always
    ships one; searching both avoids a run that silently loses text decoding.
    """
    found = shutil.which("llvm-nm")
    if found:
        return found
    try:
        found = subprocess.check_output(["xcrun", "-f", "llvm-nm"],
                                        text=True, stderr=subprocess.DEVNULL).strip()
        if found and os.path.isfile(found):
            return found
    except Exception:
        pass
    for toolchain in sorted(glob.glob(
            "/Applications/Xcode*.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-nm")):
        return toolchain
    return None


def check_llvm_nm(kernel_path: str) -> bool:
    if not llvm_nm():
        print("[!] llvm-nm not found (required for --kernel text decoding)", file=sys.stderr)
        print("    macOS: brew install llvm", file=sys.stderr)
        return False
    if not os.path.isfile(kernel_path):
        print(f"[!] kernel not found: {kernel_path}", file=sys.stderr)
        return False
    return True


# `msr OSLAR_EL1, xzr` followed by `msr DAIFSet, #0xf` — the debug unlock at
# the top of _start_first_cpu.  Unlikely to occur by accident; used to find the
# single instruction QEMU cannot execute.
OSLAR_UNLOCK = struct.pack("<II", 0xD510109F, 0xD5034FDF)
AARCH64_NOP = struct.pack("<I", 0xD503201F)


def build_image(payload: bytes) -> tuple[int, bytes, int, int]:
    """Return (phys_base, ram_image, boot_args_pa, entry_pa)."""
    magic, ver, nsegs = struct.unpack_from("<8sII", payload, 0)
    if magic != MAGIC or ver != 1:
        raise ValueError(f"not an ONELXNU v1 payload (magic={magic!r} ver={ver})")
    virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = (
        struct.unpack_from("<7Q", payload, 0x10)
    )
    cmdline = payload[0x48 : 0x48 + BOOT_LINE_LENGTH]
    delta = phys_base - virt_base
    adt_pa = kernel_end + delta
    ba_pa = (adt_pa + adt_size + PAGE - 1) & ~(PAGE - 1)
    top = ba_pa + PAGE

    img = bytearray(top - phys_base)
    for i in range(nsegs):
        vmaddr, _vmsize, foff, fsize = struct.unpack_from("<4Q", payload, 0x2A8 + 32 * i)
        o = vmaddr + delta - phys_base
        img[o : o + fsize] = payload[foff : foff + fsize]
    img[adt_pa - phys_base : adt_pa - phys_base + adt_size] = payload[adt_off : adt_off + adt_size]

    # boot_args — XNU expects deviceTreeP as a virtual address
    ba = struct.pack(
        "<HH4x4Q6QI4xQI",
        2, 2,
        virt_base, phys_base, mem_size, top,
        FB_BASE, 1, FB_STRIDE, FB_W, FB_H, 32,
        0,
        adt_pa - delta,  # VA of ADT
        adt_size,
    )
    ba += cmdline + b"\0" * 4 + struct.pack("<QQ", 0, mem_size)
    assert len(ba) == 736
    img[ba_pa - phys_base : ba_pa - phys_base + len(ba)] = ba

    #
    # QEMU has no debug registers.
    #
    # _start_first_cpu opens with `msr OSLAR_EL1, xzr` (unlock the OS lock for
    # an external debugger).  TCG does not model that register, so the store
    # raises an undefined-instruction exception *before* VBAR_EL1 is set, and
    # the guest vectors through 0x200 forever.  The unlock only affects an
    # attached debugger, so neutralise that single instruction in the QEMU
    # image; the payload and the device kernel are untouched.
    patched = 0
    off = img.find(OSLAR_UNLOCK)
    while off >= 0:
        img[off : off + 4] = AARCH64_NOP
        patched += 1
        off = img.find(OSLAR_UNLOCK, off + 4)
    if patched:
        print(f"[*] neutralised {patched} OSLAR_EL1 unlock for QEMU", flush=True)

    return phys_base, bytes(img), ba_pa, entry_va + delta


def make_stub(ba_pa: int, entry_pa: int) -> bytes:
    # ldr x0, =ba_pa ; ldr x1, =entry_pa ; br x1 ; nop ; .quad ba_pa ; .quad entry_pa
    return struct.pack("<4I2Q", 0x58000080, 0x580000A1, 0xD61F0020, 0xD503201F, ba_pa, entry_pa)


def write_png(path: str, raw: bytes) -> None:
    rows = []
    for y in range(FB_H):
        line = raw[y * FB_STRIDE : (y + 1) * FB_STRIDE]
        rgb = bytearray(FB_W * 3)
        rgb[0::3] = line[2::4]  # a8r8g8b8 LE = B G R A in memory
        rgb[1::3] = line[1::4]
        rgb[2::3] = line[0::4]
        rows.append(b"\0" + bytes(rgb))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", FB_W, FB_H, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"".join(rows), 6))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


def payload_data(payload: bytes, va: int, size: int) -> bytes:
    nsegs = struct.unpack_from("<I", payload, 12)[0]
    for i in range(nsegs):
        vmaddr, _vmsize, foff, fsize = struct.unpack_from("<4Q", payload, 0x2A8 + 32 * i)
        if vmaddr <= va < vmaddr + fsize and va + size <= vmaddr + fsize:
            return payload[foff + va - vmaddr : foff + va - vmaddr + size]
    raise ValueError(f"VA {va:#x}+{size:#x} not found in initialized payload segments")


def decode_screen(raw: bytes, font: bytes) -> tuple[str, int]:
    """Exact glyph matching for sweet_early.c's 2x white-on-black console."""
    glyphs = {font[c * 16 : (c + 1) * 16]: chr(c) for c in range(32, 127)}
    rows, unknown = [], 0
    for row in range(FB_H // 32):
        chars = []
        for col in range(FB_W // 16):
            glyph = bytearray(16)
            for y in range(16):
                offset = (row * 32 + y * 2) * FB_STRIDE + col * 16 * 4
                for x in range(8):
                    if raw[offset + x * 8 : offset + x * 8 + 4] == b"\xff" * 4:
                        glyph[y] |= 1 << x
            key = bytes(glyph)
            char = glyphs.get(key, "?")
            unknown += key not in glyphs
            chars.append(char)
        rows.append("".join(chars).rstrip())
    return "\n".join(rows).rstrip() + "\n", unknown


def screen_result(screen: str, unknown: int) -> dict:
    if "panic(cpu " in screen or "SWEET EARLY PANIC:" in screen:
        status = "panic"
    elif unknown:
        status = "incomplete_decode"
    elif screen.strip():
        status = "no_panic_observed"
    else:
        status = "blank_screen"
    return {"status": status, "unknown_glyphs": unknown, "snapshot_only": True}


def qmp(sock_path: str, *cmds: str, pmemsave=None) -> list[str]:
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    f = s.makefile("rw")
    f.readline()

    def call(execute: str, **kwargs):
        f.write(json.dumps({"execute": execute, "arguments": kwargs}) + "\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                return r

    call("qmp_capabilities")
    out = []
    for c in cmds:
        r = call("human-monitor-command", **{"command-line": c})
        if "error" in r:
            print(f"qmp {c!r}: {r['error']}", file=sys.stderr)
        out.append(r.get("return", ""))
    if pmemsave:
        r = call("pmemsave", val=pmemsave[0], size=pmemsave[1], filename=pmemsave[2])
        if "error" in r:
            print(f"qmp pmemsave: {r['error']}", file=sys.stderr)
    s.close()
    return out


def stream_serial(serial_path: str, pos: int, out=sys.stdout) -> int:
    if not os.path.exists(serial_path):
        return pos
    try:
        with open(serial_path, "r", errors="replace") as f:
            f.seek(pos)
            data = f.read()
            if data:
                out.write(data)
                out.flush()
                return f.tell()
    except Exception:
        pass
    return pos


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Boot an ONELXNU payload in QEMU's virt board.",
        epilog=(
            "Examples:\n"
            "  run_qemu.py payload.bin out/\n"
            "  run_qemu.py payload.bin out/ --live-serial\n"
            "  run_qemu.py payload.bin out/ --kernel kernel.macho --fail-on-panic\n"
            "  run_qemu.py --check-env\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("payload", nargs="?", help="ONELXNU v1 payload (from build_payload.py)")
    ap.add_argument("outdir", nargs="?", help="Output directory")
    ap.add_argument("--secs", type=float, default=120, help="Seconds to run (default: 120; XNU needs ~90s to reach EL0)")
    ap.add_argument("--gdb", action="store_true", help="Start halted, GDB stub on :1234")
    ap.add_argument("--hmp", action="append", default=[], help="Extra QMP monitor command after stop")
    ap.add_argument("--cpu", default="cortex-a76", help="QEMU CPU model (default: cortex-a76)")
    ap.add_argument("--kernel", help="Unstripped Mach-O for iso_font extraction and FB text decoding")
    ap.add_argument("--fail-on-panic", action="store_true", help="Exit 2 on panic, 3 on blank/undecodable")
    ap.add_argument("--live-serial", action="store_true", help="Stream serial output to stdout")
    ap.add_argument("--check-env", action="store_true", help="Verify QEMU install without running")
    ap.add_argument("--ramdisk", help="Raw HFS+ image to load at QEMU_RAMDISK_BASE (0x50000000)")
    args = ap.parse_args()

    if args.check_env:
        ok = check_qemu(args.cpu)
        if llvm_nm():
            print("[*] llvm-nm found", file=sys.stderr)
        else:
            print("[!] llvm-nm not found (optional, needed for --kernel)", file=sys.stderr)
        return 0 if ok else 1

    if not args.payload or not args.outdir:
        ap.error("payload and outdir are required unless --check-env is used")
    if args.fail_on_panic and not args.kernel:
        ap.error("--fail-on-panic requires --kernel")
    if not check_qemu(args.cpu):
        return 1
    if args.kernel and not check_llvm_nm(args.kernel):
        return 1

    payload = open(args.payload, "rb").read()
    font = None
    if args.kernel:
        symbols = subprocess.check_output([llvm_nm(), "--defined-only", args.kernel], text=True)
        fonts = [
            int(line.split()[0], 16)
            for line in symbols.splitlines()
            if line.split()[-1:] == ["_iso_font"]
        ]
        if len(fonts) != 1:
            ap.error("kernel must contain exactly one _iso_font symbol")
        font = payload_data(payload, fonts[0], 256 * 16)

    os.makedirs(args.outdir, exist_ok=True)
    out = os.path.abspath(args.outdir)

    phys_base, img, ba_pa, entry_pa = build_image(payload)
    stub_pa = ba_pa + PAGE  # right after boot_args, in unused RAM
    ram_gib = max(2, -(-(phys_base + struct.unpack_from("<Q", payload, 0x40)[0] - QEMU_PHYS_BASE) // (1 << 30)))

    open(f"{out}/ram.bin", "wb").write(img)
    open(f"{out}/stub.bin", "wb").write(make_stub(ba_pa, entry_pa))
    print(f"phys_base={phys_base:#x} boot_args={ba_pa:#x} entry={entry_pa:#x} stub={stub_pa:#x}", file=sys.stderr)

    mon = f"{out}/mon.sock"
    if os.path.exists(mon):
        os.unlink(mon)
    serial_file = f"{out}/serial.txt"
    serial_pos = 0

    cmd = [
        "qemu-system-aarch64",
        "-M", "virt,gic-version=3",
        "-cpu", args.cpu,
        "-smp", "1",
        "-m", f"{ram_gib}G",
        "-nographic",
        "-serial", f"file:{out}/serial.txt",
        "-qmp", f"unix:{mon},server,nowait",
        "-d", "int,guest_errors,unimp",
        "-D", f"{out}/qemu.log",
        "-no-reboot",
        "-device", f"loader,file={out}/ram.bin,addr={phys_base:#x},force-raw=on",
        "-device", f"loader,file={out}/stub.bin,addr={stub_pa:#x},force-raw=on",
        "-device", f"loader,addr={stub_pa:#x},cpu-num=0",
    ]
    if args.ramdisk:
        print(f"ramdisk={args.ramdisk} @ {QEMU_RAMDISK_BASE:#x}", file=sys.stderr)
        cmd += ["-device", f"loader,file={args.ramdisk},addr={QEMU_RAMDISK_BASE:#x},force-raw=on"]
    if args.gdb:
        cmd += ["-S", "-gdb", "tcp::1234"]

    p = None
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        if args.gdb:
            print(f"GDB stub on :1234 ; QMP socket: {mon}", file=sys.stderr)
            p.wait()
            return 0

        t0 = time.time()
        while p.poll() is None and time.time() - t0 < args.secs:
            if args.live_serial:
                serial_pos = stream_serial(serial_file, serial_pos)
            time.sleep(0.2)
        if args.live_serial:
            stream_serial(serial_file, serial_pos)

        result: dict
        if p.poll() is None:
            _, regs, *extra = qmp(
                mon,
                "stop",
                "info registers",
                *args.hmp,
                pmemsave=(FB_BASE, FB_STRIDE * FB_H, f"{out}/fb.raw"),
            )
            open(f"{out}/regs.txt", "w").write(
                regs + "".join(f"\n(qemu) {c}\n{r}" for c, r in zip(args.hmp, extra))
            )
            p.kill()
            p.wait()
            raw = open(f"{out}/fb.raw", "rb").read()
            write_png(f"{out}/fb.png", raw)
            result = {"status": "not_decoded"}
            if font is not None:
                screen, unknown = decode_screen(raw, font)
                open(f"{out}/fb.txt", "w").write(screen)
                result = screen_result(screen, unknown)
            os.unlink(f"{out}/fb.raw")
        else:
            print(f"QEMU exited early: rc={p.returncode}", file=sys.stderr)
            result = {"status": "qemu_exited", "qemu_returncode": p.returncode}

        open(f"{out}/result.json", "w").write(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), file=sys.stderr)
        if result["status"] == "qemu_exited":
            return 1
        if args.fail_on_panic and result["status"] == "panic":
            return 2
        if args.fail_on_panic and result["status"] in ("incomplete_decode", "blank_screen"):
            return 3
        return 0

    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        if p and p.poll() is None:
            p.kill()
            p.wait()
        return 130
    finally:
        for tmp in ("ram.bin",):
            path = f"{out}/{tmp}"
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass


if __name__ == "__main__":
    sys.exit(main())
