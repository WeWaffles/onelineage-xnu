#!/usr/bin/env python3
"""Generate a minimal ARM64 Mach-O init binary for XNU EL0 boot verification.

The binary:
  1. Calls write(1, "XNU_EL0_OK\n", 11) via BSD syscall (svc #0x80, x16=4)
  2. Loops on getpid(2) forever, so the kernel keeps running the syscall path

This proves XNU reached EL0 userspace on the physical device.
Syscall evidence appears in kprintf/serial log, proving the transition happened.
"""
import struct
import sys
from pathlib import Path

MH_MAGIC_64    = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
MH_EXECUTE     = 2
MH_NOUNDEFS    = 1

LC_SEGMENT_64  = 0x19
LC_UNIXTHREAD  = 0x05
ARM_THREAD_STATE64 = 6

PAGE_SIZE = 0x4000  # XNU ARM64 uses 16KB pages

# XNU ARM64 BSD syscall convention (from osfmk/arm/syscall.s):
#   x16 = syscall number, x0..x7 = args, svc #0x80

#
# Syscall sequence.
#
# The first version issued one write(2) and spun, which proved EL0 was reached
# (hw/m196_a1, ring record 0xa5) but exercised almost none of BSD.  Each call
# below walks a different part of the syscall table, and the kernel stamps every
# one it serves (0xa6), so a run reports exactly how far the layer goes:
#
#   getpid(20)          no arguments, no copyin — the cheapest possible call
#   write(4)            copyin a buffer from EL0, then the vnode write path
#   open(5)             copyin a path and run namei/VFS lookup on mockfs
#   getuid(24)          kauth credential path
#
# Numbers from bsd/kern/syscalls.master.  On arm64 the call is svc #0x80 with
# the number in x16 and the arguments in x0..x7.
#
SYS_getpid, SYS_write, SYS_open, SYS_getuid = 20, 4, 5, 24


def _movz(rd: int, imm: int) -> int:
    """movz <rd>, #imm (imm fits in 16 bits)."""
    assert 0 <= imm <= 0xFFFF
    return 0xD2800000 | (imm << 5) | rd


def _svc(imm: int = 0x80) -> int:
    return 0xD4000001 | (imm << 5)


def _mov(rd: int, rs: int) -> int:
    """mov <rd>, <rs>  (= orr rd, xzr, rs)."""
    return 0xAA0003E0 | (rs << 16) | rd


def _assemble(insns: list, blobs: dict) -> bytes:
    """Encode a tiny instruction list; adr targets resolve to instruction labels

    or to a named blob placed after the code.  Every instruction is 4 bytes, so
    the code length is known before the adr displacements are resolved.
    """
    code_len = 4 * sum(1 for i in insns if not isinstance(i, str))
    labels: dict[str, int] = {}
    pc = 0
    for ins in insns:
        if isinstance(ins, str):
            labels[ins] = pc
        else:
            pc += 4
    off = code_len
    for name, blob in blobs.items():
        labels[name] = off
        off += len(blob)

    out = bytearray()
    for ins in insns:
        if isinstance(ins, str):
            continue
        kind = ins[0]
        if kind == "movz":
            out += struct.pack("<I", _movz(ins[1], ins[2]))
        elif kind == "svc":
            out += struct.pack("<I", _svc())
        elif kind == "mov":
            out += struct.pack("<I", _mov(ins[1], ins[2]))
        elif kind == "adr":
            rd, label = ins[1], ins[2]
            delta = labels[label] - len(out)
            immlo = delta & 0x3
            immhi = (delta >> 2) & 0x7FFFF
            out += struct.pack("<I", 0x10000000 | (immlo << 29) | (immhi << 5) | rd)
        elif kind == "b":
            delta = (labels[ins[1]] - len(out)) // 4
            out += struct.pack("<I", 0x14000000 | (delta & 0x3FFFFFF))
        else:
            raise ValueError(f"unknown instruction {kind}")
    return bytes(out)


MSG = b"XNU_EL0_OK\n"
PATH = b"/dev/console\x00"

_BLOBS = {"msg": MSG, "path": PATH}

ASM_CODE = _assemble([
    ("movz", 16, SYS_getpid), ("svc",),
    #
    # fd = open("/dev/console", O_RDWR)
    #
    # O_RDONLY (0) made the write fail with EBADF in hw/m197..m201, which was
    # correct behaviour, not a kernel bug: preparefilewrite() rejects a
    # descriptor without FWRITE.  A console is opened O_RDWR.
    #
    ("movz", 16, SYS_open), ("adr", 0, "path"), ("movz", 1, 2), ("svc",),
    #
    # Write to the descriptor open() returned, not to fd 1.
    #
    # hw/m197_a1 has open("/dev/console") succeeding and returning fd 0, and
    # write(1, ...) failing with EBADF because PID 1 inherits no descriptors.
    # Writing to the fd that was actually opened is what exercises the rest of
    # the path: fileproc -> vnode -> cdevsw -> cons -> km tty -> serial/fbcon.
    #
    ("mov", 19, 0),
    ("movz", 16, SYS_write), ("mov", 0, 19), ("adr", 1, "msg"),
    ("movz", 2, len(MSG)), ("svc",),
    ("movz", 16, SYS_getuid), ("svc",),
    #
    # Keep calling into the kernel instead of spinning at EL0.
    #
    # `b .` left the kernel with nothing to do: no syscall arrived, nothing
    # petted the watchdog, and the board reset about 18 s after that last
    # getuid, with no record saying when.  getpid is the cheapest call in the
    # table, so a loop over it keeps the syscall path hot (and the kernel's
    # heartbeat records arriving) without allocating or copying anything.
    #
    "loop", ("movz", 16, SYS_getpid), ("svc",), ("b", "loop"),
], _BLOBS)

# Pad code + data to 16-byte alignment
PAYLOAD = ASM_CODE + MSG + PATH
PAYLOAD += b'\x00' * ((-len(PAYLOAD)) & 15)


def make_macho(entry_va: int = 0x100000000) -> bytes:
    """Build a minimal ARM64 Mach-O MH_EXECUTE."""
    # Layout within the file:
    # [mach header] [LC_SEGMENT_64 __TEXT] [LC_UNIXTHREAD] [code+msg aligned to PAGE_SIZE]
    MACH_HDR_SIZE    = 32   # mach_header_64: 8 × uint32
    LC_SEG64_NOSECT  = 72   # LC_SEGMENT_64 with 0 sections
    LC_THREAD_SIZE   = 32 + 68 * 2  # header + ARM_THREAD_STATE64

    # Use simple layout: no sections, just segments
    lc_seg_size  = LC_SEG64_NOSECT   # 72 bytes
    lc_thread_size = 16 + (8 + 68 * 2)  # 16 (hdr) + 8 (flavor/count) + 272 (regs) = 296... let me compute properly

    # arm_thread_state64_t (osfmk/mach/arm/_structs.h):
    #   x[29] (232) + fp + lr + sp + pc (4*8) + cpsr (4) + flags (4) = 272 bytes
    # ARM_THREAD_STATE64_COUNT is sizeof()/4 = 68.  The loader validates the
    # count exactly (thread_userstack -> KERN_INVALID_ARGUMENT), so a short
    # state makes load_unixthread return LOAD_FAILURE and exec dies with
    # EXEC_EXIT_REASON_BAD_MACHO (build/qemu-out-v68).
    THREAD_STATE_SIZE = 29 * 8 + 4 * 8 + 8  # = 272
    THREAD_STATE_COUNT = THREAD_STATE_SIZE // 4  # = 68 uint32s

    # LC_UNIXTHREAD: cmd(4) + cmdsize(4) + flavor(4) + count(4) + state(264) = 276 bytes
    lc_thread_size = 4 + 4 + 4 + 4 + THREAD_STATE_SIZE  # = 276

    # Round up to 4-byte boundary (already aligned)
    assert lc_thread_size % 4 == 0

    #
    # __PAGEZERO.
    #
    # load_segment() treats a segment with vmaddr 0, filesize 0 and no access
    # rights as *the* page zero and raises the map's min_offset past it.  An
    # arm64 64-bit image must leave the whole low 4GB unmapped, and
    # load_machfile() fails the exec if the map has no hard page zero:
    #
    #   SWEET macho: no hard page zero (0x100000000)   build/qemu-out-v91
    #
    # Every real binary carries this segment; ours simply never emitted it.
    #
    PAGEZERO_SIZE = 0x100000000

    sizeofcmds = lc_seg_size * 2 + lc_thread_size
    hdrs_size  = MACH_HDR_SIZE + sizeofcmds
    file_off   = (hdrs_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)  # round to page

    code_size  = len(PAYLOAD)

    #
    # One segment must cover file offset 0: load_machfile() rejects an image
    # with no "header segment" (LOAD_BADMACHO, EXEC_EXIT_REASON_BAD_MACHO),
    # because dyld reads the Mach-O headers through that mapping.  So __TEXT
    # starts at file offset 0 / vmaddr entry_va, includes the header and load
    # commands, and the executable entry point is its code page.
    #
    file_size  = file_off + code_size
    vm_size    = (file_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    entry_pc   = entry_va + file_off

    # Mach-O header (mach_header_64 = 32 bytes, 8 fields)
    hdr = struct.pack('<IIIIIIII',
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        MH_EXECUTE,
        3,              # ncmds (__PAGEZERO, __TEXT, LC_UNIXTHREAD)
        sizeofcmds,
        MH_NOUNDEFS,
        0,              # reserved (64-bit only)
    )

    # LC_SEGMENT_64 __PAGEZERO — covers 0..4GB, maps nothing, grants nothing.
    pagezero = struct.pack('<II16sQQQQiiii',
        LC_SEGMENT_64,
        lc_seg_size,
        b'__PAGEZERO\x00\x00\x00\x00\x00\x00',
        0,                    # vmaddr
        PAGEZERO_SIZE,        # vmsize
        0,                    # fileoff
        0,                    # filesize
        0,                    # maxprot  (no access)
        0,                    # initprot (no access)
        0,                    # nsects
        0,                    # flags
    )
    assert len(pagezero) == lc_seg_size

    # LC_SEGMENT_64 __TEXT (no sections)
    # cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4) = 72
    seg = struct.pack('<II16sQQQQiiii',
        LC_SEGMENT_64,
        lc_seg_size,
        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        entry_va,             # vmaddr
        vm_size,              # vmsize
        0,                    # fileoff (uint64) — must map the Mach-O header
        file_size,            # filesize (uint64)
        7,                    # maxprot  (rwx)
        5,                    # initprot (r-x)
        0,                    # nsects
        0,                    # flags
    )
    assert len(seg) == lc_seg_size

    # LC_UNIXTHREAD — ARM_THREAD_STATE64
    # struct: cmd, cmdsize, flavor, count, state[66 uint32s]
    state = bytearray(THREAD_STATE_SIZE)
    # Set PC to the code page, which now lives inside the __TEXT segment.
    # x[0..28]=0, fp=0, lr=0, sp=0, pc=entry_pc, cpsr=0, flags=0
    pc_off = (29 + 3) * 8  # x[0..28]=29, fp=1, lr=1, sp=1 → 32 uint64s before pc
    struct.pack_into('<Q', state, pc_off, entry_pc)

    lc_thread = struct.pack('<IIII', LC_UNIXTHREAD, lc_thread_size,
                            ARM_THREAD_STATE64, THREAD_STATE_COUNT) + bytes(state)
    assert len(lc_thread) == lc_thread_size

    #
    # Assemble file, padded out to the segment's vmsize.
    #
    # The ramdisk is handed to XNU as a memory device (md0) whose size is
    # rounded down to whole blocks, so a file whose length is not a block
    # multiple is truncated: exec then rejects the image with
    #
    #   LOAD_BADMACHO fileoff 0x0 filesize 0x4030 macho_size 0x4000
    #
    # and PID 1 dies with EXEC_EXIT_REASON_BAD_MACHO (build/qemu-out-v85).
    # vmsize is already a page multiple, so writing it out costs only zero
    # padding and makes the device size exact.
    #
    out = bytearray(vm_size)
    off = 0
    out[off:off+len(hdr)] = hdr; off += len(hdr)
    out[off:off+len(pagezero)] = pagezero; off += len(pagezero)
    out[off:off+len(seg)] = seg; off += len(seg)
    out[off:off+len(lc_thread)] = lc_thread
    out[file_off:file_off+len(PAYLOAD)] = PAYLOAD

    return bytes(out)


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('sweet_init_v3.macho')
    entry = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100000000
    data = make_macho(entry_va=entry)
    out_path.write_bytes(data)
    print(f"wrote {out_path} ({len(data)} bytes, entry=0x{entry:x})")


if __name__ == '__main__':
    main()
