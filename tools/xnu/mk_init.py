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
SYS_getpid, SYS_write, SYS_open, SYS_read, SYS_getuid = 20, 4, 5, 3, 24
SYS_mmap, SYS_stat64 = 197, 338
SYS_fork = 2
SYS_getdirentries64 = 344

# The code page and the writable page it writes into.
CODE_VA = 0x100000000 + 0x4000
DATA_VA = 0x100008000


def _movz(rd: int, imm: int, shift: int = 0) -> int:
    """movz <rd>, #imm, lsl #shift (imm fits in 16 bits)."""
    assert 0 <= imm <= 0xFFFF
    assert shift in (0, 16, 32, 48)
    return 0xD2800000 | ((shift // 16) << 21) | (imm << 5) | rd


def _movn(rd: int, imm: int) -> int:
    """movn <rd>, #imm  (the complement form, so -1 is expressible)."""
    assert 0 <= imm <= 0xFFFF
    return 0x92800000 | (imm << 5) | rd


def _movk(rd: int, imm: int, shift: int) -> int:
    """movk <rd>, #imm, lsl #shift  (patch a 16-bit lane into rd)."""
    assert 0 <= imm <= 0xFFFF
    assert shift in (0, 16, 32, 48)
    return 0xF2800000 | ((shift // 16) << 21) | (imm << 5) | rd


def _ldr32(rt: int, rn: int, off: int) -> int:
    """ldr <wt>, [<xn>, #off]  (32-bit, unsigned immediate, off a multiple of 4)."""
    assert off % 4 == 0
    return 0xB9400000 | ((off // 4) << 10) | (rn << 5) | rt


def _lsl(rd: int, rn: int, shift: int) -> int:
    """lsl <xd>, <xn>, #shift  (UBFM with imms = 63-shift, immr = 64-shift)."""
    assert 1 <= shift <= 63
    return (0xD3400000 | ((63 - shift) << 10) | (((64 - shift) & 63) << 16)
            | (rn << 5) | rd)


def _str32(rt: int, rn: int, off: int) -> int:
    """str <wt>, [<xn>, #off]  (32-bit, unsigned immediate, off a multiple of 4)."""
    assert off % 4 == 0
    return 0xB9000000 | ((off // 4) << 10) | (rn << 5) | rt


def _movabs(rd: int, value: int) -> list:
    """Materialise any 64-bit constant: movz for lane 0, movk for the rest."""
    out = [("movz", rd, value & 0xFFFF, 0)]
    for shift in (16, 32, 48):
        lane = (value >> shift) & 0xFFFF
        if lane:
            out.append(("movk", rd, lane, shift))
    return out


def _str(rt: int, rn: int, off: int) -> int:
    """str <rt>, [<rn>, #off]  (64-bit, unsigned immediate, off a multiple of 8)."""
    assert off % 8 == 0
    return 0xF9000000 | ((off // 8) << 10) | (rn << 5) | rt


def _svc(imm: int = 0x80) -> int:
    return 0xD4000001 | (imm << 5)


def _mov(rd: int, rs: int) -> int:
    """mov <rd>, <rs>  (= orr rd, xzr, rs)."""
    return 0xAA0003E0 | (rs << 16) | rd


def _assemble(insns: list, blobs: dict, abs_labels: dict = None,
               code_va: int = 0) -> bytes:
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
            out += struct.pack("<I", _movz(ins[1], ins[2], ins[3] if len(ins) > 3 else 0))
        elif kind == "movk":
            out += struct.pack("<I", _movk(ins[1], ins[2], ins[3]))
        elif kind == "str":
            out += struct.pack("<I", _str(ins[1], ins[2], ins[3]))
        elif kind == "ldr32":
            out += struct.pack("<I", _ldr32(ins[1], ins[2], ins[3]))
        elif kind == "str32":
            out += struct.pack("<I", _str32(ins[1], ins[2], ins[3]))
        elif kind == "lsl":
            out += struct.pack("<I", _lsl(ins[1], ins[2], ins[3]))
        elif kind == "movn":
            out += struct.pack("<I", _movn(ins[1], ins[2]))
        elif kind == "svc":
            out += struct.pack("<I", _svc())
        elif kind == "mov":
            out += struct.pack("<I", _mov(ins[1], ins[2]))
        elif kind == "adr":
            rd, label = ins[1], ins[2]
            if abs_labels and label in abs_labels:
                # Absolute target (the writable __DATA page): the displacement
                # is from this instruction's VA, not from a payload offset.
                delta = abs_labels[label] - (code_va + len(out))
            else:
                delta = labels[label] - len(out)
            immlo = delta & 0x3
            immhi = (delta >> 2) & 0x7FFFF
            out += struct.pack("<I", 0x10000000 | (immlo << 29) | (immhi << 5) | rd)
        elif kind == "b":
            delta = (labels[ins[1]] - len(out)) // 4
            out += struct.pack("<I", 0x14000000 | (delta & 0x3FFFFFF))
        elif kind == "cbz":
            delta = (labels[ins[2]] - len(out)) // 4
            out += struct.pack("<I", 0xB4000000 | ((delta & 0x7FFFF) << 5) | ins[1])
        else:
            raise ValueError(f"unknown instruction {kind}")
    return bytes(out)


MSG = b"XNU_EL0_OK\n"
PATH = b"/dev/console\x00"
LAUNCHDPATH = b"/launchd\x00"

_BLOBS = {"msg": MSG, "path": PATH, "launchdpath": LAUNCHDPATH}

_RAW_CODE = [
    #
    # The payload's whole job is to exercise the BSD layer and report what each
    # call returned.  Every call is stamped by the kernel (0xa6), so the order
    # here is also the reading order of a dump.
    #
    #   getpid  cheapest possible call, no arguments at all
    #   open    namei/VFS on devfs, O_RDWR|O_NONBLOCK so read cannot block
    #   write   copyin a string from EL0, then the vnode write path to cons
    #   read    the receive side of the same tty; -1/EAGAIN is a valid answer
    #   mmap    the first mapping EL0 asks for itself, rather than one the
    #           loader picked from the Mach-O's segments; the store after it
    #           is the first userspace write through an mmap'd page
    #   stat64  the first call that has the kernel write into a page userspace
    #           supplied, and its path comes from the page mmap returned
    #   mach    task_self, thread_self, host_self, mach_reply_port
    #
    ("movz", 16, SYS_getpid), ("svc",),
    ("movz", 16, SYS_open), ("adr", 0, "path"), ("movz", 1, 6), ("svc",),
    ("mov", 19, 0),
    ("movz", 16, SYS_write), ("mov", 0, 19), ("adr", 1, "msg"),
    ("movz", 2, len(MSG)), ("svc",),

    # stat64 is dropped from this payload: it has read the same devfs node
    # (mode 0x2192, ino 0x124) since hw/m340 and the slot is needed below.
    #
    # The Mach side of handle_svc().
    #
    # handle_svc() reads the trap number from x16 and sends anything negative to
    # mach_syscall(); BSD's svc #0x80 only looks like a fixed number because the
    # unix path keeps x16 positive.  These four traps take no arguments and each
    # returns a port name from the task's own IPC space, which needs no IPC
    # object to exist yet: they are the cheapest possible proof that the Mach
    # entry path runs at all, and ports are what launchd bootstraps with.
    #
    #   28 task_self    27 thread_self    29 host_self    26 mach_reply_port
    #
    ("movn", 16, 27), ("svc",),            # 28 task_self
    ("mov", 24, 0),
    #
    # A receive right, a send right for it, and a message that goes out and comes
    # back through two mach_msg2 calls: the mechanism launchd is built on.
    #
    #   16  mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &name)
    #   21  mach_port_insert_right(task, name, name, MACH_MSG_TYPE_MAKE_SEND)
    #   47  mach_msg2_trap  -- the entry point a platform binary must use
    #
    # Legacy trap 31 is refused outright for a platform binary
    # (mach_msg_legacy_allowed), which is the KERN_NOT_SUPPORTED 0x2e that
    # hw/m348 and hw/m350 recorded; trap 47 is the documented replacement.
    #
    ("mov", 0, 24), ("movz", 1, 1), ("adr", 2, "portname"),
    ("movn", 16, 15), ("svc",),                 # 16  allocate receive right
    ("adr", 22, "portname"), ("ldr32", 21, 22, 0),
    ("mov", 0, 24), ("mov", 1, 21), ("mov", 2, 21), ("movz", 3, 20),
    ("movn", 16, 20), ("svc",),                 # 21  MAKE_SEND is 20, not 0
    #
    # Send half: msgh_bits = MACH_MSGH_BITS(COPY_SEND, 0) = 0x13, size 28,
    # remote = the port, local/voucher 0, id 0x22, body 0xcafebabe.
    # hw/m351/m352 received the body but msgh_id 0 where 0x10 was sent.
    #
    ("adr", 23, "mbox"),
    ("movabs", 5, (28 << 32) | 0x13), ("str", 5, 23, 0),
    ("str", 21, 23, 8),
    ("movabs", 5, 0x22 << 32), ("str", 5, 23, 16),
    ("movabs", 6, 0xcafebabe), ("str32", 6, 23, 24),
    ("mov", 0, 23),
    ("movabs", 1, 0x800000001),                 # SEND_MSG | MACH64_SEND_ANY
    ("movabs", 2, (28 << 32) | 0x13),
    ("mov", 3, 21),
    ("movabs", 4, 0x22 << 32),                  # msgh_voucher_and_id: id 0x22
    ("movz", 5, 0),
    ("movz", 6, 0), ("movz", 7, 0),
    ("movn", 16, 46), ("svc",),                 # 47  send
    #
    # Receive half, into a buffer this code zeroes first: anything the record
    # reads back out of it can only have arrived through the port.
    #
    ("adr", 25, "rbox"), ("movz", 5, 0),
    ("str", 5, 25, 0), ("str", 5, 25, 8),
    ("str", 5, 25, 16), ("str", 5, 25, 24),
    ("mov", 0, 25), ("movz", 1, 2),             # RCV_MSG
    ("movz", 2, 0), ("movz", 3, 0), ("movz", 4, 0),
    ("lsl", 5, 21, 32),                         # rcv_name = the port
    #
    # 0x100, not 32: hw/m351 passed exactly the message size (32 for a 28-byte
    # message) and the receive answered MACH_RCV_TOO_LARGE 0x10004004, so the
    # kernel's idea of the size it must copy out is bigger than the header we
    # sent.  The buffer is one page, so giving it room costs nothing.
    ("movz", 6, 0x100), ("movz", 7, 0),
    ("movn", 16, 46), ("svc",),                 # 47  receive
    #
    # Read the image the boot was started from.
    #
    # mockfs resolves exactly three names in its root: "sbin" (itself), "dev"
    # (the devfs mountpoint) and "launchd", the file node backed by the ramdisk.
    # Directories are not openable and readdir is unimplemented, so the file node
    # is the one thing worth opening -- and its first eight bytes are the Mach-O
    # header of this very image, which no other call in the payload can produce.
    #
    ("movz", 16, SYS_open), ("adr", 0, "launchdpath"), ("movz", 1, 0), ("svc",),
    ("mov", 26, 0),
    ("mov", 0, 26), ("adr", 1, "rbuf"), ("movz", 2, 64),
    ("movz", 16, SYS_read), ("svc",),
    #
    # Map the file at an address the payload chooses.
    #
    # execve cannot negotiate: an image's __TEXT goes where its load commands say,
    # which is why this is MAP_FIXED (0x10 | MAP_PRIVATE 0x2) rather than a hint --
    # hw/m358 measured the difference, a hint that drifted 2 GB and a fixed
    # mapping that landed exactly where it was asked.  The 0xb9 record reads the
    # first eight bytes back out of the range, so the check is on the file's
    # contents rather than on the return value.
    #
    ("movz", 0, 0x3, 32),                       # address 0x300000000
    ("movz", 1, 0x4000), ("movz", 2, 1), ("movz", 3, 0x12),
    ("mov", 4, 26), ("movz", 5, 0),
    ("movz", 16, SYS_mmap), ("svc",),
    #
    # fork.
    #
    # The one call that makes a second process without needing a second file,
    # which is exactly what execve would need: mockfs has one file node and no
    # create, so the second process has to be a copy of the first.  The parent
    # returns with the child's pid in x0 and the child returns 0 at the same PC,
    # so both fall into the same getpid loop and the ring carries both answers.
    #
    ("movz", 16, SYS_fork), ("svc",),
    #
    # The first conditional branch in the payload, and the reason it exists.
    #
    # fork's answer is already in x0: 0 in the child, the child's pid in the
    # parent.  Giving each process a different syscall makes the child's arrival
    # visible as a code (getuid, 24) that the parent never issues -- hw/m362
    # could not see the child because the 0xa6 cap of 12 was saturated, and a
    # measurement should not depend on having a spare slot.
    #
    #
    # The two loops use mach traps, not BSD syscalls.
    #
    # hw/m364 could not see the child because the 0xa6 syscall cap was again
    # exactly spent by the time it ran (7 payload calls + 5 parent getpid = 12).
    # Mach traps are recorded by the separate 0xb6 budget, and the trap number
    # itself distinguishes the two processes: 28 (task_self) in the parent,
    # 26 (mach_reply_port) in the child.  A 0xb6 with trap 26 can only come from
    # the child, and neither loop can exhaust the other's budget.
    #
    ("cbz", 0, "kid"),
    "loop", ("movn", 16, 27), ("svc",), ("b", "loop"),      # 28 task_self
    "kid", ("movn", 16, 25), ("svc",), ("b", "kid"),        # 26 mach_reply_port

]
ASM_CODE = _assemble(
    [x for ins in _RAW_CODE for x in (_movabs(ins[1], ins[2])
                                     if ins[0] == "movabs" else [ins])],
    _BLOBS,
    abs_labels={"buf": DATA_VA, "portname": DATA_VA + 0x200,
                "mbox": DATA_VA + 0x400, "rbox": DATA_VA + 0x600,
                "rbuf": DATA_VA + 0x800, "basep": DATA_VA + 0xa00},
    code_va=CODE_VA)

# Pad code + data to 16-byte alignment
#
# Every blob, in the same order _assemble() laid out their labels.  This used to
# read `ASM_CODE + MSG + PATH`, which silently dropped any blob added later: the
# adr still pointed at the label's offset, so the payload read zeros past the end
# of the image and handed the kernel an empty path.  That is what hw/m353, m354
# and m355 recorded as ENOENT for "/dev", "/" and "/launchd" -- three paths that
# were never actually passed.  Building the payload from the dict keeps the two
# orders from drifting apart again.
PAYLOAD = ASM_CODE + b"".join(_BLOBS.values())
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

    sizeofcmds = lc_seg_size * 3 + lc_thread_size
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
        4,              # ncmds (__PAGEZERO, __TEXT, __DATA, LC_UNIXTHREAD)
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

    #
    # LC_SEGMENT_64 __DATA — the writable page stat64 writes into.
    #
    # filesize 0 with a non-zero vmsize is the standard zero-fill form: the
    # loader maps anonymous pages with initprot, nothing is read from the file.
    # The address must not overlap __TEXT, so it is placed at the first page
    # past that segment and checked against the constant the code was assembled
    # with; a mismatch would make every adr point into the wrong page.
    #
    data_vmaddr = entry_va + vm_size
    assert data_vmaddr == DATA_VA, f"__DATA at {data_vmaddr:#x}, code expects {DATA_VA:#x}"
    data = struct.pack('<II16sQQQQiiii',
        LC_SEGMENT_64,
        lc_seg_size,
        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        data_vmaddr,
        PAGE_SIZE,
        0,                    # fileoff
        0,                    # filesize (zero fill)
        7,                    # maxprot (rwx)
        3,                    # initprot (rw-)
        0,                    # nsects
        0,                    # flags
    )
    assert len(data) == lc_seg_size

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
    out[off:off+len(data)] = data; off += len(data)
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
