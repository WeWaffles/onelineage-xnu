#!/usr/bin/env python3
"""Decode the SWEET stage channel out of a /proc/last_kmsg dump.

The port writes its boot evidence into a reserved region the bootloader carries
into the next boot's last_kmsg (`SWEET_LOG_BASE`, 0x8883F0000 on the phone).
Slots sit at fixed offsets from that base, so a dump is only readable once the
base is known.

Finding the base is the awkward part, because last_kmsg is a *circular* buffer
and the channel is not alone in it: Linux's own log occupies the same buffer, so
the channel ends up interleaved with unrelated text and can straddle the wrap
point. Three anchors are tried, and every candidate is validated against slots
whose contents cannot be coincidence:

  * bsd_init's entry code (0xAA13) at +0x1780 — present on any run that got
    that far;
  * a known kernel_bootstrap_log() name at +0x1788 (16 raw bytes);
  * the entry stub's "XNUKRN1" ring tag at +0x0000.

Validation: +0x17a0 is either zero or a kernel text address, +0x1780 is either
zero or 0xAA13, and the label slot is printable ASCII.

    python3 tools/xnu/read_channel.py /tmp/lk_m163_a1.bin
    python3 tools/xnu/read_channel.py hw/m163_a1/last_kmsg
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import subprocess
import sys

LABELS = [
    b"vm_mem_bootstrap", b"pmap_steal", b"kmem", b"zalloc", b"percpu",
    b"event", b"codesigning", b"ktrace", b"oslog", b"machine_init",
    b"sched_init", b"console_init", b"PE_lockdown_iokit", b"task_init",
    b"thread_init", b"early_boot", b"mapping_free_prime",
]

# The kernel is linked at 0xfffffff007004000; anything else in the hook slot
# means the candidate base is wrong.
KERNEL_VA_LO = 0xFFFF_FFF0_0000_0000
KERNEL_VA_HI = 0xFFFF_FFF1_0000_0000

STAGES = {
    0x71: "pmap steals done",
    0x72: "pmap_free_pages returned",
    0x73: "bucket counts computed",
    0x74: "buckets and locks stolen",
    0x75: "entering pmap_startup",
    0x76: "pmap_startup returned",
    0x77: "vm_page_bootstrap complete",
    0x81: "entering kmem_scramble_ranges",
    0x82: "scramble returned",
    0x83: "entering pmap_init",
    0x84: "pmap_init returned",
    0x85: "kmem_metadata_init returned",
    0x86: "kmem_sizeclass_init returned",
    0x87: "inside kmem_metadata_init (before suballoc)",
    0x88: "a metadata suballoc returned",
}

IOFIND = {
    0xE001: "IOFindBSDRoot entered", 0xE002: "entering the 30s IOBSD wait",
    0xE003: "the IOBSD wait returned", 0xE004: "rd/rootdev parsed",
    0xE005: "/chosen found", 0xE006: "ramdisk mdevadd() done",
    0xE007: "about to mdevlookup()", 0xE008: "mdevlookup() returned",
    0xE00F: "IOFindBSDRoot returning",
}


class Channel:
    """Wrap-aware view of the channel inside a last_kmsg dump."""

    def __init__(self, dump: bytes, base: int):
        self.dump = dump
        self.base = base
        self.n = len(dump)

    def raw(self, off: int, length: int) -> bytes:
        start = (self.base + off) % self.n
        if start + length <= self.n:
            return self.dump[start:start + length]
        head = self.dump[start:]
        return head + self.dump[:length - len(head)]

    def q(self, off: int) -> int:
        return struct.unpack("<Q", self.raw(off, 8))[0]

    def text(self, off: int, length: int = 16) -> str:
        return self.raw(off, length).split(b"\0")[0].decode("latin1", "replace")


def valid(dump: bytes, base: int) -> bool:
    ch = Channel(dump, base)
    if ch.q(0x17A0) not in (0,) and not KERNEL_VA_LO <= ch.q(0x17A0) < KERNEL_VA_HI:
        # A wrapped read of the wrong base can still land on a plausible value,
        # so require the *pair* to agree: entered implies ret is either the same
        # function (returned) or zero (still inside it).
        return False
    if ch.q(0x1780) not in (0, 0xAA13):
        return False
    label = ch.raw(0x1788, 16)
    if label.strip(b"\0") and not all(0x20 <= c < 0x7F or c == 0 for c in label):
        return False
    return True


MAGIC = b"OLXNCHAN"
MAGIC_SLOT = 0x1A30

# sweet_early_evidence() mirrors one snapshot at 16 places, 256 bytes apart, so
# the newest one can be found and read without knowing where the channel starts.
# "OLXNSS01" as it appears in RAM.  (sweet_early.c spells the constant with one
# hex digit too many, so the literal overflows a u64 and clang truncates it; this
# is the value that actually lands, taken from hw/m187_a1's ring.)
EVIDENCE_MAGICS = (struct.pack("<Q", 0x313053534E584C4F),)
EVIDENCE_MAGIC = EVIDENCE_MAGICS[0]
EVIDENCE_STAGES = {
    # exec of PID 1: a = magic<<32 | image size, b = filetype, c = ncmds,
    # d = sizeofcmds (0x9e);  a = va_data_size, b = va_mode, c = mnt_flag (0x9f)
    0xAD: "boot heartbeat (syscalls, ticks since first pet, cntfrq, pets)",
    0x9E: "exec: mach-o header seen by the loader",
    0x9F: "exec: vnode attributes (size/mode/mnt_flag)",
    0x71: "pmap steals done", 0x72: "pmap_free_pages returned",
    0x73: "bucket counts computed", 0x76: "pmap_startup returned",
    0x77: "vm_page_bootstrap complete", 0x81: "entering kmem_scramble_ranges",
    0x82: "scramble returned", 0x83: "entering pmap_init",
    0x84: "pmap_init returned", 0x85: "kmem_metadata_init returned",
    0x89: "writing the new metadata submap", 0x8A: "first meta front written",
    0x8C: "second meta front written", 0x90: "pmap_startup entry numbers",
    0x91: "pmap_startup page release",
    # The pmap_startup loop stamps.  0x93 comes every 0x200 frames, so the last
    # one in a dump is the frontier: a run that stops between two of them died
    # in vm_page_init()/fillPage() for the frame named in `c`.
    0x92: "pmap_startup vm_pages[] stolen",
    0x93: "pmap_startup loop (a=i b=count c=phys_page)",
    0x94: "pmap_startup loop done (a=count b=i)",
    # A pair per STARTUP() entry, from kern/startup.c.  The newest snapshot in a
    # dump therefore names the startup function the boot died in.
    0x95: "STARTUP entry (a=func b=subsystem c=rank)",
    0x96: "STARTUP returned (a=func b=subsystem c=rank)",
    # Bootstrap progress labels (kern/startup.c).  `a` is the label's own
    # pointer, so it resolves against the kernel's strings with no base.
    0x97: "bootstrap label:",
    0x98: "startup phase list complete (a=phase)",
    0x99: "vm_set_restrictions (a=31 before / 32 after)",
    0x9A: "kperf_init_early (a=33 before / 34 after)",
    0x9B: "bsd_init (a=1 entering / 2 returned)",
    0x9C: "bsd_init phase:",
    0x9D: "IOFindBSDRoot stage (a=code b=arg)",
    # The display SMMU survey (osfmk/arm64/sweet_smmu.c).  The b8/b9 pairs are
    # one per context bank with translation enabled; the context bank whose
    # largest contiguous run is the size of a framebuffer (1472*3120*4 =
    # 0x1185000) is the display's.
    0xB5: "SMMU: ml_io_map of the apps SMMU failed",
    0xB6: "SMMU IDs (a=ID0|ID1<<32 b=ID2|ID7<<32 c=numcb d=pgshift)",
    0xB7: "SMMU context bank (a=cb b=SCTLR c=TTBR0 d=TCR)",
    0xB8: "SMMU CB mappings (a=cb b=total bytes c=largest run bytes d=run IOVA)",
    0xB9: "SMMU CB leaves (a=cb b=first raw descriptor c=leaves d=run first PA)",
    0xBA: "SMMU banks found (a=found b=fb PA c=fb bytes d=chosen run bytes)",
    0xBB: "SMMU chose display run (a=cb b=IOVA c=bytes d=PA)",
    0xBC: "SMMU repointed run (a=descs b=bytes c=skipped d=our fb PA)",
    0xBD: "SMMU after repoint (a=desc before b=desc after c=first IOVA d=TLBSYNC)",
    0xBE: "SMMU display run (a=IOVA b=bytes c=first PA d=descriptors)",
    0xBF: "console ink (a=chars drawn b=foreground pixels c=rows d=first pixels)",
    # pmap_map_bd() runs out of boot VA space: a=virt b=start c=end d=prot.
    0xC0: "pmap_map_bd FAILED (a=virt b=pa start c=pa end d=prot)",
    # Early I/O mappings of more than 4 MB, from io_map().
    0xC1: "io_map large request (a=pa b=bytes c=flags d=startup_phase)",
    0xC2: "io_map large mapped (a=VA b=bytes c=submap max d=submap size)",
    # The framebuffer console's first touch of its alias (pe_serial.c).
    0xC3: "fbcon clear starting (a=rows b=cols c=base VA d=stride)",
    0xC4: "fbcon clear finished (a=px0 b=px stride)",
    # The framebuffer's cached physmap alias (pe_serial.c).
    0xC5: "fbcon cached alias (a=fb PA b=alias VA c=bytes d=first word)",
    # arm_init's steps after the console starts printing.
    0xD1: "arm_init: serialmode parsed",
    0xD2: "arm_init: PE_create_console returned",
    0xD3: "arm_init: PE_init_printf returned",
    0xD4: "arm_init: cpu_machine_idle_init returned",
    0xD5: "arm_init: PE_init_platform returned",
    0xD6: "arm_init: ml_map_cpu_pio returned",
    0xD7: "arm_init: cpu_timebase_init returned",
    0xD8: "arm_init: PE_init_cpu returned",
    0xD9: "arm_init: fiq_context_init returned",
    0xDA: "arm_init: DRAM base/size read (a=base b=size)",
    0xC6: "fbcon char (a=chars b=last char c=col | row<<32)",
}

# Snapshots whose `a` is a kernel text address.
FUNC_STAGES = (0x95, 0x96)
# Snapshots whose `a` is a pointer to a string constant.
STRING_STAGES = (0x97, 0x9C)


def read_evidence(dump: bytes, sym: Symbols | None = None) -> list[str]:
    """Return every readable snapshot, newest last; needs no base at all."""
    snapshots: dict[int, dict] = {}

    start = 0
    while True:
        hits = [o for o in (dump.find(m, start) for m in EVIDENCE_MAGICS) if o >= 0]
        if not hits:
            break
        off = min(hits)
        start = off + 1
        if off + 0x40 > len(dump):
            continue
        index, seq, stage, a, b, c, d = struct.unpack_from("<7Q", dump, off + 8)
        if index >= 64:
            continue
        entry = snapshots.setdefault(seq, {"stage": stage, "args": (a, b, c, d),
                                          "copies": 0, "index": index, "off": off})
        if (entry["stage"], entry["args"]) == (stage, (a, b, c, d)):
            entry["copies"] += 1

    out = []
    for seq in sorted(snapshots):
        snap = snapshots[seq]
        if snap["copies"] < 2:
            continue
        stage, (a, b, c, d) = snap["stage"], snap["args"]
        name = EVIDENCE_STAGES.get(stage, "?")
        who = ""
        if sym is not None and a:
            if stage in FUNC_STAGES:
                who = f"  {sym.at(a)}"
            elif stage in STRING_STAGES:
                text = sym.string_at(a)
                who = f"  {text!r}" if text else f"  {sym.at(a)}"
        out.append(f"  seq {seq:2d} copy {snap['index']:2d} x{snap['copies']}  "
                   f"stage {stage:#x} ({name}){who}\n"
                   f"            a={a:#x} b={b:#x} c={c:#x} d={d:#x}")
    return out or ["no evidence snapshot in this dump (or all copies clobbered)"]


def segments(binary: pathlib.Path) -> list[tuple[int, int, int]]:
    data = binary.read_bytes()
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, out = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            vmaddr, vmsize, foff = struct.unpack_from("<3Q", data, off + 24)
            out.append((vmaddr, vmsize, foff))
        off += size
    return out


def read_cstring(data: bytes, segs, va: int) -> str | None:
    for vmaddr, vmsize, foff in segs:
        if vmaddr <= va < vmaddr + vmsize:
            chunk = data[foff + (va - vmaddr):][:64].split(b"\0")[0]
            if chunk and all(0x20 <= c < 0x7F or c in (9, 10) for c in chunk):
                return chunk.decode("latin1")
    return None


class Symbols:
    def __init__(self, binary: pathlib.Path):
        self.binary = binary
        self.syms: list[tuple[int, str]] = []
        if binary.exists():
            out = subprocess.run(["nm", "-n", str(binary)],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) != 3:
                    continue
                try:
                    self.syms.append((int(parts[0], 16), parts[2]))
                except ValueError:
                    continue
        self.data = binary.read_bytes() if binary.exists() else b""
        self.segs = segments(binary) if binary.exists() else []

    def at(self, va: int) -> str:
        best = None
        for addr, name in self.syms:
            if addr <= va:
                best = (addr, name)
            else:
                break
        if not best:
            return f"{va:#x}"
        return f"{best[1]}+{va - best[0]:#x}"

    def string_at(self, va: int) -> str | None:
        return read_cstring(self.data, self.segs, va)


def find_base(dump: bytes) -> int:
    """Return the file offset of the channel's first byte, or -1."""
    n = len(dump)

    # The entry stub writes its identity at MAGIC_SLOT, so a dump that has one
    # is unambiguous.
    start = 0
    while True:
        off = dump.find(MAGIC, start)
        if off < 0:
            break
        base = (off - MAGIC_SLOT) % n
        if Channel(dump, base).q(MAGIC_SLOT + 8) == MAGIC_SLOT:
            return base
        start = off + 1

    # A rotated dump need not keep u64 alignment. Validate the entry tag
    # against a duplicated proof record rather than accepting printable text.
    for match in __import__("re").finditer(b"XNUKRN1", dump + dump[:6]):
        base = match.start()
        if base >= n:
            continue
        if not valid(dump, base):
            continue
        ch = Channel(dump, base)
        for slot in range(0, 14, 2):
            left = struct.unpack("<8Q", ch.raw(0x600 + slot * 0x100, 64))
            right = struct.unpack("<8Q", ch.raw(0x600 + (slot + 1) * 0x100, 64))
            if (left[0] == right[0] == 0x313053534E584C4F and
                    left[1] == slot and right[1] == slot + 1 and
                    left[2:] == right[2:]):
                return base

    # Fall back to the label slot and the bsd_init code for dumps that predate
    # the identity record.
    candidates: list[int] = []
    for off in range(0, n - 8, 8):
        if struct.unpack_from("<Q", dump, off)[0] == 0xAA13:
            candidates.append((off - 0x1780) % n)
    for label in LABELS:
        pad = label.ljust(8, b"\0")
        start = 0
        while True:
            off = dump.find(pad, start)
            if off < 0:
                break
            candidates.append((off - 0x1788) % n)
            start = off + 1
    for base in candidates:
        if valid(dump, base):
            return base
    return -1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", type=pathlib.Path)
    ap.add_argument("--sym", type=pathlib.Path,
                    default=pathlib.Path("build/xnu-build/sym/kernel.development.sweet"))
    args = ap.parse_args()

    dump = args.dump.read_bytes()
    sym = Symbols(args.sym)
    for line in read_evidence(dump, sym):
        print(line)
    print()
    base = find_base(dump)
    if base < 0:
        print("no channel found: no anchor validates in this dump", file=sys.stderr)
        return 1
    ch = Channel(dump, base)

    print(f"channel base = file offset {base:#x} (buffer {len(dump):#x})")
    print(f"0x1780  bsd_init entered          = {ch.q(0x1780):#x}")
    print(f"0x1788  last bootstrap label      = {ch.text(0x1788)!r}")
    hook, ret = ch.q(0x17A0), ch.q(0x17A8)
    print(f"0x17a0  last hook entered         = {hook:#x}  ({sym.at(hook) if hook else '-'})")
    print(f"0x17a8  last hook that returned   = {ret:#x}  ({sym.at(ret) if ret else '-'})")
    print(f"0x17b0  vm_set_restrictions       = {ch.q(0x17B0):#x}")
    print(f"0x17b8  kperf_init_early          = {ch.q(0x17B8):#x}")
    print(f"0x17c0  IRQ count                 = {ch.q(0x17C0)}")
    print(f"0x17c8  last INTID                = {ch.q(0x17C8):#x}")

    phase = ch.q(0x17D0)
    if phase:
        literal = sym.string_at(phase)
        print(f"0x17d0  bsd_init phase            = {phase:#x}  ({literal!r})" if literal
              else f"0x17d0  bsd_init phase            = {phase:#x}  ({sym.at(phase)})")

    io = ch.q(0x17E0)
    print(f"0x17e0  IOFindBSDRoot stage       = {io:#x}"
          f"  ({IOFIND.get(io, 'never entered' if io == 0 else '?')})")
    if io:
        cntpct = ch.q(0x17E8)
        arg = ch.q(0x17F0).to_bytes(8, "little")
        printable = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in arg)
        print(f"0x17e8  CNTPCT at that stage      = {cntpct}  ({cntpct / 19.2e6:.3f} s)")
        print(f"0x17f0  stage argument            = {ch.q(0x17F0):#x}  {printable!r}")
        print(f"0x17f8  ramdisk page range        = {ch.q(0x17F8):#x}")

    entry, last = ch.q(0x1B00), ch.q(0x1848)
    if entry and last > entry:
        print(f"0x1848  last hook time            = {last / 19.2e6:.3f} s"
              f" after kernel entry ({(last - entry) / 19.2e6:.3f} s elapsed)")

    vm = ch.q(0x1800)
    if vm:
        print(f"0x1800  vm_page_bootstrap stage   = {vm:#x}  ({STAGES.get(vm, '?')})")
        print(f"0x1808  pmap_free_pages()         = {ch.q(0x1808):#x} pages")
        print(f"0x1810  vm_page_bucket_count      = {ch.q(0x1810):#x}")
        print(f"0x1818  vm_page_bucket_lock_count = {ch.q(0x1818):#x}")
        print(f"0x1820  vm_page_buckets           = {ch.q(0x1820):#x}")
        print(f"0x1828  virtual_space_start       = {ch.q(0x1828):#x}")
        print(f"0x1830  virtual_space_end         = {ch.q(0x1830):#x}")
        print(f"0x1838  vm_page_free_count        = {ch.q(0x1838)}")
        print(f"0x1840  vm_page_wire_count        = {ch.q(0x1840)}")

    kmem = ch.q(0x1860)
    if kmem:
        print(f"0x1860  kmem stage                = {kmem:#x}  ({STAGES.get(kmem, '?')})")
        print(f"0x1870  metadata loop i           = {ch.q(0x1870):#x}"
              f"  (kmem_ptr_ranges {ch.q(0x1878):#x})")
        print(f"0x1880  kmem_meta_size            = {ch.q(0x1880):#x}")
        print(f"0x1888  suballoc addr in          = {ch.q(0x1888):#x}")
        print(f"0x1890  suballoc result           = {ch.q(0x1890):#x}")

    if ch.q(0x900) or ch.q(0x910):
        print("--- kmem_add_extra_claims ---")
        for off, name in ((0x900, "largest_free_size"), (0x908, "total_claims"),
                          (0x910, "kmem_ptr_ranges"), (0x918, "ptr_range_size"),
                          (0x920, "sprayqtn_range_size"), (0x928, "data_range_size"),
                          (0x930, "kernel_map min"), (0x938, "kernel_map max"),
                          (0x940, "ptr_range_size after claims"),
                          (0x948, "kmem_meta_size"), (0x950, "kmem_claim_count")):
            print(f"0x{off:03x}  {name:28s}= {ch.q(off):#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
