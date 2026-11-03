#!/usr/bin/env python3
"""Decode the syscall evidence records out of a /proc/last_kmsg dump.

The history ring (sweet_early.c) holds 16 groups x 4 copies of 8 x u64:

    magic "OLXNSS01", idx, seq, tag, a, b, c, d

so a dump carries at most 16 distinct records, each repeated.  This tool scans
for the magic (the ring moves with the console store, so it is found rather
than assumed), dedupes the copies, and prints one row per record in seq order.

    python3 tools/xnu/decode_syscalls.py hw/m346_run/last_kmsg.txt
    python3 tools/xnu/decode_syscalls.py hw/m346_run/last_kmsg.txt --json hw/m346_run/measure.json

Record layouts written by bsd/dev/arm/systemcalls.c:

    0xa6  a = syscall code, b = error, c = 64-bit result, d = user PC
    0xae  a = syscall ordinal, b = code, c = result, d = user PC
    0xaf  a = code, b = error, c = result, d = arg0
    0xb0  a = st_dev | st_mode << 32 | st_nlink << 48, b = st_ino
    0xa7  a = pid, b = proc_pid(current)
    0xa5  a = pid, b = 1 (EL0 entry)

c is the full 64-bit return value: unix_syscall_return() reassembles it from
uu_rval[0..1] for _SYSCALL_RET_ADDR_T, so an address appears whole.  Before
hw/m346 the record took only uu_rval[0], which made mmap()'s 0x10000c000 read
back as 0xc000.
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

MAGIC = struct.pack("<Q", 0x313053534E584C4F)   # "OLXNSS01"

# BSD syscall numbers that appear in the payload (bsd/kern/syscalls.master).
SYSNAMES = {
    2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 7: "wait4",
    20: "getpid", 24: "getuid",
    33: "access", 59: "execve", 73: "munmap", 92: "fcntl",
    116: "gettimeofday", 118: "getrusage", 144: "sysctl", 188: "stat",
    189: "fstat", 197: "mmap", 199: "lseek", 200: "munmap",
    272: "getdirentries", 338: "stat64", 344: "getdirentries64",
}

TAGS = {0xa5: "el0-entry", 0xa6: "syscall", 0xa7: "ident", 0xa8: "arm_init",
        0xae: "sample", 0xaf: "failure", 0xb0: "stat-buffer"}


def decode(path):
    raw = pathlib.Path(path).read_bytes()
    seen = {}
    i = raw.find(MAGIC)
    while i >= 0:
        idx, seq, tag, a, b, c, d = struct.unpack("<QQQQQQQ", raw[i + 8:i + 64])
        seen.setdefault((seq, tag, a, b, c, d), idx)
        i = raw.find(MAGIC, i + 8)
    return [{"seq": s, "tag": t, "a": a, "b": b, "c": c, "d": d, "idx": idx}
            for (s, t, a, b, c, d), idx in seen.items()]


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    recs = decode(argv[1])
    as_json = None
    if "--json" in argv:
        as_json = argv[argv.index("--json") + 1]
    change = argv[argv.index("--change") + 1] if "--change" in argv else ""

    recs.sort(key=lambda r: (r["seq"], r["tag"]))
    print(f"{len(recs)} distinct records")
    print("   seq tag           a                  b                  c                  d")
    for r in recs:
        name = TAGS.get(r["tag"], "?")
        print(f"{r['seq']:>6} {name:<8} {r['a']:#018x} {r['b']:#018x} "
              f"{r['c']:#018x} {r['d']:#018x}")

    calls = []
    for r in recs:
        if r["tag"] != 0xA6:
            continue
        code = r["a"]
        calls.append({"code": code, "name": SYSNAMES.get(code, f"sys{code}"),
                      "error": r["b"], "result": r["c"], "pc": r["d"],
                      "seq": r["seq"]})
    if calls:
        print("")
        for c in calls:
            print(f"{c['code']:>10} {c['name']:<14} {c['error']:>6} "
                  f"{c['result']:#018x} {c['pc']:#018x}")

    if as_json:
        out = {
            "dump": str(argv[1]),
            "change": change,
            "records": len(recs),
            "syscalls": calls,
            "failures": [{"code": r["a"], "name": SYSNAMES.get(r["a"], "?"),
                          "error": r["b"], "arg0": r["d"]}
                         for r in recs if r["tag"] == 0xAF],
            "stat_buffers": [{"w0": r["a"], "st_ino": r["b"]}
                             for r in recs if r["tag"] == 0xB0],
        }
        pathlib.Path(as_json).write_text(json.dumps(out, indent=1) + "\n")
        print(f"\nwrote {as_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
