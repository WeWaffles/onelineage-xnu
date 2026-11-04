#!/usr/bin/env python3
"""Does this dump contain this run's kernel nonce?

XNU's first instructions store a tagged record at channel+0x1c00:

    +0x1c00  "XNUNONC1"
    +0x1c08  x0 — the boot_args address this run was given
    +0x1c10  MPIDR_EL1 — the core that arrived

The tag matters: an untagged u64 is not searchable in practice, because Android
log records carry 64-bit timestamps in the same numeric range as DRAM addresses
(hw/m185_a1 matched 0xada3ec000 inside binary log metadata).  The boot_args
address is chosen fresh by the driver for every run, so finding *this* value
under *this* tag proves that run's kernel executed — the fixed markers cannot,
since an older boot left byte-identical ones in the same preserved RAM.
"""
from __future__ import annotations

import pathlib
import re
import struct
import sys

TAG = b"XNUNONC1"
TAG_OFF = 0x1C00

dump_path = pathlib.Path(sys.argv[1])
log_path = pathlib.Path(sys.argv[2])

log = log_path.read_text()
m = re.search(r"\bba=(0x[0-9a-f]+)", log)
if not m:
    print("no boot_args address in the driver log")
    raise SystemExit(2)
ba = int(m.group(1), 16)

dump = dump_path.read_bytes()
print(f"boot_args=0x{ba:x}")

hit = -1
start = 0
while True:
    off = dump.find(TAG, start)
    if off < 0:
        break
    if struct.unpack_from("<Q", dump, off + 8)[0] == ba:
        hit = off
        break
    start = off + 1

if hit < 0:
    print("nonce absent: this run's kernel never reached its first instruction")
    raise SystemExit(1)

base = (hit - TAG_OFF) % len(dump)
mpidr = struct.unpack_from("<Q", dump, hit + 16)[0]
print(f"nonce at 0x{hit:x} -> channel base 0x{base:x}, arrived on MPIDR 0x{mpidr:x}")

for name, delta in (("XNUKRN1", 0x0000), ("OLXNCHAN", 0x1A30),
                    ("XNUJMP3", 0x0020), ("XNUJMP4", 0x0030),
                    ("XNUJMP2", 0x0028), ("XNUJMP5", 0x0068),
                    ("XNUJMP6", 0x0070), ("XNOSL01", 0x0040)):
    at = (base + delta) % len(dump)
    print(f"  +0x{delta:04x} {name:9s} {dump[at:at+8]!r}")
raise SystemExit(0)
