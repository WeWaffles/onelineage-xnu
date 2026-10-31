#!/usr/bin/env python3
"""Verify a .ko against the SM-S948U running kernel's module ABI.

Two independent checks:
  1. vermagic string must match the running kernel exactly.
  2. every symbol the module imports must carry the same CRC as Samsung's
     own shipped modules for this build.
"""
import json
import os
import re
import subprocess
import sys

MODNAME_LEN = 64  # 8-byte crc + 56-byte name in struct modversion_info


def _read_section(path, section):
    out = subprocess.run(["readelf", "-x", section, path],
                         capture_output=True, text=True).stdout
    data = bytearray()
    for line in out.splitlines():
        m = re.match(r"\s+0x[0-9a-f]+\s((?:[0-9a-f]{8}\s+){1,4})", line)
        if not m:
            continue
        for grp in m.group(1).split():
            data += bytes.fromhex(grp)
    return bytes(data)


def versions(path):
    data = _read_section(path, "__versions")
    found = {}
    for i in range(0, len(data) - MODNAME_LEN + 1, MODNAME_LEN):
        e = data[i:i + MODNAME_LEN]
        crc = int.from_bytes(e[:8], "little")
        name = e[8:].split(b"\x00")[0].decode(errors="replace")
        if name:
            found[name] = crc
    return found


def vermagic(path):
    out = subprocess.run(["readelf", "-p", ".modinfo", path],
                         capture_output=True, text=True).stdout
    m = re.search(r"vermagic=([^\x00\n]+)", out)
    return m.group(1).strip() if m else None


def harvest(directory, out_json):
    table, sources = {}, {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".ko"):
            continue
        try:
            v = versions(os.path.join(directory, name))
        except Exception:
            continue
        for sym, crc in v.items():
            table.setdefault(sym, {})
            entry = table[sym].setdefault(crc, [])
            entry.append(name)
            sources.setdefault(sym, set()).add(crc)
    summary = {s: {hex(c): v for c, v in crcs.items()} for s, crcs in table.items()}
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=1, sort_keys=True)
    conflicting = {s: [hex(c) for c in cs] for s, cs in sources.items() if len(cs) > 1}
    print(f"harvested {len(table)} symbols from {len(os.listdir(directory))} files")
    print(f"symbols with conflicting CRCs across shipped modules: {len(conflicting)}")
    return summary


def verify(ko, table_json, expected_vermagic):
    ok = True
    vm = vermagic(ko)
    print(f"module: {ko}")
    print(f"  vermagic: {vm}")
    if vm != expected_vermagic:
        print(f"  FAIL vermagic mismatch")
        print(f"       expected: {expected_vermagic}")
        ok = False
    else:
        print(f"  OK  vermagic matches running kernel")
    table = json.load(open(table_json))
    v = versions(ko)
    print(f"  imports: {len(v)} versioned symbols")
    unknown, mismatch = [], []
    for sym, crc in sorted(v.items()):
        known = table.get(sym)
        if not known:
            unknown.append(sym)
        elif hex(crc) not in known:
            mismatch.append((sym, hex(crc), list(known)))
    for sym, crc, known in mismatch:
        print(f"  FAIL {sym}: module {crc} != device {known}")
        ok = False
    if unknown:
        print(f"  note: {len(unknown)} symbols not present in any shipped module: "
              f"{', '.join(unknown[:8])}{' ...' if len(unknown) > 8 else ''}")
    print("  RESULT:", "ABI MATCH" if ok else "ABI MISMATCH")
    return ok


if __name__ == "__main__":
    if sys.argv[1] == "harvest":
        harvest(sys.argv[2], sys.argv[3])
    else:
        sys.exit(0 if verify(sys.argv[2], sys.argv[3], sys.argv[4]) else 1)
