#!/usr/bin/env python3
"""
Field-by-field diff of the DPU's SSPP register blocks against a known-linear pipe.

The panel shows bars although the console pipes read linear in the five words
B1 covered, so the question is which *other* register field differs from a pipe
the DPU demonstrably draws linearly. Two sources are combined:

  console pipes  0xc6000 / 0xc8000 - 1024 raw registers each, dumped by the
                 kernel (pe_serial.c, SWEET_DUMP_P0/P1) into the log region at
                 +0x190000 / +0x191000, carved back out here.

  reference      0xb4000 - the 320x780 AR24 layer, reconstructed from the
                 vendor driver's own register-write log
                 (hw/display_probe/evt_full.txt: "value offset" per write, last
                 write wins).  Not read from XNU on purpose: hw/m306 tried that
                 and the board died on the read, because that SSPP is powered
                 down between frames.

    python3 tools/xnu/dpu_diff.py hw/m307_run/last_kmsg.txt \
        --ref-from-evt hw/display_probe/evt_full.txt --json hw/dpu_diff_m307.json

Naming caveat: only the five offsets in KNOWN are verified against this port's
own linear-vs-UBWC comparison (M26). Everything else is reported by offset with
a guess at the *kind* of value, not a register name, because a wrong name is
worse than an offset.
"""

import argparse
import json
import pathlib
import re
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import read_channel  # noqa: E402

# Console pipe blocks inside the log region: before and after the reference
# set is applied, so a field this pass changed is visible as a difference
# between the two dumps rather than inferred from the readback alone.
DUMPS = {"pre_p0": 0x190000, "pre_p1": 0x191000,
         "post_p0": 0x192000, "post_p1": 0x193000}
WORDS = 0x400
REF_BLOCK = 0xB4000

KNOWN = {
    0x0000: "format word: bit31 = tiled/UBWC, low bits = pixel format id",
    0x0001: "format word (byte view)",
    0x0004: "unpack / channel order",
    0x0008: "component depth (0 = 8-bit, 1 = 10-bit)",
    0x0020: "source width/height or stride-adjacent geometry",
    0x005c: "stride: bit23 = tiled, low 23 bits = pitch in bytes",
    0x0078: "misc / id (9 linear vs 15 UBWC)",
    0x0080: "fetch / unpack config candidate",
    0x0084: "fetch / unpack config candidate",
    0x0090: "fetch config candidate",
}

EVT_LINE = re.compile(
    r"sde_reg_write:.*?=>\[[^\]]*\]\[(\d+)\]:\[[^\]]*\]:(\d+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*$")


def parse_evt(path: pathlib.Path, block: int = REF_BLOCK) -> dict:
    """Last value the driver wrote to each 32-bit register in `block`."""
    table = {}
    if not path.exists():
        return table
    for line in path.read_text(errors="ignore").splitlines():
        m = EVT_LINE.search(line)
        if not m:
            continue
        _pid, _ctx, value, offset = m.groups()
        off = int(offset, 16)
        if block <= off < block + WORDS * 4:
            table[off - block] = int(value, 16)
    return table


def carve(dump: bytes, base: int, off: int, words: int = WORDS) -> list:
    ch = read_channel.Channel(dump, base)
    return [struct.unpack("<I", ch.raw(off + i * 4, 4))[0] for i in range(words)]


def kind(value: int) -> str:
    if value == 0:
        return "zero"
    if 0x0E000000 <= value <= 0x0FFFFFFF:
        return "iova-like"
    if 0x80000000 <= value <= 0x8FFFFFFF:
        return "pa-like"
    if 0xAB000000 <= value <= 0xBFFFFFFF:
        return "pa-like32"
    if value < 0x10000:
        return "small"
    return ""


def diff(dump: bytes, base: int, ref: dict) -> dict:
    blocks = {k: carve(dump, base, v) for k, v in DUMPS.items()}
    broken = {k: (blocks[k][0] >> 16) == 0xDEAD for k in blocks}
    rows = []
    for i in range(WORDS):
        off = i * 4
        pre0, pre1 = blocks["pre_p0"][i], blocks["pre_p1"][i]
        post0, post1 = blocks["post_p0"][i], blocks["post_p1"][i]
        r = ref.get(off)
        if r is None and pre0 == 0 and pre1 == 0 and post0 == 0 and post1 == 0:
            continue          # neither source says anything about this word
        if r is not None and pre0 == pre1 == post0 == post1 == r:
            continue          # console pipes already match the reference
        rows.append({
            "offset": f"0x{off:04x}",
            "ref_0xb4000": None if r is None else f"0x{r:08x}",
            "pre_p0": f"0x{pre0:08x}",
            "pre_p1": f"0x{pre1:08x}",
            "post_p0": f"0x{post0:08x}",
            "post_p1": f"0x{post1:08x}",
            "changed_this_pass": (pre0, pre1) != (post0, post1),
            "matches_reference_after": r is not None and post0 == post1 == r,
            "known": KNOWN.get(off, ""),
            "kinds": f"{kind(r) if r is not None else '-'}/{kind(post0)}/{kind(post1)}",
        })
    return {
        "dump_bytes": len(dump), "channel_base": base,
        "block_dump_failed": broken,
        "reference_fields_known": len(ref),
        "differing_fields": len(rows),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", type=pathlib.Path)
    ap.add_argument("--ref-from-evt", type=pathlib.Path, default=None)
    ap.add_argument("--json", type=pathlib.Path, default=None)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    dump = args.dump.read_bytes()
    base = read_channel.find_base(dump)
    if base < 0:
        print("no channel base in this dump", file=sys.stderr)
        return 1
    ref = parse_evt(args.ref_from_evt) if args.ref_from_evt else {}
    res = diff(dump, base, ref)
    print(f"channel base {base:#x}; reference fields recovered from the driver "
          f"log: {res['reference_fields_known']}; {res['differing_fields']} "
          f"offsets differ from the reference")
    if any(res["block_dump_failed"].values()):
        print(f"BLOCK DUMP FAILED: {res['block_dump_failed']}")
    print(f"{'offset':8s} {'ref 0xb4000':>12s} {'pre p0':>10s} {'pre p1':>10s} "
          f"{'post p0':>10s} {'post p1':>10s}  note")
    shown = res["rows"] if args.all else res["rows"][:70]
    for r in shown:
        note = r["known"]
        if r["changed_this_pass"]:
            note = (note + " | CHANGED THIS PASS").strip(" |")
        if r["matches_reference_after"]:
            note = (note + " | now matches reference").strip(" |")
        print(f"{r['offset']:8s} {str(r['ref_0xb4000'] or 'unknown'):>12s} "
              f"{r['pre_p0']:>10s} {r['pre_p1']:>10s} "
              f"{r['post_p0']:>10s} {r['post_p1']:>10s}  {note}")
    if not args.all and len(res["rows"]) > len(shown):
        print(f"... {len(res['rows']) - len(shown)} more, use --all")
    if args.json:
        args.json.write_text(json.dumps(res, indent=2))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
