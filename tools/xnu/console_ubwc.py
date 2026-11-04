#!/usr/bin/env python3
"""Offline end-to-end check: a console-shaped screen through UBWC at panel pitch.

This is the software half of the framebuffer question, kept strictly separate from
panel scanout.  It renders text into a linear ARGB8888 raster exactly the way the
kernel console does (8x16 cells, opaque pixels), encodes that raster with the
UBWC pixel-plane layout in tools/xnu/ubwc_encode.py at the live panel pitch, then
decodes it again and requires byte equality.  Nothing here says the panel would
display it: the metadata plane contents are still undocumented and refused.

Usage:
    python3 tools/xnu/console_ubwc.py --self-check
    python3 tools/xnu/console_ubwc.py --rows 24 --out hw/qemu_baseline/console_ubwc.txt
"""
from __future__ import annotations

import hashlib
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

from tools.xnu import ubwc_encode as ubwc

PANEL_WIDTH = 1472
PANEL_PITCH = 5888
PANEL_HEIGHT = 3120
CELL_W, CELL_H = 8, 16
FG = 0xFFFFFFFF
BG = 0xFF000000

# A tiny 5x7-in-8x16 glyph set, enough to draw a fixed marker string without
# pulling the kernel's iso_font: each entry is 16 rows of 8 pixels, MSB left.
_GLYPHS = {
    "X": (0x00, 0x00, 0x44, 0x44, 0x28, 0x10, 0x28, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    "N": (0x00, 0x00, 0x44, 0x64, 0x54, 0x54, 0x4C, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    "U": (0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    " ": (0x00,) * 16,
}
MARKER = "XNU XNU"


def raster(width: int, height: int, text: str, fg: int = FG, bg: int = BG) -> bytes:
    """Linear ARGB8888 rows of the kernel console's 8x16 glyph cells."""
    if width % CELL_W or height % CELL_H:
        raise ValueError("raster must be whole 8x16 cells")
    buf = bytearray()
    rows = height // CELL_H
    cols = width // CELL_W
    for cy in range(rows):
        line = (text * cols)[:cols] if text else " " * cols
        for gy in range(CELL_H):
            for cx in range(cols):
                bits = _GLYPHS.get(line[cx], _GLYPHS[" "])[gy]
                for gx in range(CELL_W):
                    buf += (fg if bits & (0x80 >> gx) else bg).to_bytes(4, "little")
    return bytes(buf)


def self_check(width: int = PANEL_WIDTH, rows: int = 8) -> int:
    height = rows * CELL_H
    src = raster(width, height, MARKER)
    tiled = ubwc.encode(src, width, height, 4, pitch=PANEL_PITCH)
    back = ubwc.decode(tiled, width, height, 4, pitch=PANEL_PITCH)
    tiny = ubwc.pixel_offsets(width, height, 4, pitch=PANEL_PITCH)
    ok = (back == src
          and len(tiled) == PANEL_PITCH * height
          and len(set(tiny)) == len(tiny)
          and max(tiny) + 4 <= PANEL_PITCH * height)
    print(f"panel pitch      {PANEL_PITCH} (1472 px * 4)")
    print(f"raster           {width}x{height}, {len(src)} bytes, sha256 {hashlib.sha256(src).hexdigest()[:16]}")
    print(f"ubwc pixels      {len(tiled)} bytes, sha256 {hashlib.sha256(tiled).hexdigest()[:16]}")
    print(f"round trip       {'byte-identical' if back == src else 'MISMATCH'}")
    print(f"offset map       {len(set(tiny))}/{len(tiny)} distinct, max+4 {max(tiny)+4} <= {PANEL_PITCH*height}")
    print("verdict          " + ("PASS (software only; not panel evidence)" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--rows", type=int, default=8)
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.out:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self_check(rows=a.rows)
        text = buf.getvalue()
        open(a.out, "w").write(text)
        sys.stdout.write(text)
        return rc
    return self_check(rows=a.rows)


if __name__ == "__main__":
    sys.exit(main())
