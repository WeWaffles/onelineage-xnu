#!/usr/bin/env python3
"""Offline checks for the UBWC pixel-plane layout (Gate C, software side only).

Run: python3 -m unittest tests.test_ubwc -v
"""
from __future__ import annotations

import unittest

from tools.xnu import ubwc_encode as ubwc


def solid(width: int, height: int, value: int, cpp: int = 4) -> bytes:
    return value.to_bytes(cpp, "little") * (width * height)


def gradient(width: int, height: int, cpp: int = 4) -> bytes:
    """Row- and column-dependent, so tile order cannot hide inside one colour."""
    out = bytearray()
    for y in range(height):
        for x in range(width):
            out += ((x * 3 + y * 11) & 0xFF).to_bytes(1, "little")
            out += ((y * 5) & 0xFF).to_bytes(1, "little")
            out += ((x * 7) & 0xFF).to_bytes(1, "little")
            out += bytes([0xFF])
    return bytes(out)


class LayoutConstants(unittest.TestCase):
    def test_block_is_256_bytes_for_32bpp(self):
        self.assertEqual(ubwc.block_dims(4), (16, 4))
        self.assertEqual(16 * 4 * 4, 256)

    def test_block_is_32x8_only_for_8bpp(self):
        self.assertEqual(ubwc.block_dims(1), (32, 8))
        self.assertEqual(32 * 8 * 1, 256)

    def test_macrotile_stride_for_panel_pitch(self):
        # 1472 px * 4 B = 5888 B, the live panel pitch, is 23 units of 256 B.
        self.assertEqual(ubwc.macrotile_stride(5888, 4), 23)

    def test_misaligned_pitch_is_refused(self):
        with self.assertRaises(ValueError):
            ubwc.macrotile_stride(5888 + 4, 4)


class PixelOrder(unittest.TestCase):
    def test_first_pixels_follow_the_2x2_then_x_rule(self):
        # Hand-derived from idx = (x&1) | (y&1)<<1 | ((x>>1)&1)<<2 | ((y>>1)&1)<<3
        # | ((x>>2)&3)<<4, in units of cpp=4 bytes, for block (0, 0).
        base = ubwc.block_offset(0, 0, 4, ubwc.macrotile_stride(256, 4))
        self.assertEqual(base, 0)
        for (x, y), expect in {(0, 0): 0, (1, 0): 4, (2, 0): 16, (3, 0): 20,
                               (0, 1): 8, (1, 1): 12, (4, 0): 64}.items():
            self.assertEqual(ubwc.pixel_index(x, y) * 4, expect, (x, y))

    def test_offsets_are_a_permutation_of_the_macrotile(self):
        # One macrotile is 4x4 blocks of 16x4 px = 64x16 px = 4096 B.
        offs = ubwc.pixel_offsets(64, 16, 4, pitch=64 * 4)
        self.assertEqual(len(offs), 64 * 16)
        self.assertEqual(len(set(offs)), len(offs), "two pixels share a byte offset")
        self.assertEqual(sorted(offs), list(range(0, 4096, 4)),
                         "macrotile must fill its 4096 bytes exactly")


class RoundTrip(unittest.TestCase):
    def check(self, src, width, height, pitch=None):
        tiled = ubwc.encode(src, width, height, 4, pitch=pitch)
        self.assertEqual(ubwc.decode(tiled, width, height, 4, pitch=pitch), src)

    def test_solid_fixture(self):
        self.check(solid(64, 32, 0x11223344), 64, 32)

    def test_gradient_fixture(self):
        self.check(gradient(64, 32), 64, 32)

    def test_pitched_gradient_fixture(self):
        # pitch 96*4 = 384 = 1.5 * 256: refused, so use 128*4 = 512 (2 macrotiles)
        self.check(gradient(64, 32), 64, 32, pitch=128 * 4)

    def test_panel_geometry_is_addressable(self):
        # The real scanout geometry: 1472x3120, pitch 5888.  Full encode of 18 MB
        # is unnecessary here; the offset map alone must stay inside the buffer.
        w, h, pitch = 1472, 3120, 5888
        offs = ubwc.pixel_offsets(w, h, 4, pitch=pitch)
        self.assertEqual(max(offs) + 4, pitch * h)
        self.assertEqual(len(set(offs)), len(offs))


class OrderIsDiscriminated(unittest.TestCase):
    def test_tiled_differs_from_linear_for_gradient(self):
        src = gradient(64, 32)
        self.assertNotEqual(ubwc.encode(src, 64, 32, 4), src)

    def test_solid_cannot_distinguish_order_so_it_is_not_used_for_that(self):
        src = solid(64, 32, 0xFFFFFFFF)
        self.assertEqual(ubwc.encode(src, 64, 32, 4), src,
                         "a solid colour is byte-identical either way; that is why "
                         "the gradient fixture exists")

    def test_wrong_layout_produces_a_different_picture(self):
        # Negative control: treat the tiled buffer as linear rows and it must not
        # look like the original, so a broken layout cannot pass this suite.
        src = gradient(64, 32)
        tiled = ubwc.encode(src, 64, 32, 4)
        self.assertNotEqual(tiled, src, "tiled bytes must differ from linear rows")
        # The layout is pitch-dependent (macrotile_stride = pitch / 256), so the
        # same image at two pitches must not produce the same bytes.  A broken or
        # pitch-ignoring layout fails this.
        self.assertNotEqual(ubwc.encode(src, 64, 32, 4, pitch=256),
                            ubwc.encode(src, 64, 32, 4, pitch=512),
                            "layout must depend on pitch")


if __name__ == "__main__":
    unittest.main()
