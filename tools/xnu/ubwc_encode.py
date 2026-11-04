#!/usr/bin/env python3
"""UBWC (fourcc_mod_code(QCOM, 1)) uncompressed pixel-plane tiling: encode + decode.

Every constant and formula here comes from Mesa's freedreno tiled-memcpy helper,
read on 2026-11-04:

  src/freedreno/fdl/fd6_tiled_memcpy.cc
  https://git.userevolt.app/intel-hard/intel-hard-graphics/raw/commit/4d12fc3ec6ee8efdff4be91e9c889fd9e2bf529d/src/freedreno/fdl/fd6_tiled_memcpy.cc

What is implemented, and only this:

  * A UBWC block is 256 bytes.  The pixel count is therefore a function of cpp;
    for cpp == 4 (ARGB8888 and ABGR2101010 alike) that is 16x4 = 64 pixels.
    Mesa: "Block dimension of a UBWC block is (block_width, block_height) and
    total size is 256 bytes, unless the format is smaller."  There is no 32x8
    block for 32-bpp formats; 32x8 is cpp == 1 only.
  * Pixel order inside a block is swizzled, the pixel bytes are linear:
        idx = (x&1) | (y&1)<<1 | ((x>>1)&1)<<2 | ((y>>1)&1)<<3 | ((x>>2)&3)<<4
    (get_pixel_offset(), truncated to the block's 64 pixels for cpp == 4).
  * Four blocks per axis form a macrotile (4x4 blocks).  Block placement inside a
    macrotile is (X ^ Y) with
        X = (((x&1) * 0b111) ^ (x & 0b010) ^ ((x>>1) << 3)) << 8
        Y = ((((y&1) * 0b110) ^ (((y>>1)&1) * 0b011)) << 8) | ((y & mask) << shift)
    for cpp < 16 (4-channel mode), exactly as block_x_xormask()/block_y_xormask().
  * Macrotile stride is pitch in 256-byte units:
        macrotile_stride = pitch // (4 * block_width * cpp)   # pitch // 256 for cpp 4
    and a macrotile row advances by macrotile_stride * 4096 bytes.
  * Bank swizzle mask/shift follow fdl6_get_bank_mask()/fdl6_get_bank_shift();
    with the default config (highest_bank_bit = 0, no levels) it is disabled.

What is NOT implemented, and is reported as blocked rather than guessed:

  * The metadata plane.  Mesa records a per-block metadata byte that selects a
    compressed encoding and stores a compressed size, but the meta-plane size,
    pitch and field layout are not public in anything readable, so this module
    writes the pixel plane only and makes no claim that a display pipe will
    accept the result as a UBWC surface.
  * Compression.  These are uncompressed blocks; whether a pipe treats them as
    such is decided by that metadata byte, not by this encoder.

Usage:
    python3 tools/xnu/ubwc_encode.py --self-test
"""
from __future__ import annotations

BLOCK_BYTES = 256

# get_block_size(): pixels per 256-byte block, keyed by bytes per pixel.
_BLOCK_DIMS = {
    1: (32, 8),
    2: (32, 4),
    4: (16, 4),
    8: (8, 4),
    16: (4, 4),
    32: (4, 2),
    64: (2, 2),
}
# R8G8 is the one cpp == 2 special case: 16x8 rather than 32x4.
_R8G8_DIMS = (16, 8)


def block_dims(cpp: int, r8g8: bool = False) -> tuple[int, int]:
    if cpp == 2 and r8g8:
        return _R8G8_DIMS
    if cpp not in _BLOCK_DIMS:
        raise ValueError(f"cpp={cpp} has no UBWC block size")
    width, height = _BLOCK_DIMS[cpp]
    assert width * height * cpp == BLOCK_BYTES, (width, height, cpp)
    return width, height


def pixel_index(x: int, y: int) -> int:
    """Offset of pixel (x, y) within its block, in pixels."""
    return ((x & 1)
            | ((y & 1) << 1)
            | (((x >> 1) & 1) << 2)
            | (((y >> 1) & 1) << 3)
            | (((x >> 2) & 0x3) << 4)
            | (((y >> 2) & 0x1) << 7))


def macrotile_stride(pitch: int, cpp: int, r8g8: bool = False) -> int:
    bw, _ = block_dims(cpp, r8g8)
    divisor = 4 * bw * cpp
    if pitch % divisor:
        raise ValueError(f"pitch {pitch} is not a multiple of {divisor}")
    return pitch // divisor


def bank_mask(stride: int, highest_bank_bit: int, levels: int,
              cpp: int, r8g8: bool = False) -> int:
    """fdl6_get_bank_mask(): the swizzle bits that are active for this stride."""
    offset = 1 if (r8g8 or cpp == 1) else 0
    mask = 0
    if levels & 0x2 and not (stride & ((1 << (highest_bank_bit - 12 + offset)) - 1)):
        mask |= 0b1
    if levels & 0x4 and not (stride & ((1 << (highest_bank_bit - 11 + offset)) - 1)):
        mask |= 0b10
    if levels & 0x1 and not (stride & ((1 << (highest_bank_bit - 10 + offset)) - 1)):
        mask |= 0b100
    return mask


def bank_shift(highest_bank_bit: int) -> int:
    return highest_bank_bit - 1


def block_offset(bx: int, by: int, cpp: int, stride: int,
                 mask: int = 0, shift: int = 0) -> int:
    """Byte offset of block (bx, by) from the start of its macrotile row."""
    x = bx & 0x3
    y = by & 0x3
    if cpp < 16:
        xo = (((x & 1) * 0b111) ^ (x & 0b010) ^ ((x >> 1) << 3)) << 8
        yo = ((((y & 1) * 0b110) ^ (((y >> 1) & 1) * 0b011)) << 8) | ((y & mask) << shift)
    else:
        xo = (((x & 1) * 0b111) ^ ((x >> 1) << 3)) << 8
        yo = ((((y & 1) * 0b110) ^ (((y >> 1) & 1) * 0b011)) << 8) | ((y & mask) << shift)
    # Macrotiles are 4x4 blocks.  Along a row they are 4096 bytes apart, and a
    # macrotile row advances by stride * 4096 bytes (stride is pitch / 256).
    return (xo ^ yo) + ((bx >> 2) << 12) + (by >> 2) * stride * 4096


def pixel_offsets(width: int, height: int, cpp: int, pitch: int | None = None,
                  highest_bank_bit: int = 0, levels: int = 0,
                  r8g8: bool = False) -> list[int]:
    """Byte offset of every pixel, indexed [y * width + x].

    One block_offset() call per pixel: it already folds the macrotile row term
    ((by >> 2) * stride * 4096), so block x and y are applied together and the
    sixteen block slots of a macrotile stay a permutation of 0..4095.
    """
    bw, bh = block_dims(cpp, r8g8)
    if width % bw or height % bh:
        raise ValueError(f"{width}x{height} is not a whole number of {bw}x{bh} blocks")
    pitch = width * cpp if pitch is None else pitch
    stride = macrotile_stride(pitch, cpp, r8g8)
    mask = bank_mask(stride, highest_bank_bit, levels, cpp, r8g8)
    shift = bank_shift(highest_bank_bit) if mask else 0
    out = [0] * (width * height)
    for y in range(height):
        for x in range(width):
            # The block's own address plus the pixel's swizzled slot inside it.
            # Do not subtract anything here: the swizzle index carries the y bits
            # too, and cancelling them collapsed whole rows onto offset 0.
            off = block_offset(x // bw, y // bh, cpp, stride, mask, shift)
            out[y * width + x] = off + pixel_index(x % bw, y % bh) * cpp
    return out


def encode(src: bytes, width: int, height: int, cpp: int, pitch: int | None = None,
           highest_bank_bit: int = 0, levels: int = 0, r8g8: bool = False) -> bytes:
    """Linear rows -> UBWC-layout (uncompressed) pixel plane."""
    pitch = width * cpp if pitch is None else pitch
    if len(src) != width * height * cpp:
        raise ValueError("source length does not match width*height*cpp")
    dst = bytearray(pitch * height)
    offs = pixel_offsets(width, height, cpp, pitch, highest_bank_bit, levels, r8g8)
    for i, off in enumerate(offs):
        dst[off:off + cpp] = src[i * cpp:(i + 1) * cpp]
    return bytes(dst)


def decode(tiled: bytes, width: int, height: int, cpp: int, pitch: int | None = None,
           highest_bank_bit: int = 0, levels: int = 0, r8g8: bool = False) -> bytes:
    """UBWC-layout (uncompressed) pixel plane -> linear rows."""
    pitch = width * cpp if pitch is None else pitch
    if len(tiled) < pitch * height:
        raise ValueError("tiled buffer is shorter than pitch * height")
    out = bytearray(width * height * cpp)
    offs = pixel_offsets(width, height, cpp, pitch, highest_bank_bit, levels, r8g8)
    for i, off in enumerate(offs):
        out[i * cpp:(i + 1) * cpp] = tiled[off:off + cpp]
    return bytes(out)


class MetadataPlaneBlocked(NotImplementedError):
    """Raised because the UBWC metadata plane layout is not publicly documented.

    A UBWC surface is a pixel plane plus a metadata plane; the metadata byte per
    block is what tells the decoder whether a block is uncompressed and how big a
    compressed block is.  Mesa names the byte and its compat codes
    (src/freedreno/common/freedreno_ubwc.h) but the meta-plane size, pitch and
    field layout live in layout code that no readable public source provides, so
    this module refuses to synthesise one.  Callers must treat a buffer produced
    here as a pixel plane only: correct tiling, not a display-ready surface.
    """


def meta_plane(pixel_plane_bytes: int) -> bytes:
    """Refuse to invent the metadata plane.  See MetadataPlaneBlocked."""
    raise MetadataPlaneBlocked(
        "UBWC metadata plane layout is undocumented publicly; "
        f"refusing to guess a meta plane for {pixel_plane_bytes} pixel-plane bytes"
    )


def _self_test() -> int:
    import hashlib
    w, h, cpp = 64, 32, 4
    src = bytes((i * 7) & 0xFF for i in range(w * h * cpp))
    tiled = encode(src, w, h, cpp)
    assert len(tiled) == w * h * cpp
    assert decode(tiled, w, h, cpp) == src
    assert tiled != src, "gradient must not survive linear order"
    print("self-test ok:", w, "x", h, "cpp", cpp,
          "sha256", hashlib.sha256(tiled).hexdigest()[:16])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
