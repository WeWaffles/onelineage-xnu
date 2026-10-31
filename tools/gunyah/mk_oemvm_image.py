#!/usr/bin/env python3
"""Build the OEM-slot probe payload as an arm64 Linux Image.

crosvm's aarch64 loader rejects an ELF with "invalid magic number"; the format
it wants is the arm64 boot Image, whose magic "ARM\\x64" sits at offset 0x38.
Entry is image_base + text_offset, so the code goes at that offset.

Payload: store 'A' to 0x0f000000, an address no device covers, so a running
vCPU produces an observable MMIO exit.
"""
import struct
import sys

# The QTVM loader requires the payload at offset 0 of the image
# ("payload offset 64 != 0" when text_offset was 0x40), so the code goes first
# and text_offset stays zero.
TEXT_OFFSET = 0x0
IMAGE_SIZE = 0x1000

code = b"".join(struct.pack("<I", w) for w in (
    0xD2A01E01,   # movz x1, #0x0f00, lsl #16   -> x1 = 0x0f000000
    0x52800820,   # mov  w0, #0x41              -> 'A'
    0xB9000020,   # str  w0, [x1]
    0x14000000,   # b .
))

img = bytearray(IMAGE_SIZE)
img[0x00:len(code)] = code                       # entry is the image base
struct.pack_into("<Q", img, 0x08, TEXT_OFFSET)   # text_offset
struct.pack_into("<Q", img, 0x10, IMAGE_SIZE)    # image_size
struct.pack_into("<Q", img, 0x18, 0xA)           # flags: LE, 4K pages
img[0x38:0x3C] = b"ARM\x64"                      # magic

with open(sys.argv[1] if len(sys.argv) > 1 else "oemvm_probe.img", "wb") as f:
    f.write(img)
print(f"wrote {len(img)} bytes, entry=base+0x{TEXT_OFFSET:x}, magic at 0x38")
