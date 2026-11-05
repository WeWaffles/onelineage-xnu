# Pinned XNU build for the QEMU early-console milestone

This directory makes the first XNU milestone reproducible: obtain one exact XNU
tree, apply one exact patch series, and build one exact kernel configuration.
Nothing here is a phone operation. No boot partition, running kernel, or payload
is touched, and none of this authorizes execution on the the arm64 target.

The milestone is the one recorded in `XNU_PROGRESS.md`: an XNU kernel built from
source that reaches an identifiable early boot message in QEMU. Phone support is
explicitly out of scope for this series.

## What is pinned

| Item | Value |
| --- | --- |
| Kernel source | `apple-oss-distributions/xnu` tag `xnu-8796.141.3` |
| Source archive | tarball SHA-256 `f08bfe045a1fb552a6cbf7450feae6a35dd003e9979edf71ea77d1a836c8dc99` |
| Tag source | `distribution-macOS` `macos-135/release.json` (macOS 13.5, XNU-8796 generation) |
| Build harness | `blacktop/darwin-xnu-build` at `663906528d1cd5ea8fde7de6f16de73db9511549` |
| Configuration | `KERNEL_CONFIG=DEVELOPMENT`, `ARCH_CONFIG=ARM64`, `MACHINE_CONFIG=SWEET` |
| Host | macOS with Xcode and the `Kernel.framework` private headers |

All of it lives in [series.json](series.json), including a SHA-256 per patch.
The build harness reads its pins from that file instead of repeating them.

## The series

`patches/` vendors patches `0001`–`0018` of `dipa-studio/ios-sweet` at commit
`45263bee51df4a0f55cdf9c649af886399488ddb` (MIT, see
[LICENSE.ios-sweet](../tools/xnu/LICENSE.ios-sweet)). They are byte-identical to
the upstream git blobs. The upstream working tree on a Windows checkout has CRLF
in these files, which makes every patch fail to apply; the vendored copies are
LF-only, and the verifier enforces that.

The selection is the contiguous prefix that covers this milestone:

- `0001`, `0002`, `0005`, `0007`, `0008`, `0009` — build and link against an open
  source tree with a current clang, no closed `lib<SoC>.os.a`, and no Apple-only
  exports.
- `0004`, `0006` — a non-Apple arm64 machine configuration (`SWEET`) built from
  the open-source assembly and pmap.
- `0003`, `0010`, `0012` — early serial output: a framebuffer-backed `pe_serial`
  and an early debug console that survives the TTBR0 switch.
- `0011`, `0013`, `0014`, `0015` — vm/prng/security adjustments so the kernel
  does not depend on Apple memory layout, CoreCrypto, or the trust-cache runtime.
- `0016`, `0017`, `0018` — device-tree platform expert, virtual-timer IRQ through
  `pe_fiq`, and single-CPU `IOCPU` bring-up.

Left out on purpose: everything from `0019` on (filesystem, AMFI, HFS/mockfs,
UFS, USB, HID/touch, display, keystore, SMP). Those belong to later milestones,
and several of them need `*.sh` staging scripts that vendor third-party sources.
The series stops before any of that, so it has no staging scripts.

## Verify the series offline

```sh
python3 tools/xnu/verify_xnu_series.py --verify-only   # manifest, hashes, line endings
python3 tools/xnu/verify_xnu_series.py --fetch         # download, hash-check, apply in order
```

`--fetch` downloads the pinned tarball into `build/xnu-src/`, verifies its
SHA-256, extracts a fresh tree, writes a provenance marker, then applies every
patch in declared order with text conversion disabled. It refuses to patch a
tree that lacks the marker, so it will never modify an unidentified XNU
checkout. `--json PATH` writes a report that explicitly records
`compiled: false`, `linked: false`, `qemu_console_reached: false` and
`phone_execution_authorized: false`.

A clean run means the patch text composes against the pinned tag. It does not
mean the kernel builds, links, boots, or runs — that is what the next two
commands are for.

## Build it

Local macOS host:

```sh
bash xnu/build_xnu.sh
```

The script verifies the series, fetches the pinned harness, installs the series,
widens `libfirehose_kernel` to plain arm64 (ios-sweet does the same; the
`SWEET` kernel is not arm64e), builds, then fails closed unless *every* pinned
patch shows up as applied in the build log. `darwin-xnu-build` skips a patch it
cannot apply, so a kernel can otherwise be produced with part of the series
missing. The kernel lands in `build/xnu/`, is checked with
`tools/xnu/inspect_macho.py`, and is hashed.

Without a Mac, [.github/workflows/xnu-build.yml](../.github/workflows/xnu-build.yml)
runs the same script on a `macos-14` runner (Xcode 15.x, whose `iig` matches the
XNU-8796 IORPC ABI) and uploads the kernel and build log as artifacts. It needs
`workflow_dispatch` or a push that touches `xnu/**` or `tools/xnu/**`.

## Status

| Check | Result |
| --- | --- |
| Pinned source downloads and matches its SHA-256 | verified |
| All 18 patches hash-match and are LF-only | verified |
| Series applies in order to pristine `xnu-8796.141.3` | verified (2026-10-24) |
| Compiles and links | **not run** — needs macOS/Xcode |
| Reaches an early console line in QEMU | **not run** |
| Anything on the the arm64 target | not implemented, not authorized |

## QEMU harness

Once a kernel is built, `tools/xnu/run_qemu.py` launches it:

```sh
# Generate the ADT
python3 tools/xnu/mk_m3q_adt.py kernel/device-hardware/generic-arm64.json \
    build/qemu.adt

# Pack the ONELXNU payload
python3 tools/xnu/build_payload.py build/xnu/kernel.development.arm64.sweet \
    build/qemu.adt build/payload.bin

# Boot it (20 s timeout, dump fb.png + regs.txt + qemu.log)
python3 tools/xnu/run_qemu.py build/payload.bin build/qemu-out/

# Stream serial output live
python3 tools/xnu/run_qemu.py build/payload.bin build/qemu-out/ --live-serial

# GDB attach
python3 tools/xnu/run_qemu.py build/payload.bin build/qemu-out/ --gdb
```

`run_qemu.py` places QEMU virt RAM at `0x40000000` with 2 GB, covering the
sweet early-console framebuffer at `0x9c000000`.  It saves `result.json` with
the boot outcome.  With `--kernel` it decodes the framebuffer text via the
kernel's `iso_font` and writes `fb.txt`.

## Known gaps before the first QEMU console line

These gaps are **closed** in the host tooling as of 2026-10-30.  They cannot be
verified until a kernel is built (CI run needed):

1. **Platform expert match** — *closed.*  `mk_m3q_adt.py` adds `xiaomi,sweet`
   as the first string in the root `compatible` property.  Patch `0016`'s
   `IONameMatch = 'xiaomi,sweet'` will match.
2. **Early console target** — *closed.*  QEMU memory is 2 GB
   (`0x40000000`–`0xbfffffff`), which covers `0x9c000000`.  `start.s`'s
   bootstrap L2 block mapping and `sweet_early.c`'s hardcoded address both
   write into plain RAM that QEMU backs.  `mk_m3q_adt.py` also emits a
   `sweet-fbcon` node with the matching address, dimensions and stride for the
   `pe_serial.c` late console (patch `0003`).  `run_qemu.py` dumps the
   framebuffer region after the run timeout.
3. **Timer INTID** — *closed.*  Patch `0017` already reads `virtual-timer-intid`
   from the GIC ADT node at boot and overrides the compiled-in `SWEET_VTIMER_INTID`.
   The GIC node has always carried `27` (QEMU virt standard).
4. **No loader** — *closed.*  `tools/xnu/run_qemu.py` (new) reads the ONELXNU
   payload, reconstructs the flat RAM image, constructs `boot_args`, places a
   6-instruction entry stub, and drives `qemu-system-aarch64 -M virt,gic-version=3`.

The remaining blockers are compile-time, not host-tooling:

- A `macos-14` CI run is needed to build the kernel (Xcode 15.x for the XNU-8796
  IORPC ABI).  The `.github/workflows/xnu-build.yml` workflow is the path.
