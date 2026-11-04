# Kernel checkpoints

`build/xnu-src/` is gitignored, so every kernel-side instrument — the ring
recorder, the syscall and trap probes, mockfs, the scheduler records — exists
only on this machine. This directory makes that work reproducible from the
pinned source.

## What is here

- `0001-onelineage-instrumentation-2026-11-04.patch` — the complete difference
  between the source that was measured on the phone and a tree built from the
  pinned tarball plus `xnu/patches/` alone. 65 files, ~9k lines.

The recorded tags, in the order they were added:

| tag | where | meaning |
|-----|-------|---------|
| 0xa6 | `bsd/dev/arm/systemcalls.c` | BSD syscall, capped at 12 |
| 0xb6 | `osfmk/arm64/bsd_arm64.c` | Mach trap, capped at 64 |
| 0xb8/0xb9 | `osfmk/kern/startup.c`, `bsd_init.c` | boot stage markers |
| 0xba–0xbb | `bsd/dev/arm/systemcalls.c` | fork, child `p_stat` |
| 0xbc–0xbf | `osfmk/kern/task.c` | wait-to-return handoff |
| 0xc0/0xc2 | `osfmk/arm64/status.c` | sampled user state, context vs upcb |
| 0xc1 | `osfmk/arm64/sleh.c` | user faults (never fired) |
| 0xc3 | `osfmk/arm64/sleh.c` | interrupt count, every 1024 |
| 0xc5 | `osfmk/kern/ast.c` `ast_taken_user` | AST taken returning to user |
| 0xc7 | `osfmk/kern/ast.c` `ast_taken_kernel` | AST taken in kernel |

## Reproduce

```sh
cd /Users/waffles/onelineage-xnu
rm -rf /tmp/xnu_base && mkdir -p /tmp/xnu_base
tar xzf build/xnu-src/xnu-8796.141.3.tar.gz -C /tmp/xnu_base --strip-components=1
cd /tmp/xnu_base
for p in /Users/waffles/onelineage-xnu/xnu/patches/*.patch; do
    patch -p1 -N < "$p"
done
patch -p1 < /Users/waffles/onelineage-xnu/xnu/checkpoints/0001-onelineage-instrumentation-2026-11-04.patch
```

Then build with `-C build/xnu-src/source` as the Makefile expects (see
`xnu/build_xnu.sh`), `ARCH_CONFIGS=ARM64 KERNEL_CONFIGS=DEVELOPMENT
MACHINE_CONFIGS=SWEET BUILD_WERROR=0`.

Verified on 2026-11-04: the series applies 24/24 clean and the checkpoint
applies to it with `patch -p1 --dry-run` returning 0 and no failures.
