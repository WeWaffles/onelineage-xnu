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
| 0xc9 | `osfmk/kern/timer_call.c` | running timers: active, quantum deadline, now |
| 0xca | `osfmk/kern/priority.c` | quantum expired: remaining, quantum_end, priority |
| 0xcb | `osfmk/kern/priority.c` | `csw_check` verdict at quantum expiry |
| 0xcc | `osfmk/kern/sched_prim.c` | quantum armed at dispatch |
| 0xcd | `osfmk/kern/priority.c` | quantum callback entered (thread ids) |
| 0xce | `bsd/kern/kern_exit.c` | `exit(0)` reached BSD: pid, status |
| 0xcf | `osfmk/kern/sched_prim.c` | thread blocking after fork: id, reason, continuation |
| 0xd0 | `osfmk/kern/task.c` | `task_terminate` (not on the process-exit path) |
| 0xd1 | `osfmk/kern/thread_act.c` | `thread_terminate` |
| 0xd2 | `bsd/kern/kern_exit.c` | `proc_exit` entered |
| 0xd3 | `bsd/kern/kern_exit.c` | exit branch: `p_lflag`, is this the exit thread |
| 0xd4 | `bsd/kern/kern_exit.c` | `task_terminate_internal` returned |
| 0xd5 | `bsd/kern/kern_exit.c` | past the branch and the signal drain |
| 0xd6 | `osfmk/kern/task.c` | `task_terminate_internal` entered |
| 0xd7 | `bsd/kern/kern_exit.c` | about to sleep on `proc_prepareexit_wait` |
| 0xd8 | `bsd/kern/kern_exit.c` | about to drain in-flight signals |
| 0xd9 | `bsd/kern/kern_exit.c` | `proc_refdrain` returned |
| 0xda | `bsd/kern/kern_exit.c` | `fdt_invalidate` returned |
| 0xdb | `bsd/kern/kern_exit.c` | `workq_exit` returned |
| 0xdc | `bsd/kern/kern_proc.c` | `proc_refdrain` entry: raw bits, refcount, pid |
| 0xdd | `bsd/kern/kern_proc.c` | about to sleep on the reference count |
| 0xde | `bsd/kern/kern_proc.c` | reference wait returned |
| 0xe1 | `osfmk/kern/ast.c` | `ast_taken_kernel` early return: 1 not urgent, 2 waitq not possible |
| 0xe3 | `bsd/kern/kern_exit.c` | all three teardown stages have returned |
| 0xe4 | `bsd/kern/kern_exit.c` | just before `proc_pgrp` (takes `proc_list_lock` and a pgrp lock) |
| 0xe5 | `bsd/kern/kern_exit.c` | `proc_pgrp` returned |
| 0xe6 | `bsd/kern/kern_exit.c` | end of the `proc_exit` body |
| 0xe7 | `bsd/kern/kern_exit.c` | `exit_with_reason` resumed after `proc_exit` returned |
| 0xe8 | `bsd/kern/kern_exit.c` | just before `thread_terminate(self)` |
| 0xe9 | `bsd/kern/kern_exit.c` | just before `thread_exception_return()` |
| 0xea | `osfmk/kern/thread.c` | `thread_terminate_self` resumed after `proc_exit` returned |
| 0xeb | `osfmk/kern/thread.c` | before `splsched()` after the corpse/task bookkeeping |
| 0xec | `osfmk/kern/thread.c` | just before `thread_exception_return()` in `thread_terminate_self` |
| 0xed | `osfmk/kern/thread.c` | before the `task->corpse_info` block; carries the pointer value |
| 0xee | `osfmk/kern/thread.c` | before the `threadcnt == 0` task lock |
| 0xef | `osfmk/kern/thread.c` | immediately before `splsched()` |
| 0xf0 | `osfmk/kern/thread.c` | `ipc_task_reset` returned |
| 0xf1 | `osfmk/kern/thread.c` | `ipc_task_enable` returned |
| 0xf2 | `osfmk/kern/thread.c` | before `task_deliver_crash_notification` |
| 0xf3 | `osfmk/kern/thread.c` | `task_deliver_crash_notification` returned |
| 0xf4 | `osfmk/kern/ipc_tt.c` | `ipc_task_reset` entered |
| 0xf5 | `osfmk/kern/ipc_tt.c` | before `itk_lock(task)` |
| 0xf6 | `osfmk/kern/ipc_tt.c` | after `itk_lock(task)` |
| 0xf7 | `osfmk/kern/ipc_tt.c` | end of `ipc_task_reset` |
| 0xf8 | `osfmk/kern/thread.c` | inside the corpse block, with `task->corpse_info` as the value |
| 0xc4 | `osfmk/arm64/sleh.c` | post-exit liveness: an IRQ was still taken, capped at 2 |

**A note on 0xd9–0xdb.** These were listed here before they existed in the
kernel: the insert used an anchor that no longer matched, the patch script
aborted, and the build reported success because it built the unchanged tree.
`hw/m383` was interpreted through records that were not in the binary. They are
now inserted by line position, verified with `grep`, and part of this patch.
`0xc5`, `0xc7`, `0xca`, `0xcb`, `0xcd` are gated on `sweet_fork_seen` so their
caps are not consumed during boot (`hw/m385`).

`0xb6` (trap) is now recorded only after `sweet_fork_seen` and capped at 10, so
post-fork trap records survive the 16-slot ring and can show the parent
running again. Before the fork they were boot noise.

Two measurement hazards are also fixed here. The ring holds 16 records and the
console emits `0xc6` at character rate, so `sweet_early_evidence()` now keeps
only the first two `0xc6` and six `0xb6`; without that, records from after the
fork child runs are rotated out before the pull (`hw/m379`). Scheduler records
are gated on `sweet_fork_seen` so cap-consuming boot activity cannot hide the
post-fork event (`hw/m380`).

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
