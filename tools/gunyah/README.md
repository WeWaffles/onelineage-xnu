# Gunyah probes (the arm64 target)

Small userspace probes for the phone's `/dev/gunyah`. They create VMs and inspect how the vendor
resource manager responds. Nothing here writes a partition, loads a module, or touches the
`trustedvm`.

**Read `XNU_BLOCKERS.md` before running anything.** On this firmware a non-QTVM `VM_START` is
refused; the LEND variant additionally panicked the host and reset the phone on 2026-10-31.

## Layout

| Path | What it is |
| --- | --- |
| `probes/` | Recovered sources of every earlier probe, kept byte-for-byte as they were run |
| `gunyah_lend_start.c` | The current probe: LEND + valid DTB + correct PC + one vCPU, one shot |
| `probe.dts` | Minimal FDT used as the VM's config image |
| `build.sh` | `dtc` → embedded header → static aarch64 binary via the Android NDK |

## Build

```sh
./build.sh                      # builds out/gunyah_lend_start
./build.sh gunyah_lend_start    # or name any probe in this directory
```

Defaults to the NDK at `/opt/homebrew/share/android-commandlinetools/ndk/27.2.12479018`; override
with `NDK=` (a `toolchains/llvm/prebuilt/*/bin` directory) or `CC=`.

## Run

```sh
adb push out/gunyah_lend_start /data/local/tmp/
adb shell 'su -c "timeout 25 /data/local/tmp/gunyah_lend_start"'
```

After any unexpected reboot, read `/proc/last_kmsg` — it survives and is the only record of a panic.

## OEM QTVM slot probes (concluded)

The phone reserves a second authenticated VM slot, `oemvm` (vmid 49, pas-id 34), with no image
deployed. `run_oemvm_probe{,2,3}.sh` and `oemvm_launch.c` walked it end to end:

| Piece | What it established |
| --- | --- |
| `run_oemvm_probe.sh` | a plain run never reaches the hypervisor (guest memory setup) |
| `run_oemvm_probe2.sh` | the region layout must leave room for crosvm's swiotlb |
| `run_oemvm_probe3.sh` | mirroring the trustedvm's memory layout gets the payload loaded |
| `mk_oemvm_image.py` | the QTVM loader wants an arm64 Image with the payload at **offset 0** |
| `oemvm_launch.c` | guest RAM must be a Gunyah **CMA mem fd**, not a plain file |

Outcome: the VM is built and authenticated against, and the RM refuses:
`VM_AUTH_IMAGE` (`0x5600000a`), error 6. An unsigned image cannot run in any QTVM slot on this
device. See `XNU_PHONE_PATH.md`.

`oemvm_launch.c` is still the useful artefact: crosvm has no CMA code of its own, so any future
Gunyah work on a permissive device will need the same fd plumbing.

## Why the probe looks the way it does

- **LEND, not SHARE.** `GH_VM_ANDROID_LEND_USER_MEM` produces a different RM request
  (`gunyah_rm_mem_share()` picks the message from the ACL count), so it is a separate hypothesis
  from the share path that failed first.
- **The DTB must live inside a bound region.** `gunyah_share_parcel()` looks the config parcel up in
  the VM's binding tree; a DTB outside every region fails with `-ENOENT`/`-EINVAL` before any RM
  call. One earlier LEND run failed exactly there and was misread as an RM refusal.
- **Boot context `reg` is `(set << 8) | index`.** `REG_SET_PC` is 1, so the register value is
  `0x100`. The earlier probes passed `reg = 1`, which set X1 and left the PC at 0.
- **The payload writes to `0x0f000000`.** If the guest ever runs, `GUNYAH_VCPU_RUN` returns
  `GUNYAH_VCPU_EXIT_MMIO` naming that address with data `0x41` — evidence that cannot be produced
  by the host alone.
