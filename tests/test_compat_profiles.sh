#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
for p in "$root"/assets/profile-a*.conf; do
  [[ $(grep -Ec '^host_api_(min|max)=[0-9]+$' "$p") -eq 2 ]]
  [[ $(grep -Ec '^guest_api_(min|max)=[0-9]+$' "$p") -eq 2 ]]
  grep -qx 'backend=container' "$p"
  grep -Eq '^experimental=(true|false)$' "$p"
done
grep -q 'ONELINEAGE_ALLOW_EXPERIMENTAL_GUEST' "$root/assets/compat.sh"
! grep -Eq '^[[:space:]]*(kexec|reboot)[[:space:]]' "$root/assets/kexec_backend.sh"
grep -q 'NO EXECUTION' "$root/assets/kexec_backend.sh"
grep -q 'xnu-arm64-port' "$root/assets/kexec_backend.sh"
grep -q '"exact_source_available": false' "$root/kernel/device-abi/sm-s948u-azf1.json"
! grep -Eqi 'unlocked_ioctl|compat_ioctl|device_create[[:space:]]*\(|register_restart_handler|kernel_kexec|machine_kexec' "$root/kernel/xnu_probe/onelineage_xnu_probe.c"
grep -q 'diagnostics.sh' "$root/assets/switch_to_lineage.sh"
echo 'compatibility profile tests passed'
