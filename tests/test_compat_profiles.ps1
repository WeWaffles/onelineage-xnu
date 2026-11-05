$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Get-ChildItem (Join-Path $Root 'assets/profile-a*.conf') | ForEach-Object {
    $Content = Get-Content $_.FullName
    if (($Content | Where-Object { $_ -match '^host_api_(min|max)=\d+$' }).Count -ne 2) { throw "Invalid host range: $($_.Name)" }
    if (($Content | Where-Object { $_ -match '^guest_api_(min|max)=\d+$' }).Count -ne 2) { throw "Invalid guest range: $($_.Name)" }
    if ($Content -notcontains 'backend=container') { throw "Missing container backend: $($_.Name)" }
    if (-not ($Content | Where-Object { $_ -match '^experimental=(true|false)$' })) { throw "Missing experimental marker: $($_.Name)" }
}
$Compat = Get-Content (Join-Path $Root 'assets/compat.sh') -Raw
$Kexec = Get-Content (Join-Path $Root 'assets/kexec_backend.sh') -Raw
$Switch = Get-Content (Join-Path $Root 'assets/switch_to_lineage.sh') -Raw
if ($Compat -notmatch 'ONELINEAGE_ALLOW_EXPERIMENTAL_GUEST') { throw 'Experimental opt-in missing' }
if ($Kexec -match '(?m)^\s*(kexec|reboot)\s') { throw 'kexec probe contains an execution command' }
if ($Kexec -notmatch 'NO EXECUTION') { throw 'kexec probe safety marker missing' }
if ($Kexec -notmatch 'xnu-arm64-port') { throw 'kexec probe target is not explicitly XNU' }
$AbiProfile = Get-Content (Join-Path $Root 'kernel/device-abi/generic-arm64-6.12.30.json') -Raw | ConvertFrom-Json
if ($AbiProfile.exact_source_available -ne $false) { throw 'source-unavailable ABI profile must block module loading' }
$Probe = Get-Content (Join-Path $Root 'kernel/xnu_probe/onelineage_xnu_probe.c') -Raw
if ($Probe -match '(?i)unlocked_ioctl|compat_ioctl|device_create\s*\(|register_restart_handler|kernel_kexec|machine_kexec') { throw 'inert XNU probe exposes an execution mechanism' }
if ($Switch -notmatch 'diagnostics\.sh') { throw 'Takeover diagnostic hook missing' }
Write-Output 'compatibility profile tests passed'
