#!/system/bin/sh
# OEM QTVM slot probe, variant 3: the trustedvm's exact memory layout.
#
# Variant 2 got as far as parsing the hypervisor (49/34) and then failed with:
#   RAM file-backed-mapping cannot span regions with different purposes:
#   StaticSwiotlbRegion vs GuestMemoryRegion
# The running trustedvm avoids that by keeping the file-backed mapping inside a
# larger guest RAM and reserving the swiotlb at the top:
#   --mem 72 --swiotlb 4 --file-backed-mapping ...,addr=0x80000000,size=0x4400000
# This variant does the same, only with the OEM slot's ids.
set -u

CROSVM=${CROSVM:-/apex/com.android.virt/bin/crosvm}
KERNEL=${1:-/data/local/tmp/oemvm_probe.elf}
RAMFILE=${RAMFILE:-/data/local/tmp/oemvm-ram68.bin}
LOG=/data/local/tmp/oemvm-probe3.out
# The CMA heap is per VM: crosvm_trustedvm uses /dev/trustedvm_cma, so the
# name has to be the one whose heap exists (/dev/oemvm_cma).
NAME=${NAME:-oemvm}
SER=/data/local/tmp/oemvm-serial.log

rm -f "$SER"
: > "$LOG"
echo "payload=$KERNEL ramfile=$RAMFILE" >> "$LOG"

timeout 60 "$CROSVM" --log-level debug run \
	--disable-sandbox \
	--protected-vm \
	--unmap-guest-memory-on-fork \
	--lock-guest-memory \
	--name "${NAME:-oemvm}" \
	--cpus 1 \
	--mem 72 --swiotlb 4 \
	--no-balloon --no-usb --no-pmu \
	--serial=type=file,path="$SER" \
	--file-backed-mapping "$RAMFILE,addr=0x80000000,size=0x4400000,rw,ram" \
	--hypervisor "gunyah[device=/dev/gunyah,qcom_trusted_vm_id=49,qcom_trusted_vm_pas_id=34]" \
	"$KERNEL" </dev/null >> "$LOG" 2>&1
echo "EXIT=$?" >> "$LOG"

tail -30 "$LOG"
