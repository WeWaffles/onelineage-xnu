#!/system/bin/sh
# OEM QTVM slot probe, variant 2: explicit file-backed guest RAM.
#
# Variant 1 failed in crosvm before the hypervisor was touched:
#   failed to create guest memory: mmap ... Invalid argument (os error 22)
# The working trustedvm uses --file-backed-mapping for its RAM, so this variant
# gives crosvm the same shape of backing and asks for debug logging to see how
# far it gets.
set -u

CROSVM=${CROSVM:-/apex/com.android.virt/bin/crosvm}
KERNEL=${1:-/data/local/tmp/oemvm_probe.elf}
RAMFILE=${RAMFILE:-/data/local/tmp/oemvm-ram.bin}
LOG=/data/local/tmp/oemvm-probe2.out
SER=/data/local/tmp/oemvm-serial.log

rm -f "$SER"
: > "$LOG"
echo "payload=$KERNEL ramfile=$RAMFILE" >> "$LOG"

timeout 60 "$CROSVM" --log-level debug run \
	--disable-sandbox \
	--protected-vm \
	--unmap-guest-memory-on-fork \
	--lock-guest-memory \
	--name xnu-oemvm-probe \
	--cpus 1 \
	--mem 68 \
	--no-balloon --no-usb --no-pmu \
	--serial=type=file,path="$SER" \
	--file-backed-mapping "$RAMFILE,addr=0x80000000,size=0x4000000,rw,ram" \
	--hypervisor "gunyah[device=/dev/gunyah,qcom_trusted_vm_id=49,qcom_trusted_vm_pas_id=34]" \
	"$KERNEL" </dev/null >> "$LOG" 2>&1
echo "EXIT=$?" >> "$LOG"

tail -25 "$LOG"
