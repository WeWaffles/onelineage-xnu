#!/system/bin/sh
# One attempt at the phone's unused OEM QTVM slot (vmid 49, pas-id 34).
#
# This does NOT write any partition: crosvm takes the payload as an argument, so
# the only thing being asked is whether the resource manager / TZ will accept a
# protected VM for that slot with an image we supplied.
#
# Run as root on the phone:  su -c "sh /data/local/tmp/run_oemvm_probe.sh"
set -u

CROSVM=${CROSVM:-/apex/com.android.virt/bin/crosvm}
KERNEL=${1:-/data/local/tmp/oemvm_probe.elf}
LOG=/data/local/tmp/oemvm-probe.out
SER=/data/local/tmp/oemvm-serial.log

rm -f "$SER"
: > "$LOG"
echo "payload=$KERNEL" >> "$LOG"

timeout 60 "$CROSVM" run \
	--disable-sandbox \
	--protected-vm \
	--unmap-guest-memory-on-fork \
	--lock-guest-memory \
	--name xnu-oemvm-probe \
	--cpus 1 \
	--mem 64 \
	--no-balloon --no-usb --no-pmu \
	--serial=type=file,path="$SER" \
	--hypervisor "gunyah[device=/dev/gunyah,qcom_trusted_vm_id=49,qcom_trusted_vm_pas_id=34]" \
	"$KERNEL" </dev/null >> "$LOG" 2>&1
echo "EXIT=$?" >> "$LOG"

tail -40 "$LOG"
