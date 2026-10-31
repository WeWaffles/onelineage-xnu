#!/system/bin/sh
# Read-only: print the properties of the firmware's Gunyah VM loader nodes.
# Run as root on the phone. Touches nothing.
BASE=/sys/firmware/devicetree/base/soc
for n in gh-secure-vm-loader@0 gh-secure-vm-loader@1 qcom,oem_vm qcom,trust_ui_vm; do
	echo "===== $n ====="
	d="$BASE/$n"
	[ -d "$d" ] || { echo "  (absent)"; continue; }
	for p in "$d"/*; do
		name=$(basename "$p")
		printf '  %-24s ' "$name"
		size=$(wc -c < "$p" 2>/dev/null)
		if [ "${size:-0}" -le 8 ] && [ "${size:-0}" -gt 0 ]; then
			# small integer property: print as big-endian number and hex
			od -An -tx1 -v "$p" | tr -d '\n' | sed 's/^/hex:/'
			printf '  int:'
			od -An -tu8 -v "$p" 2>/dev/null | tr -d '\n'
			echo
		else
			echo "size=$size"
			strings "$p" 2>/dev/null | head -3 | sed 's/^/      str: /'
		fi
	done
done
