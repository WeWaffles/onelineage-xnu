#!/system/bin/sh
# Read-only: print phandle, reg and size of the reserved-memory nodes the
# Gunyah VM loaders point at (memory-region phandles 0x97/0x98/0x9a).
BASE=/sys/firmware/devicetree/base/reserved-memory
for d in "$BASE"/*; do
	[ -d "$d" ] || continue
	ph="$d/phandle"
	[ -f "$ph" ] || continue
	# phandle is one big-endian u32
	set -- $(od -An -tu1 -v "$ph")
	[ $# -eq 4 ] || continue
	val=$(( ($1 << 24) | ($2 << 16) | ($3 << 8) | $4 ))
	case "$val" in
	151|152|154)
		echo "=== $(basename "$d") (phandle $val) ==="
		if [ -f "$d/reg" ]; then
			echo -n "  reg bytes: "
			od -An -tx1 -v "$d/reg" | tr -d '\n'; echo
			echo -n "  reg u32:   "
			od -An -tu4 -v "$d/reg" | tr -d '\n'; echo
		fi
		[ -f "$d/size" ] && { echo -n "  size: "; od -An -tu4 -v "$d/size"; }
		[ -f "$d/compatible" ] && echo "  compatible: $(strings "$d/compatible" | head -1)"
		;;
	esac
done
