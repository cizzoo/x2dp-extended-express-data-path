#!/bin/bash
# Program the Alveo U55N with the X2DP bitstream, re-enumerate it on PCIe,
# set the OpenNIC shell registers and bind both functions to the modified
# OpenNIC driver (onic), which must already be loaded.
#
# Usage: sudo ./program_fpga.sh [bitstream.bit]
#        sudo ./program_fpga.sh --no-program   # only registers and binding,
#                                              # e.g. after a reboot
#
# Environment overrides:
#   XSDB      path to the Vitis xsdb binary     (default: xsdb in PATH)
#   PCIMEM    path to the pcimem tool           (default: pcimem in PATH)
#   PCI_FUNCS space-separated PCI functions     (default: 0000:16:00.0 0000:16:00.1)
#
# If the rescan cannot fit both 4 MB BAR2s in the bridge window (dmesg: "BAR 2
# ... no space"), the bridge was sized at boot for another design: reboot with
# this bitstream loaded (a warm reboot keeps it) and run with --no-program.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRAM=1
while [ $# -gt 0 ]; do
	case "$1" in
	--no-program) PROGRAM=0; shift ;;
	-h|--help) sed -n '2,17p' "$0"; exit 0 ;;
	*) break ;;
	esac
done
BITSTREAM="$(realpath "${1:-$DIR/xdp_batch.bit}")"
XSDB="${XSDB:-xsdb}"
PCIMEM="${PCIMEM:-pcimem}"
read -r -a FUNCS <<< "${PCI_FUNCS:-0000:16:00.0 0000:16:00.1}"
BAR="/sys/bus/pci/devices/${FUNCS[0]}/resource2"

unbind() {
	local drv="/sys/bus/pci/devices/$1/driver"
	if [ -e "$drv" ]; then
		echo "$1" > "$drv/unbind"
	fi
}

bind() {
	echo onic > "/sys/bus/pci/devices/$1/driver_override"
	echo "$1" > /sys/bus/pci/drivers_probe
}

[ -d /sys/bus/pci/drivers/onic ] || { echo "the onic driver is not loaded"; exit 1; }

if [ "$PROGRAM" = 1 ]; then
[ -f "$BITSTREAM" ] || { echo "bitstream not found: $BITSTREAM"; exit 1; }

# Release and remove the old functions, so the kernel enumerates the new design
for f in "${FUNCS[@]}"; do
	if [ -e "/sys/bus/pci/devices/$f" ]; then
		unbind "$f"
		echo 1 > "/sys/bus/pci/devices/$f/remove"
	fi
done

echo "Programming $BITSTREAM"
echo "connect; target 1; fpga -f $BITSTREAM" | "$XSDB"

# The JTAG load resets the endpoint: remove whatever re-appeared, then rescan
for f in "${FUNCS[@]}"; do
	[ -e "/sys/bus/pci/devices/$f" ] && echo 1 > "/sys/bus/pci/devices/$f/remove"
done
sleep 1
echo 1 > /sys/bus/pci/rescan
sleep 2
fi

for f in "${FUNCS[@]}"; do
	[ -e "/sys/bus/pci/devices/$f" ] || { echo "$f missing"; lspci -nn | grep -i xilinx; exit 1; }
	if ! lspci -vv -s "$f" | grep -q "Region 2: Memory at [0-9a-f]"; then
		echo "$f has no BAR2 assigned (see dmesg): reboot and rerun with --no-program"
		exit 1
	fi
	unbind "$f"
done

# OpenNIC shell registers. After a rescan no driver has enabled the device,
# so turn on memory decoding or the writes are dropped.
setpci -s "${FUNCS[0]}" COMMAND=0x02:0x02
for reg in 0x1000=0x1 0x2000=0x00010001 0x8014=0x1 0x800c=0x1 0xC014=0x1 0xC00c=0x1; do
	out=$("$PCIMEM" "$BAR" "${reg%=*}" w "${reg#*=}")
	echo "$out" | grep -i "readback"
	if echo "$out" | grep -qi "readback 0xFFFFFFFF"; then
		echo "register ${reg%=*} not writable: BAR not mapped"
		exit 1
	fi
done

for f in "${FUNCS[@]}"; do
	bind "$f"
	echo "$f -> $(basename "$(readlink "/sys/bus/pci/devices/$f/driver")")"
done
