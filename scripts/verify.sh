#!/bin/bash
# Load every built XDP program through the verifier (no attach) and report the
# result and the number of processed instructions (the limit is 1,000,000).
#
# Usage: sudo scripts/verify.sh [dir|file.bpf.o ...]   (default: all apps)
#
# Build first (make). The a* variants need the kfunc module: make -C xxhash load
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN=/sys/fs/bpf/bxdp_verify
BPFTOOL="${BPFTOOL:-bpftool}"
APPS=(pass drop tx router conntrack nat cms nitroSketch)

objs=()
for arg in "${@:-${APPS[@]}}"; do
	case "$arg" in
	*.bpf.o) objs+=("$arg") ;;
	*) objs+=("$ROOT/$arg"/*.bpf.o) ;;
	esac
done

fail=0
for obj in "${objs[@]}"; do
	[ -f "$obj" ] || continue
	name="$(basename "$obj" .bpf.o)"
	rm -rf "$PIN"
	log="$("$BPFTOOL" -d prog loadall "$obj" "$PIN" type xdp 2>&1)"
	insns="$(echo "$log" | grep -o 'processed [0-9]* insns' | tail -1 | grep -o '[0-9]*')"
	if [ -d "$PIN" ] && [ -n "$(ls -A "$PIN")" ]; then
		printf "OK    %-16s %8s insns\n" "$name" "${insns:-?}"
	else
		printf "FAIL  %-16s\n" "$name"
		echo "$log" | grep -v '^libbpf: ' | tail -5 | sed 's/^/      /'
		fail=1
	fi
	rm -rf "$PIN"
done
exit $fail
