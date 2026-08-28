/*
 * drop — bare XDP_DROP, single-packet.
 *
 * Microbenchmark: the floor of the standard XDP path. The program touches
 * nothing — no packet data, no metadata, no maps — so what is measured is the
 * driver's per-packet XDP call overhead alone. Everything else in the repo is
 * read against this number.
 *
 * NF:      none.
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_DROP.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int  drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
