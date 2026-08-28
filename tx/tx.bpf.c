/*
 * tx — bare XDP_TX, single-packet.
 *
 * Microbenchmark: the floor of the forwarding path. Touches nothing and bounces
 * the packet straight back out of the interface it arrived on, so against
 * drop.bpf.c the difference is the driver's TX path alone.
 *
 * NF:      none.
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_TX.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


SEC("xdp")
int tx(struct xdp_md *ctx)
{
	return XDP_TX;
}

char __license[] SEC("license") = "GPL";
