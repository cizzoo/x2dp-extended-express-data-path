/*
 * pass — bare XDP_PASS, single-packet.
 *
 * Microbenchmark: like drop.bpf.c, but the packet continues up the network
 * stack instead of being freed, so the difference against drop is the cost of
 * the kernel's normal receive path.
 *
 * NF:      none.
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
