/*
 * bpass — bare packed XDP_PASS, batched.
 *
 * Microbenchmark: the batched counterpart of pass.bpf.c. Touches nothing, not
 * even the batch header, and returns the packed verdict immediately: one XDP
 * call per batch.
 *
 * NF:      none.
 * Variant: batched — one XDP invocation per batch, no walk at all.
 * Opt:     none.
 * Verdict: packed nibbles, XDP_PASS in every slot.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int bpass(struct xdp_md *ctx)
{
	return XDP_PASS + (XDP_PASS << 4) + (XDP_PASS << 8) + (XDP_PASS << 12) + (XDP_PASS << 16) + (XDP_PASS << 20) + (XDP_PASS << 24) + (XDP_PASS << 28);
}

char __license[] SEC("license") = "GPL";
