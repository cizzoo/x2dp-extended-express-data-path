/*
 * bdrop — bare packed XDP_DROP, batched.
 *
 * Microbenchmark: the floor of the batching path, the counterpart of
 * drop.bpf.c. The program touches nothing — not even the batch header — and
 * immediately returns the packed verdict, so against drop.bpf.c it measures
 * what one XDP call per batch saves over one per packet.
 *
 * NF:      none.
 * Variant: batched — one XDP invocation per batch, no walk at all.
 * Opt:     none.
 * Verdict: packed nibbles, XDP_DROP in every slot (the packed XDP_PASS form is
 *          left commented out beside it).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int bdrop(struct xdp_md *ctx)
{
return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
	//return XDP_PASS + (XDP_PASS << 4) + (XDP_PASS << 8) + (XDP_PASS << 12);
}

char __license[] SEC("license") = "GPL";
