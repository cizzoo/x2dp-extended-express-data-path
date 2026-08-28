/*
 * btx — bare packed XDP_TX, batched.
 *
 * Microbenchmark: the batched counterpart of tx.bpf.c. Touches nothing — not
 * even the batch header — and returns the packed verdict, so the driver
 * transmits the whole batch back out after one XDP call.
 *
 * NF:      none.
 * Variant: batched — one XDP invocation per batch, no walk at all.
 * Opt:     none.
 * Verdict: packed nibbles, XDP_TX in every slot.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct t_meta
{
	__u16 offset;
};

SEC("xdp")
int btx(struct xdp_md *ctx)
{
	return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);
}

char __license[] SEC("license") = "GPL";
