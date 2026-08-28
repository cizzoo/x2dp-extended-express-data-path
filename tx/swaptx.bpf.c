/*
 * swaptx — MAC swap then transmit, single-packet.
 *
 * Microbenchmark: the minimal realistic forwarder — rewrite the frame, send it
 * back out. Against tx.bpf.c it adds the packet write; against
 * drop/swap.bpf.c it adds the TX path.
 *
 * NF:      swaps the Ethernet source and destination MAC addresses in place.
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_TX (bare XDP_PASS if the frame is too short to hold an
 *          Ethernet header).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>


SEC("xdp")
int swaptx(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return XDP_PASS;
	}

	//swap the source and destination MAC addresses
	__be16 tmp[ETH_ALEN];
	memcpy(tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source,eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp, ETH_ALEN);

	return XDP_TX;
}

char __license[] SEC("license") = "GPL";
