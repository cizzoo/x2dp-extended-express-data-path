/*
 * swap — MAC swap then drop, single-packet.
 *
 * Microbenchmark: drop.bpf.c plus the cheapest possible packet WRITE. Against
 * drop it isolates what it costs to actually touch the frame — the bounds
 * check the verifier demands and the write itself — with no map involved.
 *
 * NF:      swaps the Ethernet source and destination MAC addresses in place.
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     none. See tx/swaptx.bpf.c and tx/swappass.bpf.c for the same work
 *          ending in XDP_TX / XDP_PASS.
 * Verdict: bare XDP_DROP, so the rewritten packet is never transmitted.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>


SEC("xdp")
int swap(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return XDP_DROP;
	}

	//swap the source and destination MAC addresses
	__be16 tmp[ETH_ALEN];
	memcpy(tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source,eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp, ETH_ALEN);

	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
