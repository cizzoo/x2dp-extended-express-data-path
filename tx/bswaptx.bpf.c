/*
 * bswaptx — MAC swap then transmit, batched.
 *
 * Microbenchmark: the batched counterpart of swaptx.bpf.c — the minimal
 * realistic forwarder, rewriting every packet of a batch and sending the batch
 * back out after one XDP call.
 *
 * NF:      swaps the Ethernet source and destination MAC addresses of each
 *          packet in place.
 * Variant: batched — one XDP invocation per batch of up to 16 packets.
 *          Reads the u16 bitmap at data_meta and walks 16 slots, skipping
 *          those whose bit is clear; each slot's length is read inline at
 *          data_meta + 2 + 2*i, bounds-checked against data (a slot past the
 *          header counts as 0), and the running offset is masked with 0x7FFF
 *          for the verifier.
 *          A slot too short for an Ethernet header is left untouched and the
 *          offset still advances.
 * Opt:     none beyond batching.
 * Verdict: packed nibbles (all 8), XDP_TX in every slot; a packed XDP_DROP if
 *          the batch header is missing.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>

// Swap source/destination MAC of every valid packet in the batch (up to 16).
// Batch header in [data_meta, data): __u16 bitmap, then per-packet __u16
// lengths at m + 2 + 2*i (network order), read inline and bounds-checked so
// slots past the header count as length 0. The 0x7FFF mask covers the whole
// batch (16 * 1518 + 32 B); it only bounds the offset for the verifier.
SEC("xdp")
int bswaptx(struct xdp_md *ctx)
{
	void *data_meta = (void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u8 *m = (__u8 *)data_meta;
	if (m + 2 > (__u8 *)data)
		return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);

	__u16 valid = bpf_ntohs(*(__u16 *)m);
	__u16 lentot = 0;

	for (int i = 0; i < 16; i++) {
		if (valid & (1 << i)) {
			struct ethhdr *eth = data + (lentot & 0x7FFF);
			// skip only this packet if it is truncated
			if ((void *)(eth + 1) <= data_end) {
				__u8 tmp[ETH_ALEN];
				memcpy(tmp, eth->h_source, ETH_ALEN);
				memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
				memcpy(eth->h_dest, tmp, ETH_ALEN);
			}
		}
		// advance by this slot's length even if invalid or skipped
		__u8 *lp = m + 2 + (i << 1);
		if (lp + 2 <= (__u8 *)data)
			lentot += bpf_ntohs(*(__u16 *)lp);
	}

	return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12) + (XDP_TX << 16) + (XDP_TX << 20) + (XDP_TX << 24) + (XDP_TX << 28);
}

char __license[] SEC("license") = "GPL";
