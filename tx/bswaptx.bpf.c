/*
 * bswaptx — MAC swap then transmit, batched.
 *
 * Microbenchmark: the batched counterpart of swaptx.bpf.c — the minimal
 * realistic forwarder, rewriting every packet of a batch and sending the batch
 * back out after one XDP call.
 *
 * NF:      swaps the Ethernet source and destination MAC addresses of each
 *          packet in place.
 * Variant: batched, legacy fixed 4-slot header; lens[] read from
 *          `struct t_meta`, loop gated by the `valid` bitmap.
 * Opt:     none beyond batching.
 * Verdict: packed nibbles, XDP_TX in every slot.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>

struct t_meta
{
	__u16 valid;
	__u16 len1;
	__u16 len2;
	__u16 len3;
};

SEC("xdp")
int bswaptx(struct xdp_md *ctx)
{
	void *data_meta = (void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        bpf_printk("md + 1 > data\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lentot = 0;
    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

	for (int i = 0; i<4; i++){
        if(bpf_ntohs(md->valid) & (1 << i)) {

			struct ethhdr *eth = data+(lentot&0x1FFF);
			if ((void *)(eth + 1) > data_end)
			{
				bpf_printk("eth\n");
				return XDP_PASS;
			}

			//swap the source and destination MAC addresses
			__be16 tmp[ETH_ALEN];
			memcpy(tmp, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source,eth->h_dest, ETH_ALEN);
			memcpy(eth->h_dest, tmp, ETH_ALEN);
			lentot += lens[i];
		}

	}
	return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);

	
}

char __license[] SEC("license") = "GPL";
