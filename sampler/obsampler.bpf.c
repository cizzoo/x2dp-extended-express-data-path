/*
 * obsampler — sampled per-source-IP counting, batched + optimised (ob).
 *
 * NF:      same as sampler.bpf.c — for the slots it keeps, reads the IPv4
 *          source address and bumps its counter in the `ips` hash map (1M
 *          entries), inserting on first sight.
 * Variant: batched, legacy fixed 4-slot header; lens[] read from
 *          `struct t_meta`, loop gated by the `valid` bitmap, cursor advanced
 *          whether or not the slot was sampled.
 * Opt:     amortises the randomness over the batch: a single
 *          bpf_get_prandom_u32() is split into four bytes randoms[0..3], one
 *          sampling decision per slot (low samplerate=3 bits zero, 1 in 8),
 *          instead of one helper call per packet. The per-slot call is left
 *          commented out beside it for the comparison.
 * Verdict: packed nibbles, XDP_DROP in every slot.
 */

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, __u64);
} ips SEC(".maps");


static __always_inline __be32 get_ip(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return -1;

    return ip->saddr;
}





SEC("xdp")
int obsampler(struct xdp_md *ctx) {

    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data) {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),bpf_ntohs(md->len3), bpf_ntohs(md->len3)};
    __u16 lentot = 0;

     __u8 randoms[4];
    __u32 random = bpf_get_prandom_u32();

    randoms[0] = (random & 0xFF);
    randoms[1] = random >> 8 & 0xFF;
    randoms[2] = random >> 16 & 0xFF;
    randoms[3] = random >> 24 & 0xFF;

    int samplerate = 3;

    for (int i = 0; i < 4; i++) {
        if (bpf_ntohs(md->valid) & (1 << i)) {
            // __u32 random = bpf_get_prandom_u32();

            // if ((random & ((1 << samplerate)-1)) == 0){
            if ((randoms[i] & ((1 << samplerate)-1)) == 0){


                __be32 ip = get_ip(data + (lentot & 0x1FFF), data_end);
                if (ip < 0){
                    bpf_printk("get ip failed\n");
                    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
                }
                
                __u64 *count = bpf_map_lookup_elem(&ips, &ip);
                if (count) {
                    *count += 1;
                } else {
                    __u64 init = 1;
                    bpf_map_update_elem(&ips, &ip, &init, BPF_ANY);
                }
            }
        }
    }

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
