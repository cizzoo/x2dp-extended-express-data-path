/*
 * bsampler — batch sampling microbenchmark.
 *
 * NF:      none of the packet work — this variant isolates the sampling step
 *          itself. It walks the batch, draws a fresh bpf_get_prandom_u32() for
 *          every valid slot and builds the `valids` bitmask of the slots the
 *          draw kept, then classifies the resulting mask into the `buoni` /
 *          `cattivi` / `tot` counters. What it measures is how the per-slot
 *          decisions of a batch are distributed, i.e. how often a batch ends up
 *          with a scattered rather than a contiguous set of survivors.
 * Variant: batched, legacy fixed 4-slot header; lens[] read from
 *          `struct t_meta`, loop gated by the `valid` bitmap.
 * Opt:     none — the deliberately naive form, one helper call per slot, to be
 *          compared against obsampler's single draw per batch.
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


__u32 buoni=0;
__u32 cattivi=0;
__u32 tot=0;



SEC("xdp")
int bsampler(struct xdp_md *ctx) {

    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data) {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),bpf_ntohs(md->len3), bpf_ntohs(md->len3)};
    __u16 lentot = 0;


    int samplerate = 2;

    __u8 valids=0;

    for (int i = 0; i < 4; i++) {
        if (bpf_ntohs(md->valid) & (1 << i)) {
            __u32 random = bpf_get_prandom_u32();

            // if ((random & ((1 << samplerate)-1)) == 0){
            if ((random % 3) == 0){


                valids += 1<<i;

                lentot += lens[i];

            }
        }
    }

    tot++;

    if (valids == 5 || valids == 9 || valids == 10 || valids == 11 || valids == 13) {
        cattivi += 1;
    }else {
        buoni += 1;
    }

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
