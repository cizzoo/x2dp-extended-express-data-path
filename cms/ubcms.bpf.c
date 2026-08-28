/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ubcms — Count-Min Sketch, batched, unconditional 4-slot loop (u).
 *
 * NF:      same CMS as cms.bpf.c — 4 rows x 1M counters, xxhash64 over the
 *          IPv4 5-tuple.
 * Variant: batched, legacy fixed 4-slot header; lens[] is read from
 *          `struct t_meta` before the loop.
 * Opt:     the `valid` bitmap test is dropped — all four slots are processed
 *          unconditionally, one branch per slot less and a straight-line loop
 *          body the verifier can unroll cleanly. The cursor advances by the
 *          precomputed lens[i] instead of an inline header read, and the map
 *          lookup stays hoisted out of the loop (one per batch).
 * Verdict: packed nibbles, XDP_DROP in every slot.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "xxhash64.h"

struct t_meta
{
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
    // unsigned short len4;

};

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576
// #define COLUMNS 512


struct countmin
{
    __u64 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

struct
{
    // __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct countmin);
} countmin SEC(".maps");

static __always_inline void hash(const void *pkt, const __u64 len, __u16 hashes[4])
{
    __u64 h = xxhash64(pkt, len, _SEED_HASHFN);
    hashes[0] = (h & 0xFFFF);
    hashes[1] = h >> 16 & 0xFFFF;
    hashes[2] = h >> 32 & 0xFFFF;
    hashes[3] = h >> 48 & 0xFFFF;
    return;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static __always_inline void countmin_add(struct countmin *cm, const __u16 hashes[4])
{
    for (int i = 0; i < ARRAY_SIZE(hashes); i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash clang
        cm->values[i][target_idx]++;
    }
    return;
}

static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) >= data_end){
        bpf_printk("eth + 1 >= data_end\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 h_proto = eth->h_proto;

    switch (h_proto)
    {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        bpf_printk("eth\n");
        bpf_printk("h_proto: %d\n", h_proto);
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) >= data_end )
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    // bpf_printk("src_ip: %pI4\n", &ip->saddr);
    // bpf_printk("dst_ip: %pI4\n", &ip->daddr);
    // bpf_printk("proto: %d\n", ip->protocol);
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > data_end)
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end){
            bpf_printk("udp\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        bpf_printk("proto\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    return 0;
}

SEC("xdp")
int ubcms(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        bpf_printk("md + 1 > data\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        // return XDP_PASS + (XDP_PASS << 4) + (XDP_PASS << 8) + (XDP_PASS << 12);
    }

    __u16 lentot = 0;
    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

    // bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
    // bpf_printk("lens: %d %d %d %d\n", lens[0], lens[1], lens[2], lens[3]);

    __u32 zero = 0;
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    
    // #pragma clang loop vectorize(disable) interleave(enable)
    // // #pragma clang loop unroll(enable)
     for( int i = 0; i < 4; i++ ) {
        // if(bpf_ntohs(md->valid) & (1 << i)) {

            struct pkt_5tuple pkt;
            __u16 pkt_hashes[4];            

            
            int ret = handle_pkt(data + (lentot & 0x1FFF), data_end, &pkt);
            if (ret){
                bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
                bpf_printk("lens: %d %d %d %d\n", lens[0], lens[1], lens[2], lens[3]);
                bpf_printk("handle_pkt failed at i %d\n", i);
                bpf_printk("len %d lens[i]%d, lentot %d\n",i, lens[i], lentot);
                return ret;
            }
            hash(&pkt, sizeof(pkt), pkt_hashes);
            countmin_add(cm, pkt_hashes);
            
            lentot += lens[i];
        // }
    }
    
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
