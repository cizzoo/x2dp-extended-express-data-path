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
 * sobcms — Count-Min Sketch, batched, unrolled + split map access (so).
 *
 * NF:      same CMS as cms.bpf.c — 4 rows x 1M counters, xxhash64 over the
 *          IPv4 5-tuple.
 * Variant: batched, legacy fixed 4-slot header, fully unrolled like obcms:
 *          four straight-line handle_pkt() calls at offsets derived from
 *          lens[].
 * Opt:     on top of the unrolling, the counter update is split in two phases.
 *          countmin_load() reads a packet's four counters and countmin_store()
 *          increments and writes them back, and every load of the batch is
 *          issued before any store — so the cache-missing loads of different
 *          packets overlap instead of each one stalling its own
 *          read-modify-write.
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
#include "fasthash.h"
#include "xxhash64.h"

struct t_meta
{
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
};

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576

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

// static __always_inline void countmin_add(struct countmin *cm, const __u16 hashes[4])
// {
//     for (int i = 0; i < ARRAY_SIZE(hashes); i++)
//     {
//         __u32 target_idx = hashes[i] & (COLUMNS - 1);
//         //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash clang
//         cm->values[i][target_idx]++;
//     }
//     return;
// }

static __always_inline void countmin_load(struct countmin *cm, const __u16 hashes[4], __u64 *new_values)
{
    for (int i = 0; i < ARRAY_SIZE(hashes); i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        new_values[i] = cm->values[i][target_idx];
    }
    return;
}

static __always_inline void countmin_store(struct countmin *cm, const __u16 hashes[4], __u64 *new_values)
{
    for (int i = 0; i < ARRAY_SIZE(hashes); i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        new_values[i]++;
        cm->values[i][target_idx] = new_values[i];
    }
    return;
}



static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end ){
        bpf_printk("quit1\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    

    __u16 h_proto = eth->h_proto;

    switch (h_proto)
    {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) >= data_end)
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    // bpf_printk("src_ip: %pI4\n", &ip->saddr);
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
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    return 0;
}

SEC("xdp")
int sobcms(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

    __u32 zero = 0;
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

    struct pkt_5tuple pkt1;
    struct pkt_5tuple pkt2;
    struct pkt_5tuple pkt3;
    struct pkt_5tuple pkt4;
    __u16 pkt_hashes1[4];
    __u16 pkt_hashes2[4];
    __u16 pkt_hashes3[4];
    __u16 pkt_hashes4[4];
    __u64 values1[4];
    __u64 values2[4];
    __u64 values3[4];
    __u64 values4[4];
    int ret1 = handle_pkt(data, data_end, &pkt1);
    int ret2 = handle_pkt(data+(lens[0] &0x1FFF), data_end, &pkt2);
    int ret3 = handle_pkt(data+((lens[0]+lens[1])&0x1FFF), data_end, &pkt3);
    int ret4 = handle_pkt(data+((lens[0]+lens[1]+lens[2])&0x1FFF), data_end, &pkt4);
    // if (ret1 || ret2 || ret3 || ret4){
    // if (ret1 || ret2 || ret3){
    if (ret1 || ret2){
        // bpf_printk("ret1: %d ret2: %d ret3: %d ret4:%d\n", ret1, ret2, ret3, ret4);
        bpf_printk("ret1: %d ret2: %d\n", ret1, ret2);
        bpf_printk("handle_pkt failed\n");
        return ret1;
    }

    hash(&pkt1, sizeof(pkt1), pkt_hashes1);
    countmin_load(cm, pkt_hashes1, values1);
    hash(&pkt2, sizeof(pkt2), pkt_hashes2);
    countmin_load(cm, pkt_hashes2, values2);
    hash(&pkt3, sizeof(pkt3), pkt_hashes3);
    countmin_load(cm, pkt_hashes3, values3);
    hash(&pkt4, sizeof(pkt4), pkt_hashes4);
    countmin_load(cm, pkt_hashes4, values4);

    countmin_store(cm, pkt_hashes1, values1);
    countmin_store(cm, pkt_hashes2, values2);
    countmin_store(cm, pkt_hashes3, values3);
    countmin_store(cm, pkt_hashes4, values4);
    

    
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";