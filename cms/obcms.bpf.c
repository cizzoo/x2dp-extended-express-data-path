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
    unsigned short len[15];   // 15 explicit per-packet lengths (batch 16)
};

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576
#define BATCH_SIZE 16

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
    __u64 h = xxhash64(pkt, sizeof(struct pkt_5tuple), _SEED_HASHFN);
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
int obcms(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    __u32 zero = 0;
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

    // Per-packet start offsets, walking the batch by the header lengths.
    __u16 off1  = 0;
    __u16 off2  = off1  + bpf_ntohs(md->len[0]);
    __u16 off3  = off2  + bpf_ntohs(md->len[1]);
    __u16 off4  = off3  + bpf_ntohs(md->len[2]);
    __u16 off5  = off4  + bpf_ntohs(md->len[3]);
    __u16 off6  = off5  + bpf_ntohs(md->len[4]);
    __u16 off7  = off6  + bpf_ntohs(md->len[5]);
    __u16 off8  = off7  + bpf_ntohs(md->len[6]);
    __u16 off9  = off8  + bpf_ntohs(md->len[7]);
    __u16 off10 = off9  + bpf_ntohs(md->len[8]);
    __u16 off11 = off10 + bpf_ntohs(md->len[9]);
    __u16 off12 = off11 + bpf_ntohs(md->len[10]);
    __u16 off13 = off12 + bpf_ntohs(md->len[11]);
    __u16 off14 = off13 + bpf_ntohs(md->len[12]);
    __u16 off15 = off14 + bpf_ntohs(md->len[13]);
    __u16 off16 = off15 + bpf_ntohs(md->len[14]);

    struct pkt_5tuple pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8,
                      pkt9, pkt10, pkt11, pkt12, pkt13, pkt14, pkt15, pkt16;
    __u16 h1[4], h2[4], h3[4], h4[4], h5[4], h6[4], h7[4], h8[4],
          h9[4], h10[4], h11[4], h12[4], h13[4], h14[4], h15[4], h16[4];

    // Parse all 16 packets (manually unrolled).
    int ret = 0;
    ret |= handle_pkt(data + (off1  & 0x1FFF), data_end, &pkt1);
    ret |= handle_pkt(data + (off2  & 0x1FFF), data_end, &pkt2);
    ret |= handle_pkt(data + (off3  & 0x1FFF), data_end, &pkt3);
    ret |= handle_pkt(data + (off4  & 0x1FFF), data_end, &pkt4);
    ret |= handle_pkt(data + (off5  & 0x1FFF), data_end, &pkt5);
    ret |= handle_pkt(data + (off6  & 0x1FFF), data_end, &pkt6);
    ret |= handle_pkt(data + (off7  & 0x1FFF), data_end, &pkt7);
    ret |= handle_pkt(data + (off8  & 0x1FFF), data_end, &pkt8);
    ret |= handle_pkt(data + (off9  & 0x1FFF), data_end, &pkt9);
    ret |= handle_pkt(data + (off10 & 0x1FFF), data_end, &pkt10);
    ret |= handle_pkt(data + (off11 & 0x1FFF), data_end, &pkt11);
    ret |= handle_pkt(data + (off12 & 0x1FFF), data_end, &pkt12);
    ret |= handle_pkt(data + (off13 & 0x1FFF), data_end, &pkt13);
    ret |= handle_pkt(data + (off14 & 0x1FFF), data_end, &pkt14);
    ret |= handle_pkt(data + (off15 & 0x1FFF), data_end, &pkt15);
    ret |= handle_pkt(data + (off16 & 0x1FFF), data_end, &pkt16);
    if (ret) {
        bpf_printk("handle_pkt failed\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    // Hash all 16 (manually unrolled).
    hash(&pkt1,  sizeof(pkt1),  h1);
    hash(&pkt2,  sizeof(pkt2),  h2);
    hash(&pkt3,  sizeof(pkt3),  h3);
    hash(&pkt4,  sizeof(pkt4),  h4);
    hash(&pkt5,  sizeof(pkt5),  h5);
    hash(&pkt6,  sizeof(pkt6),  h6);
    hash(&pkt7,  sizeof(pkt7),  h7);
    hash(&pkt8,  sizeof(pkt8),  h8);
    hash(&pkt9,  sizeof(pkt9),  h9);
    hash(&pkt10, sizeof(pkt10), h10);
    hash(&pkt11, sizeof(pkt11), h11);
    hash(&pkt12, sizeof(pkt12), h12);
    hash(&pkt13, sizeof(pkt13), h13);
    hash(&pkt14, sizeof(pkt14), h14);
    hash(&pkt15, sizeof(pkt15), h15);
    hash(&pkt16, sizeof(pkt16), h16);

    // Update the sketch for all 16 (manually unrolled, deferred).
    countmin_add(cm, h1);
    countmin_add(cm, h2);
    countmin_add(cm, h3);
    countmin_add(cm, h4);
    countmin_add(cm, h5);
    countmin_add(cm, h6);
    countmin_add(cm, h7);
    countmin_add(cm, h8);
    countmin_add(cm, h9);
    countmin_add(cm, h10);
    countmin_add(cm, h11);
    countmin_add(cm, h12);
    countmin_add(cm, h13);
    countmin_add(cm, h14);
    countmin_add(cm, h15);
    countmin_add(cm, h16);

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
