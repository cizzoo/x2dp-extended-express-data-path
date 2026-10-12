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
#define MAX_GEOSAMPLING_SIZE 4096



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

struct geosampling
{
      __u32 geo_sampling_array[MAX_GEOSAMPLING_SIZE];
      __u32 geo_sampling_idx;
      __u32 count;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct geosampling);
} geosampling SEC(".maps");


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

static __always_inline void nitro_add(struct countmin *cm, const __u16 hashes[4], __u32 row_to_update)
{
    if (row_to_update >= HASHFN_N)
        return;
    __u16 hash = hashes[row_to_update];
    __u16 target_idx = hash & (COLUMNS - 1);
    
    cm->values[row_to_update][target_idx]++;

    return;
}

static __always_inline void nitro_update(struct countmin *cm, const __u16 hashes[4], struct geosampling *geo, __u32 row_to_update, __u32 next_geo_value)
{
    // __u32 next_geo_value;
    // __u32 row_to_update = geo->count;


    for (int i = 0; i < HASHFN_N; i++){
        nitro_add(cm, hashes, row_to_update);

        __u32 geo_value_idx = geo->geo_sampling_idx;
        geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
        next_geo_value = geo->geo_sampling_array[geo_value_idx];
        row_to_update += next_geo_value;
        geo->geo_sampling_idx = geo_value_idx;
        
        if (row_to_update >= HASHFN_N) break;
    }

    if (next_geo_value > 0) {
        geo->count = next_geo_value - 1;
    } else {
        bpf_printk("Geo sammpling variable is 0. This should never happen");
    }

}

static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end){
        bpf_printk("eth + 1 >= data_end\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
    }

    __u16 h_proto = eth->h_proto;

    switch (h_proto)
    {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        bpf_printk("eth\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) >= data_end )
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
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
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end){
            bpf_printk("udp\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
        }
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        bpf_printk("proto\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
    }
    return 0;
}


SEC("xdp")
int bnitro2(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        bpf_printk("md + 1 > data\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
    }

    // The mask on lentot below is 0x7FFF, not 0x1FFF: it must cover the WHOLE
    // batch (16 * 1518 + 32 = 24320 B, in the driver 32 KB RX buffer) or the
    // offset wraps and the tail packets are parsed from the start of the
    // buffer. It only bounds the offset for the verifier; the real protection
    // stays the data_end checks in the per-packet parser.
    __u16 lentot = 0;
    // Per-packet lengths live in the long header at m + 2 + 2*i (network order),
    // where m = data_meta and the header spans [data_meta, data). Read each one
    // inline in the loop below, bounds-checked against the header end, so any
    // batch size works (4/6/8/12/16) and missing packets (past the header) count
    // as length 0. Reading inline (instead of into an array via size tiers)
    // keeps the verifier from re-checking this xxhash-heavy loop once per tier.
    __u8 *m = (__u8 *)data_meta;

    // bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
    // bpf_printk("lens: %d %d %d %d\n", lens[0], lens[1], lens[2], lens[3]);



    // int samplerate = 4;

    for( int i = 0; i < 16; i++ ) {
        if(bpf_ntohs(md->valid) & (1 << i)) {

                __u32 zero = 0;



            struct geosampling *geo = bpf_map_lookup_elem(&geosampling, &zero);

            if (!geo){
                bpf_printk("geo is null\n");
                return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
            }

            if(geo->count >HASHFN_N){
                geo->count -= HASHFN_N ;
                continue;
                // return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
            }
            __u32 row_to_update = geo->count;
            __u32 next_geo_value;

            struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
            if (!cm)
                return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);

            struct pkt_5tuple pkt;
            __u16 pkt_hashes[4];            

            int ret = handle_pkt(data+(lentot & 0x7FFF), data_end, &pkt);
            if (ret){
                bpf_printk("handle_pkt failed at i %d\n", i);
                // bpf_printk("len i %d\n", lens[i]);
                return ret;
            }
            hash(&pkt, sizeof(pkt), pkt_hashes);
            nitro_update(cm, pkt_hashes, geo, row_to_update, next_geo_value);

            // advance by this packet's real length (0 if past the header)
            __u8 *lp = m + 2 + (i << 1);
            if (lp + 2 <= data)
                lentot += bpf_ntohs(*(__u16 *)lp);
        }
    }

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
