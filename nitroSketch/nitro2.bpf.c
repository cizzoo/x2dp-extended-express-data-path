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
 * nitro2 — NitroSketch flavour 2 (geometric sampling), single-packet baseline.
 *
 * NF:      Count-Min Sketch, 4 rows x 1M counters, xxhash64 over the IPv4
 *          5-tuple, updated one ROW at a time by nitro_add().
 * Variant: baseline — one XDP invocation per packet.
 * Opt:     proper NitroSketch sampling. A `geosampling` map holds a
 *          precomputed table of geometric random variates (filled by the
 *          loader, which is why this program links against GSL) plus a cursor
 *          and a countdown. Each packet consumes the countdown; when it is
 *          still above HASHFN_N the packet is skipped entirely, otherwise the
 *          program walks only the rows the geometric skips land on. This
 *          replaces per-packet randomness (nitro1) with one table read, and
 *          skips whole rows rather than whole packets.
 * Verdict: bare XDP_DROP.
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
    // __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct geosampling);
} geosampling SEC(".maps");


static __always_inline void hash(const void *pkt, const __u64 len, __u16 hashes[4])
{
    __u64 h = xxhash64	(pkt, len, _SEED_HASHFN);
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

static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end)
        return XDP_DROP;

    __u16 h_proto = eth->h_proto;

    switch (h_proto)
    {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        return XDP_DROP;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 >= data_end)
        return XDP_DROP;
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > data_end)
            return XDP_DROP;
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udp + 1 > data_end)
            return XDP_DROP;
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        return XDP_DROP;
    }
    return 0;
}

SEC("xdp")
int nitro2(struct xdp_md *ctx)
{

    // int samplerate = 4;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 zero = 0;
    struct geosampling *geo = bpf_map_lookup_elem(&geosampling, &zero);

    if (!geo){
        bpf_printk("geo is null\n");
        return XDP_DROP;
    }

    if(geo->count >HASHFN_N){
        geo->count -= HASHFN_N ;

        return XDP_DROP;
    }

    __u32 row_to_update = geo->count;
    __u32 next_geo_value;
    
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm){
        bpf_printk("cm is null\n");
        return XDP_DROP;
    }

    struct pkt_5tuple pkt1;
    __u16 pkt1_hashes[4];

    int ret = handle_pkt(data, data_end, &pkt1);
    if (ret){
        bpf_printk("handle_pkt failed\n");
        return ret;
    }
    hash(&pkt1, sizeof(pkt1), pkt1_hashes);

    for (int i = 0; i < HASHFN_N; i++){
        nitro_add(cm, pkt1_hashes, row_to_update);

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
        return XDP_DROP;
    }

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
