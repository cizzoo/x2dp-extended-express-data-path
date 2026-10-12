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

// obnitro2: optimized batched NitroSketch (geometric sampling). Shared per-batch
// work (B3): one geo lookup, one skip check and one countmin lookup per batch;
// if the next geometric update is beyond this batch the whole batch is skipped.
// Otherwise code reordering + unrolling (Listing 2): parse all valid slots,
// then hash them, then update the sketch, each phase fully unrolled.

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

// The driver applies (ret & 0xF) to the whole batch; keep all 8 nibbles packed.
#define ALL_DROP                                                               \
    (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) +         \
     (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28))

#define BATCH 16

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576
#define MAX_GEOSAMPLING_SIZE 4096

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

struct countmin
{
    __u64 values[HASHFN_N][COLUMNS];
};

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

static __always_inline void nitro_add(struct countmin *cm, const __u16 hashes[4], __u32 row_to_update)
{
    if (row_to_update >= HASHFN_N)
        return;
    __u16 hash = hashes[row_to_update];
    __u32 target_idx = hash & (COLUMNS - 1);

    cm->values[row_to_update][target_idx]++;

    return;
}

static __always_inline void nitro_update(struct countmin *cm, const __u16 hashes[4], struct geosampling *geo, __u32 row_to_update, __u32 next_geo_value)
{
    for (int i = 0; i < HASHFN_N; i++){
        nitro_add(cm, hashes, row_to_update);

        __u32 geo_value_idx = geo->geo_sampling_idx;
        geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
        next_geo_value = geo->geo_sampling_array[geo_value_idx];
        row_to_update += next_geo_value;
        geo->geo_sampling_idx = geo_value_idx;

        if (row_to_update >= HASHFN_N) break;
    }

    // A geometric value of 0 should never happen (the loader fills >= 1).
    if (next_geo_value > 0)
        geo->count = next_geo_value - 1;
}

// Parse one packet into its 5-tuple. Returns 0 on success, -1 if the packet is
// not IPv4 TCP/UDP or is truncated: the caller skips only that slot.
static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) >= data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) >= data_end)
        return -1;
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end)
            return -1;
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        return -1;
    }
    return 0;
}

SEC("xdp")
int obnitro2(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;

    // Batch header at [data_meta, data): [u16 bitmap][u16 len_0]..[u16 len_14],
    // network order (the 16th length is implicit). Packets are back to back
    // from data. Each length is read inline, bounds-checked against data, so a
    // shorter header (batch 4/8) makes the missing slots count as length 0.
    // The offset mask is 0x7FFF so it covers the whole batch (16 * 1518 + 32 B
    // in the 32 KB RX buffer); it only bounds the offset for the verifier, the
    // data_end checks in handle_pkt are the real protection.
    __u8 *m = (__u8 *)data_meta;
    if (m + 2 > (__u8 *)data)
        return ALL_DROP;
    __u16 valid = bpf_ntohs(*(__u16 *)m);

    __u32 zero = 0;
    struct geosampling *geo = bpf_map_lookup_elem(&geosampling, &zero);
    if (!geo)
        return ALL_DROP;

    // Whole-batch geometric skip.
    if (geo->count > HASHFN_N) {
        geo->count -= HASHFN_N;
        return ALL_DROP;
    }

    __u32 row_to_update = geo->count;
    __u32 next_geo_value = 0;

    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return ALL_DROP;

    struct pkt_5tuple pkts[BATCH];
    __u16 pkt_hashes[BATCH][4];
    // ok[i] = slot i is valid in the bitmap, (sampled,) and parsed. Kept in a
    // volatile stack array, not a constant bitmask in a register: a precise
    // constant mask would give the verifier one state per mask value.
    volatile __u8 ok[BATCH];

    // Phase 1: parse all valid slots.
    __u16 lentot = 0;
    #pragma unroll
    for (int i = 0; i < BATCH; i++) {
        ok[i] = 0;
        if (valid & (1 << i))
            ok[i] = handle_pkt(data + (lentot & 0x7FFF), data_end, &pkts[i]) == 0;

        // advance by this slot's length (0 if past the header), outside the
        // validity test so skipped slots still move the offset
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    // Phase 2: hash all parsed slots.
    #pragma unroll
    for (int i = 0; i < BATCH; i++)
        if (ok[i])
            hash(&pkts[i], sizeof(pkts[i]), pkt_hashes[i]);

    // Phase 3: update the sketch for all parsed slots.
    #pragma unroll
    for (int i = 0; i < BATCH; i++)
        if (ok[i])
            nitro_update(cm, pkt_hashes[i], geo, row_to_update, next_geo_value);

    return ALL_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
