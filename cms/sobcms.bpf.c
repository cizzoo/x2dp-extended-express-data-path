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

// The driver reads only the low nibble and applies it to the whole batch.
#define XDP_DROP_ALL (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28))

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

// Split update: all loads of a group are issued before any store, so the
// cache misses of the group overlap.
static __always_inline void countmin_load(struct countmin *cm, const __u16 hashes[4], __u64 *new_values)
{
    for (int i = 0; i < HASHFN_N; i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        new_values[i] = cm->values[i][target_idx];
    }
    return;
}

static __always_inline void countmin_store(struct countmin *cm, const __u16 hashes[4], __u64 *new_values)
{
    for (int i = 0; i < HASHFN_N; i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        new_values[i]++;
        cm->values[i][target_idx] = new_values[i];
    }
    return;
}

// Returns 0 if the packet is IPv4 TCP/UDP and pkt was filled, 1 otherwise.
static __always_inline int handle_pkt(void *data, void *data_end, struct pkt_5tuple *pkt)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) >= data_end)
        return 1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) >= data_end)
        return 1;
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end)
            return 1;
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end)
            return 1;
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        break;
    }
    default:
        return 1;
    }
    return 0;
}

SEC("xdp")
int sobcms(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;

    // Batch header in [data_meta, data): [u16 bitmap][u16 len_0]...[u16 len_14]
    // (network order). Lengths are read inline below, bounds-checked against the
    // header end, so any batch size works and slots past the header count as 0.
    __u8 *m = (__u8 *)data_meta;
    if (m + 2 > (__u8 *)data)
        return XDP_DROP_ALL;
    __u16 valid = bpf_ntohs(*(__u16 *)m);

    // One map lookup per batch.
    __u32 zero = 0;
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return XDP_DROP_ALL;

    // ok starts as the bitmap and loses the bit of every slot that fails to
    // parse; it gates hashing and the sketch update.
    __u16 ok = valid;
    __u16 lentot = 0;

    // The batch of 16 is processed as four groups of 4 (fully unrolled), the
    // group width of the original 4-packet sobcms: the loaded counters of all
    // 16 (16 * 4 * 8 B = 512 B) would not fit the BPF stack, and groups of 8
    // spill past it. Within a group: parse all -> hash + load all -> store all.
    // The mask on lentot is 0x7FFF, not 0x1FFF: it must cover the WHOLE batch
    // (16 * 1518 + 32 = 24320 B, in the driver 32 KB RX buffer) or the offset
    // wraps and the tail packets are parsed from the start of the buffer. It
    // only bounds the offset for the verifier; the real protection stays the
    // data_end checks in handle_pkt.
#pragma unroll
    for (int g = 0; g < 16; g += 4) {
        // Stack per group: 4 * 13 B tuples + 4 * 4 * 2 B hashes + 4 * 4 * 8 B values.
        struct pkt_5tuple pkts[4] = {0};
        __u16 h[4][4];
        __u64 values[4][4];
        // Keep the arrays in memory (clang otherwise scalarizes and spills them).
        asm volatile("" : : "r"(pkts), "r"(h), "r"(values) : "memory");

#pragma unroll
        for (int j = 0; j < 4; j++) {
            int i = g + j;
            // on parse failure skip only this packet, never abort the batch
            if ((ok & (1 << i)) &&
                handle_pkt(data + (lentot & 0x7FFF), data_end, &pkts[j]) != 0)
                ok &= ~(1 << i);
            // advance by this slot's real length (0 if past the header), for
            // invalid/skipped slots too
            __u8 *lp = m + 2 + (i << 1);
            if (lp + 2 <= (__u8 *)data)
                lentot += bpf_ntohs(*(__u16 *)lp);
        }

#pragma unroll
        for (int j = 0; j < 4; j++) {
            if (ok & (1 << (g + j))) {
                hash(&pkts[j], sizeof(pkts[j]), h[j]);
                countmin_load(cm, h[j], values[j]);
            }
        }

#pragma unroll
        for (int j = 0; j < 4; j++) {
            if (ok & (1 << (g + j)))
                countmin_store(cm, h[j], values[j]);
        }
    }

    return XDP_DROP_ALL;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
