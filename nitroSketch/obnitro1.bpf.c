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
 * obnitro1 — NitroSketch flavour 1 (uniform sampling), batched + shared work.
 *
 * NF:      CMS, 4 rows x 1M counters (indexed by 16-bit slices of one
 *          xxhash64 over the IPv4 5-tuple, so only the first 64K of each row
 *          are hit), updated only for sampled packets.
 * Variant: batched — one XDP invocation per batch of up to 16. The loop walks
 *          all 16 slots gated by the bitmap at data_meta; slot i's length is
 *          read inline from data_meta + 2 + 2*i, bounds-checked against data
 *          (a slot past the header counts as 0, so batch 4..16 all work), and
 *          the running offset is masked with 0x7FFF. The offset advances for
 *          every slot, valid, skipped or not. A non-IPv4 TCP/UDP or truncated
 *          packet skips only its own slot.
 * Opt:     per-batch sharing (B3): one countmin lookup per batch, and four
 *          bpf_get_prandom_u32() calls split into 16 bytes, one sampling
 *          decision per slot (low samplerate=4 bits zero, 1 in 16), instead
 *          of one lookup and one draw per packet. Valid, sampled slots are
 *          parsed, hashed (scalar xxhash64) and counted inside the same loop;
 *          no explicit unrolling or reordering.
 * Verdict: XDP_DROP packed in all 8 nibbles (ALL_DROP).
 */

// obnitro1: optimized batched NitroSketch (uniform sampling). Shared per-batch
// work (B3): one countmin lookup and 4 PRNG draws for the whole batch (one
// sampling byte per slot) instead of one lookup + one draw per packet. Only
// valid, sampled slots are parsed, hashed and counted.

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

static __always_inline void hash(const void *pkt, const __u64 len, __u16 hashes[4])
{
    __u64 h = xxhash64(pkt, len, _SEED_HASHFN);
    hashes[0] = (h & 0xFFFF);
    hashes[1] = h >> 16 & 0xFFFF;
    hashes[2] = h >> 32 & 0xFFFF;
    hashes[3] = h >> 48 & 0xFFFF;
    return;
}

static __always_inline void countmin_add(struct countmin *cm, const __u16 hashes[4])
{
    for (int i = 0; i < HASHFN_N; i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        cm->values[i][target_idx]++;
    }
    return;
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
int obnitro1(struct xdp_md *ctx)
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

    // 16 sampling bytes from 4 PRNG draws (one byte per slot).
    __u8 randoms[BATCH];
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 random = bpf_get_prandom_u32();
        randoms[i * 4 + 0] = random & 0xFF;
        randoms[i * 4 + 1] = random >> 8 & 0xFF;
        randoms[i * 4 + 2] = random >> 16 & 0xFF;
        randoms[i * 4 + 3] = random >> 24 & 0xFF;
    }

    int samplerate = 4;
    __u32 mask = (1 << samplerate) - 1;

    __u32 zero = 0;
    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return ALL_DROP;

    __u16 lentot = 0;
    for (int i = 0; i < BATCH; i++) {
        if ((valid & (1 << i)) && (randoms[i] & mask) == 0) {
            struct pkt_5tuple pkt;
            __u16 pkt_hashes[4];

            // on parse failure skip only this slot
            if (handle_pkt(data + (lentot & 0x7FFF), data_end, &pkt) == 0) {
                hash(&pkt, sizeof(pkt), pkt_hashes);
                countmin_add(cm, pkt_hashes);
            }
        }

        // advance by this slot's length (0 if past the header), outside the
        // validity test so skipped slots still move the offset
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    return ALL_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
