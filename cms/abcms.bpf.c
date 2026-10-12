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
 * abcms — Count-Min Sketch, batched + AVX-512 hashing (ab).
 *
 * NF:      same CMS as cms.bpf.c — 4 rows x 1M counters keyed on the IPv4
 *          5-tuple; row r uses bits [16r, 16r + 16) of the 64-bit hash.
 * Variant: batched, same slot walk as bcms: `valid` bitmap, 16-slot loop,
 *          lengths read inline from data_meta + 2 + 2*i (bounds-checked
 *          against ctx->data), offset masked with 0x7FFF and advanced for every
 *          slot. The loop only parses each valid packet's 5-tuple into
 *          pkts[16] (unpacked 16 B keys, zero-initialized, 32-byte aligned). A
 *          slot that fails to parse is cleared from the `ok` mask and skipped;
 *          the batch goes on.
 * Opt:     the whole batch is hashed in ONE call to the xxhash16x16() kfunc
 *          (16 xxhash64 digests with AVX-512, one FPU section per batch)
 *          instead of 16 scalar xxhash64 calls; all 16 keys are hashed, and a
 *          second loop runs countmin_add() only for the slots set in `ok`. One
 *          map lookup per batch. No unroll pragmas (see aobcms).
 * Needs:   the xxhash kernel module loaded first — `make -C xxhash load`.
 * Verdict: packed nibbles, XDP_DROP in every slot, also when the header is
 *          missing or the map lookup fails.
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

// AVX-512 kfunc from xxhash/xxhash_avx.c (module must be loaded): hashes 16
// contiguous 16 B keys (buf, 256 B) into 16 xxhash64 values (out, 128 B).
void xxhash16x16(const __u64 *buf, __u32 seed, __u64 *out) __ksym;

// The driver reads only the low nibble and applies it to the whole batch.
#define XDP_DROP_ALL (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28))

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576

struct countmin
{
    __u64 values[HASHFN_N][COLUMNS];
};

// NOT packed: 16 B per tuple (3 B tail padding), the key size the kfunc
// expects. The batch array is zero-initialized so the padding is deterministic.
struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct countmin);
} countmin SEC(".maps");

// Row r uses bits [16r, 16r + 16) of the packet's 64-bit hash.
static __always_inline void countmin_add(struct countmin *cm, const __u64 h)
{
    for (int i = 0; i < HASHFN_N; i++)
    {
        __u32 target_idx = (h >> (16 * i)) & 0xFFFF & (COLUMNS - 1);
        //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash clang
        cm->values[i][target_idx]++;
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
int abcms(struct xdp_md *ctx)
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

    // The verifier checks only the first 8 bytes behind each kfunc pointer, so
    // both arrays must be stack arrays fully owned by this program.
    // Stack: 256 B keys + 128 B hashes = 384 B (< 512 B).
    struct pkt_5tuple pkts[16] __attribute__((aligned(32))) = {0};
    __u64 out[16] = {0};

    // ok starts as the bitmap and loses the bit of every slot that fails to
    // parse; it gates the sketch update (invalid slots are hashed but ignored).
    __u16 ok = valid;

    // The mask on lentot is 0x7FFF, not 0x1FFF: it must cover the WHOLE batch
    // (16 * 1518 + 32 = 24320 B, in the driver 32 KB RX buffer) or the offset
    // wraps and the tail packets are parsed from the start of the buffer. It
    // only bounds the offset for the verifier; the real protection stays the
    // data_end checks in handle_pkt.
    __u16 lentot = 0;
    // Parse the whole batch (bitmap-aware).
    for (int i = 0; i < 16; i++) {
        // on parse failure skip only this packet, never abort the batch
        if ((ok & (1 << i)) &&
            handle_pkt(data + (lentot & 0x7FFF), data_end, &pkts[i]) != 0)
            ok &= ~(1 << i);
        // advance by this slot's real length (0 if past the header), for
        // invalid/skipped slots too
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    // Hash the whole batch with one SIMD call (one FPU section per batch).
    xxhash16x16((const __u64 *)pkts, _SEED_HASHFN, out);

    for (int i = 0; i < 16; i++) {
        if (ok & (1 << i))
            countmin_add(cm, out[i]);
    }

    return XDP_DROP_ALL;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
