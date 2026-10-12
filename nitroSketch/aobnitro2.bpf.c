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
 * aobnitro2 — NitroSketch flavour 2 (geometric sampling), batched, unrolled +
 *             AVX-512 hashing (aob).
 *
 * NF:      CMS, 4 rows x 1M counters (indexed by 16-bit slices of one
 *          xxhash64 over the IPv4 5-tuple, so only the first 64K of each row
 *          are hit), updated one row at a time on the schedule given by the
 *          `geosampling` table (see nitro2.bpf.c for the sampling scheme).
 * Variant: batched — one XDP invocation per batch of up to 16. The loop walks
 *          all 16 slots gated by the bitmap at data_meta; slot i's length is
 *          read inline from data_meta + 2 + 2*i, bounds-checked against data
 *          (a slot past the header counts as 0, so batch 4..16 all work), and
 *          the running offset is masked with 0x7FFF. The offset advances for
 *          every slot, valid, skipped or not. A non-IPv4 TCP/UDP or truncated
 *          packet skips only its own slot.
 * Opt:     same code as abnitro2 except that the phase 1 and phase 3 loops
 *          are fully unrolled (#pragma unroll). One geosampling and one
 *          countmin lookup per batch, then three phases.
 *          Phase 1 walks the slots in order as nitro2 does: a valid slot is
 *          skipped while the countdown is above HASHFN_N (countdown -=
 *          HASHFN_N), otherwise it is parsed and geo_rows() walks the
 *          geometric schedule to get the mask of rows it updates. The schedule
 *          runs on local copies of count/cursor, written back once at the end;
 *          a parse failure leaves it untouched.
 *          Parsed keys go into a zeroed, 32-byte-aligned pkts[16]. Phase 2 is
 *          ONE xxhash16x16() kfunc call for the batch (always made); phase 3
 *          updates the scheduled rows of every slot with a non-empty mask.
 * Needs:   the xxhash kernel module loaded first — `make -C xxhash load`.
 * Verdict: XDP_DROP packed in all 8 nibbles (ALL_DROP).
 */

// aobnitro2: optimized batched NitroSketch (geometric sampling) with the SIMD
// hash kfunc (B4). Shared per-batch work (B3): one geo lookup and one countmin
// lookup per batch; the geometric schedule is walked packet by packet. Then: parse all
// valid slots, ONE xxhash16x16 call, update the sketch (phases unrolled).

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

// The driver applies (ret & 0xF) to the whole batch; keep all 8 nibbles packed.
#define ALL_DROP                                                               \
    (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) +         \
     (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28))

#define BATCH 16

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576
#define MAX_GEOSAMPLING_SIZE 4096

// Unpacked: 16 B per key, the layout xxhash16x16 expects (16 keys x 16 B).
struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
};

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

// Exported by xxhash/xxhash_avx.c: buf = 16 keys x 16 B, out = 16 xxhash64.
void xxhash16x16(const __u64 *buf, __u32 seed, __u64 *out) __ksym;

// Split one 64-bit hash into the four 16-bit row hashes.
static __always_inline void split_hash(__u64 h, __u16 hashes[4])
{
    hashes[0] = h & 0xFFFF;
    hashes[1] = h >> 16 & 0xFFFF;
    hashes[2] = h >> 32 & 0xFFFF;
    hashes[3] = h >> 48 & 0xFFFF;
}

// Walk the geometric schedule over one sampled packet, as nitro2 does per
// packet, on local copies of geo->count and geo->geo_sampling_idx. Returns the
// mask of sketch rows the packet updates. The schedule does not depend on the
// packet contents, only on the packet order, so it can run in the parse phase
// and the hash and update phases stay separate.
static __always_inline __u8 geo_rows(const struct geosampling *geo, __u32 *count, __u32 *idx)
{
    __u32 row = *count, next = 0;
    __u8 rows = 0;

    for (int r = 0; r < HASHFN_N; r++) {
        if (row < HASHFN_N)
            rows |= 1 << row;
        *idx = (*idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
        next = geo->geo_sampling_array[*idx];
        row += next;
        if (row >= HASHFN_N)
            break;
    }

    // A geometric value of 0 should never happen (the loader fills >= 1);
    // nitro2 leaves count unchanged in that case.
    if (next > 0)
        *count = next - 1;
    return rows;
}

static __always_inline void rows_add(struct countmin *cm, const __u16 hashes[4], __u8 rows)
{
    for (int r = 0; r < HASHFN_N; r++)
        if (rows & (1 << r))
            cm->values[r][hashes[r] & (COLUMNS - 1)]++;
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
int aobnitro2(struct xdp_md *ctx)
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

    // One geo lookup per batch: the schedule runs on local copies, written
    // back once at the end.
    __u32 count = geo->count;
    __u32 idx = geo->geo_sampling_idx;

    struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        return ALL_DROP;

    // Plain stack arrays (the verifier checks only 8 B behind each kfunc
    // pointer). Zero-initialized so the struct padding hashed by the kfunc is
    // deterministic (out too: the verifier checks kfunc pointer arguments
    // as reads of initialized stack). pkts (256 B) + out (128 B) + rows (16 B) fit the 512 B stack.
    struct pkt_5tuple pkts[BATCH] __attribute__((aligned(32))) = {0};
    __u64 out[BATCH] = {0};
    // rows[i] = sketch rows slot i updates (0: invalid, not sampled, not
    // parsed, or sampled with no row left). Kept in a volatile stack array,
    // not a constant bitmask in a register: a precise constant mask would give
    // the verifier one state per mask value.
    volatile __u8 rows[BATCH];

    // Phase 1: geometric skip, parse and row schedule, packet by packet in
    // order, exactly as nitro2. A packet that fails to parse leaves the
    // schedule untouched, as in nitro2.
    __u16 lentot = 0;
    #pragma unroll
    for (int i = 0; i < BATCH; i++) {
        rows[i] = 0;
        if (valid & (1 << i)) {
            if (count > HASHFN_N)
                count -= HASHFN_N;
            else if (handle_pkt(data + (lentot & 0x7FFF), data_end, &pkts[i]) == 0)
                rows[i] = geo_rows(geo, &count, &idx);
        }

        // advance by this slot's length (0 if past the header), outside the
        // validity test so skipped slots still move the offset
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    // Phase 2: one SIMD hash call for the whole batch.
    xxhash16x16((const __u64 *)pkts, _SEED_HASHFN, out);

    // Phase 3: update the scheduled rows of each sampled slot.
    #pragma unroll
    for (int i = 0; i < BATCH; i++) {
        if (rows[i]) {
            __u16 h4[4];
            split_hash(out[i], h4);
            rows_add(cm, h4, rows[i]);
        }
    }

    geo->count = count;
    geo->geo_sampling_idx = idx;

    return ALL_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
