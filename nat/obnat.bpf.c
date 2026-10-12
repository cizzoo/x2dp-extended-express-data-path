/*
 * obnat — source NAT, batched + reordered + unrolled (ob).
 *
 * NF:      same source NAT as nat.bpf.c — `external_map` lookup on ip->saddr,
 *          address rewrite, IPv4 checksum recomputed with bpf_csum_diff().
 * Variant: batched — one XDP invocation per batch of up to 16 packets.
 *          Reads the u16 bitmap at data_meta and walks 16 slots, skipping
 *          those whose bit is clear; each slot's length is read inline at
 *          data_meta + 2 + 2*i, bounds-checked against data (a slot past the
 *          header counts as 0), and the running offset is masked with 0x7FFF
 *          for the verifier.
 * Opt:     code reordering in two phases, each a bounded loop over 16 slots
 *          with 4-way partial unrolling (#pragma unroll(4)): phase 1 runs
 *          get_ip() and the map lookup for every slot, so the independent hash
 *          probes are issued back to back, and stores the translated address
 *          (or the slot's own source IP on a miss) in nat_vals[16]; phase 2
 *          recomputes the offsets from the header and runs every
 *          update_ipaddr(). A miss therefore rewrites saddr with itself
 *          (only the checksum is recomputed); a too-short frame is skipped by
 *          update_ipaddr()'s own bounds check. Full 16x unrolling exceeds the
 *          1M-insn verifier limit on the variable-offset packet writes.
 * Verdict: packed nibbles (all 8), XDP_DROP in every slot; also a packed
 *          XDP_DROP if the batch header is missing.
 */

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <bpf/bpf_helpers.h>

// struct {
//     __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//     __uint(max_entries, 1000000);
//     __type(key, struct ipv4_lpm_key);
//     __type(value, __u32);
//     __uint(map_flags, BPF_F_NO_PREALLOC);

// } lpm SEC(".maps") ;

#define START_IP_ADDR 0x0a0a0100 // 10.10.1.0
#define END_IP_ADDR 0x0a0a01ff   // 10.10.1.256

#define NAT_IP_ADDR 0x0a0a0200 // 10.10.2.0

// NAT with code reordering (all lookups first, then all rewrites) and 4-way
// loop unrolling. Measured at batch 8: fully unrolling the batch makes the
// verifier explode on the per-packet variable-offset packet WRITES in
// update_ipaddr (>1,000,000 insns), independently of the stack. A partially
// unrolled (4x) loop keeps the unrolling but lets the verifier converge on the
// loop back-edge.

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, __be32);
} external_map SEC(".maps");

static __always_inline __be32 get_ip(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return -1;

    return ip->saddr;
}

static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum =
            bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline int update_ipaddr(void *data, void *data_end,
                                                                                 __u32 newip) {
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 >= data_end)
        return -1;
    ip->saddr = newip;
    ip->check = iph_csum(ip);

    // bpf_printk("post src_ip: %pI4\n", &ip->saddr);

    return 0;
}

#define BATCH_SIZE 16
// Packed per-slot verdict, 4 bits per slot (all 8 nibbles of the u32).
#define ALL_ACT(a) ((a) + ((a) << 4) + ((a) << 8) + ((a) << 12) + \
                    ((a) << 16) + ((a) << 20) + ((a) << 24) + ((a) << 28))

SEC("xdp")
int obnat(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;

    // Batch header in [data_meta, data): [u16 bitmap][u16 len_0]...[u16 len_14]
    // (network order, 16th length implicit). Each length is read inline and
    // bounds-checked against data, so a slot past the header counts as 0.
    // The offset mask is 0x7FFF (not 0x1FFF): it must cover the whole batch
    // (16 * 1518 + 32 B, inside the 32 KB RX buffer). It only bounds the offset
    // for the verifier; the data_end checks in get_ip/update_ipaddr are the
    // real protection.
    __u8 *m = (__u8 *)data_meta;
    if (m + 2 > (__u8 *)data)
        return ALL_ACT(XDP_DROP);
    __u16 valid = bpf_ntohs(*(__u16 *)m);

    // Code reordering, obnat8 structure at batch 16: phase 1 issues every NAT
    // lookup (the cache-missing hash-map accesses back to back), phase 2 does
    // every rewrite. Both phases are 4-way partially unrolled inside a bounded
    // loop over 16: a full 16x unroll makes the verifier exceed 1M insns on the
    // variable-offset packet WRITES in update_ipaddr (see obnat8 history).
    //
    // On a lookup miss the slot stores its own source IP, so phase 2 rewrites
    // saddr with itself (no-op apart from recomputing the checksum). This keeps
    // every stored value an unknown scalar and avoids a per-slot "ok" flag that
    // the verifier would have to track (constant-vs-unknown stack slots defeat
    // state pruning across the 16 iterations). A slot whose frame is too short
    // fails get_ip and is skipped by update_ipaddr's own bounds check.
    __be32 nat_vals[BATCH_SIZE] = {0};   // 64 B of stack
    __u16 lentot = 0;
    #pragma unroll(4)
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (valid & (1 << i)) {
            __be32 ip = get_ip(data + (lentot & 0x7FFF), data_end);
            __be32 *p = bpf_map_lookup_elem(&external_map, &ip);
            nat_vals[i] = p ? *p : ip;
        }
        // advance by this slot's length even when the slot is skipped
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    // Phase 2: deferred rewrites. Offsets are recomputed from the header.
    lentot = 0;
    #pragma unroll(4)
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (valid & (1 << i))
            update_ipaddr(data + (lentot & 0x7FFF), data_end, nat_vals[i]);
        // advance by this slot's length even when the slot is skipped
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    return ALL_ACT(XDP_DROP);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
