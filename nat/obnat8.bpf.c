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

#define START_IP_ADDR 0x0a0a0100 // 10.10.1.0
#define END_IP_ADDR 0x0a0a01ff   // 10.10.1.256

#define NAT_IP_ADDR 0x0a0a0200 // 10.10.2.0

// Batch of 8. NAT with code reordering (all lookups first, then all rewrites)
// and 4-way loop unrolling. Fully unrolling the batch (8x, and even more so 16x
// in tobnat) makes the verifier explode on the per-packet variable-offset packet
// WRITES in update_ipaddr (>1,000,000 insns), independently of the stack. A
// partially unrolled (4x) loop keeps the unrolling but lets the verifier
// converge on the loop back-edge.
#define BATCH_SIZE 8

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

    return 0;
}

struct t_meta {
    unsigned short valid;
    unsigned short len[7];   // 7 explicit per-packet lengths (batch 8)
};


SEC("xdp")
int obnat8(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data) {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[BATCH_SIZE - 1];
    #pragma unroll
    for (int i = 0; i < BATCH_SIZE - 1; i++)
        lens[i] = bpf_ntohs(md->len[i]);

    // Phase 1: NAT lookup for every packet (4-way unrolled). Code reordering:
    // the cache-missing map lookups are all issued before any rewrite; store the
    // looked-up address value.
    __be32 nat_vals[BATCH_SIZE];
    __u16 lentot = 0;
    #pragma unroll(4)
    for (int i = 0; i < BATCH_SIZE; i++) {
        __be32 ip = get_ip(data + (lentot & 0x1FFF), data_end);
        __be32 *p = bpf_map_lookup_elem(&external_map, &ip);
        if (!p) {
            bpf_printk("Failed to get nat ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }
        nat_vals[i] = *p;
        if (i < BATCH_SIZE - 1)
            lentot += lens[i];
    }

    // Phase 2: rewrite every packet's source IP (deferred, 4-way unrolled).
    lentot = 0;
    #pragma unroll(4)
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (update_ipaddr(data + (lentot & 0x1FFF), data_end, nat_vals[i])) {
            bpf_printk("Failed to update ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }
        if (i < BATCH_SIZE - 1)
            lentot += lens[i];
    }

    return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
