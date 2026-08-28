/*
 * obnat (bsoftware) — source NAT, batched + unrolled, software batches.
 *
 * Software-batched copy of nat/obnat.bpf.c: packets sit at a fixed PAGE_SIZE
 * (4096 B) stride, so packet i is at data + i*PAGE_SIZE and no real per-packet
 * lengths are read. Use these when the FPGA bitstream is not available.
 *
 * NF:      source NAT — `external_map` lookup on ip->saddr, address rewrite,
 *          IPv4 checksum recomputed with bpf_csum_diff().
 * Variant: batched, PAGE_SIZE stride, 4 slots.
 * Opt:     unrolling and phase separation, applied only to the full-batch case:
 *          when `valid` is 0b1111 all four get_ip() calls run first, then all
 *          four map lookups, then all four rewrites, so the independent hash
 *          probes overlap; any other bitmap falls back to the single packet at
 *          the head of the frame.
 * Verdict: packed nibbles, XDP_DROP in every slot.
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
#define PAGE_SIZE 4096

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

struct t_meta {
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
};


SEC("xdp")
int obnat(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data) {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    //if valid 4 packets else 1
    if(bpf_ntohs(md->valid) == 15){ //1111
        __be32 ip1;
        __be32 ip2;
        __be32 ip3;
        __be32 ip4;
        __be32 *nat_ip1;
        __be32 *nat_ip2;
        __be32 *nat_ip3;
        __be32 *nat_ip4;
        ip1 = get_ip(data, data_end);
        ip2 = get_ip(data + (PAGE_SIZE), data_end);
        ip3 = get_ip(data + (2*PAGE_SIZE), data_end);
        ip4 = get_ip(data + (3*PAGE_SIZE), data_end);

        if (ip1 < 0 || ip2 < 0 || ip3 < 0 || ip4 < 0) {
        // if (ip1 < 0 || ip2 < 0 || ip3 < 0) {
        // if (ip1 < 0 || ip2 < 0) {
            bpf_printk("Failed to get ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }

        nat_ip1 = bpf_map_lookup_elem(&external_map, &ip1);
        nat_ip2 = bpf_map_lookup_elem(&external_map, &ip2);
        nat_ip3 = bpf_map_lookup_elem(&external_map, &ip3);
        nat_ip4 = bpf_map_lookup_elem(&external_map, &ip4);

        if (!nat_ip1 || !nat_ip2 || !nat_ip3 || !nat_ip4) {
        // if (!nat_ip1 || !nat_ip2 || !nat_ip3) {
        // if (!nat_ip1 || !nat_ip2) {
            bpf_printk("Failed to get nat ip\n");

            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }

        int ret1 = update_ipaddr(data, data_end, *nat_ip1);
        int ret2 = update_ipaddr(data + (PAGE_SIZE), data_end, *nat_ip2);
        int ret3 = update_ipaddr(data + (2*PAGE_SIZE), data_end, *nat_ip3);
        int ret4 = update_ipaddr(data + (3*PAGE_SIZE), data_end, *nat_ip4);

        if (ret1 || ret2 || ret3 || ret4) {
        // if (ret1 || ret2 || ret3) {
        // if (ret1 || ret2) {
            bpf_printk("Failed to update ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }
    } else {
        __be32 ip1;
        __be32 *nat_ip1;
        ip1 = get_ip(data, data_end);
        if (ip1 < 0) {
            bpf_printk("Failed to get ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }

        nat_ip1 = bpf_map_lookup_elem(&external_map, &ip1);

        if (!nat_ip1) {
            bpf_printk("Failed to get nat ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }

        int ret1 = update_ipaddr(data, data_end, *nat_ip1);

        if (ret1) {
            bpf_printk("Failed to update ip\n");
            return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        }

    }
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

};

char LICENSE[] SEC("license") = "Dual BSD/GPL";