/*
 * tnat — source NAT, single-packet, forwarding-biased (t).
 *
 * NF:      same source NAT as nat.bpf.c — `external_map` lookup on ip->saddr,
 *          address rewrite, IPv4 checksum recomputed with bpf_csum_diff().
 * Variant: baseline — standard XDP, one invocation per packet.
 * Opt:     none; the difference against nat.bpf.c is on the exits — a packet
 *          with no mapping is forwarded rather than dropped, so a miss costs
 *          the same TX path as a hit. The per-packet reference for the batched
 *          TX NAT variants.
 * Verdict: bare XDP_TX on a hit and on a lookup miss; bare XDP_DROP only when
 *          the packet is malformed or the rewrite fails.
 */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>


// struct {
//     __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//     __uint(max_entries, 1000000);
//     __type(key, struct ipv4_lpm_key);
//     __type(value, __u32);
//     __uint(map_flags, BPF_F_NO_PREALLOC);

// } lpm SEC(".maps") ;

#define START_IP_ADDR 0x0a0a0100 // 10.10.1.0 
#define END_IP_ADDR 0x0a0a01ff // 10.10.1.256

#define NAT_IP_ADDR 0x0a0a0200 // 10.10.2.0

static __u32 ip_cnt = 0;


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, __be32);
} external_map SEC(".maps");


static __always_inline __be32 get_ip(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return -1;

    return ip->saddr;
}


static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}


static __always_inline int update_ipaddr(void *data, void *data_end, __u32 newip)
{
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





SEC("xdp")
int tnat(struct xdp_md *ctx) {
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);

    __be32 ip = get_ip(data, data_end);
    if (ip < 0){
        bpf_printk("Failed to get ip address\n");
        return XDP_DROP;
    }
    
    __be32 *nat_ip = bpf_map_lookup_elem(&external_map, &ip);
    if (nat_ip == NULL){
        bpf_printk("Failed to lookup ip address\n");
        return XDP_TX;
    }

    if (update_ipaddr(data, data_end, *nat_ip) < 0){
        bpf_printk("Failed to update ip address\n");
        return XDP_DROP;
    }
    return XDP_TX;
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
