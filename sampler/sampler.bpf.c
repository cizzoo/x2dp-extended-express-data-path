/*
 * sampler — sampled per-source-IP counting, single-packet baseline.
 *
 * NF:      for the packets it keeps, reads the IPv4 source address and bumps
 *          its counter in the `ips` hash map (1M entries), inserting the entry
 *          on first sight.
 * Variant: baseline — standard XDP, one invocation per packet.
 * Opt:     random sampling: one bpf_get_prandom_u32() per packet, and the
 *          packet is only parsed and counted when the low samplerate=3 bits are
 *          zero (1 in 8). The draw happens before anything touches the packet,
 *          so a sampled-out packet costs one helper call and a test.
 * Verdict: bare XDP_DROP, for kept and skipped packets alike.
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
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, __u64);
} ips SEC(".maps");


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





SEC("xdp")
int sampler(struct xdp_md *ctx) {

    __u32 random = bpf_get_prandom_u32();

    int samplerate = 3;

    if ((random & ((1 << samplerate)-1)) != 0){
        return XDP_DROP;
    }

    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);

    __be32 ip = get_ip(data, data_end);
    if (ip < 0){
        bpf_printk("get ip failed\n");
        return XDP_DROP;
    }
    
    __u64 *count = bpf_map_lookup_elem(&ips, &ip);
    if (count) {
        *count += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&ips, &ip, &init, BPF_ANY);
    }


    return XDP_DROP;
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
