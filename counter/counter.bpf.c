/*
 * counter — per-source-IP packet counting, single-packet baseline.
 *
 * Microbenchmark: the cost of one hash-map read-modify-write per packet.
 *
 * NF:      parses Ethernet + IPv4 and bumps the counter keyed by ip->saddr in
 *          `proto_count_map` (BPF_MAP_TYPE_HASH, 64k entries), inserting the
 *          entry on first sight. Uses __sync_fetch_and_add() on the value.
 * Variant: baseline — standard XDP, one invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_DROP.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256*256);
    __type(key, __u32);     // protocol number
    __type(value, __u64);  // packet count
} proto_count_map SEC(".maps");


static __always_inline int handle_pkt(void *data, void *data_end) {
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Controlla se è un pacchetto IP
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    __u8 proto = ip->protocol;
    __u32 src_ip = ip->saddr;

    __u64 *count = bpf_map_lookup_elem(&proto_count_map, &src_ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_count_map, &src_ip, &init_val, BPF_ANY);
    }
    return XDP_DROP;

}

SEC("xdp")
int counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    return handle_pkt(data,data_end);
}

char LICENSE[] SEC("license") = "GPL";
