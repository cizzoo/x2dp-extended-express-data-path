/*
 * torouter — IPv4 LPM lookup behind an LRU flow cache, single-packet,
 * forwarding path (t).
 *
 * NF:      router.bpf.c's lookup (Ethernet + IPv4, source address, non-IPv4
 *          frames skipped) through resolve(): a BPF_MAP_TYPE_LRU_HASH
 *          flow_cache (64k, keyed by the /32 source IP) is tried first; on a
 *          miss the 1M-entry LPM trie is walked and a hit is inserted into the
 *          cache.
 * Variant: baseline — standard XDP, one invocation per packet. The
 *          per-packet counterpart of tobrouter.
 * Opt:     flow cache only (a hot flow costs one hash access, not a trie walk).
 * Verdict: bare XDP_TX on every path.
 */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};


// Full routing table: an LPM trie keyed by {prefixlen, src IP}. A lookup walks
// several trie nodes, i.e. a chain of dependent (cache-missing) memory accesses.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);

} lpm SEC(".maps") ;

// Flow cache in front of the LPM trie. Keyed by the exact /32 source IP, so a
// hit is a single hash access instead of a multi-node trie walk. LRU eviction
// keeps the hottest flows resident automatically ("cache the most common
// flows"). The stored value is the matched prefix length, exactly what the LPM
// trie returns, so a hit is equivalent to a trie hit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u8);
} flow_cache SEC(".maps");

// Resolve one source IP through the flow cache, falling back to the LPM trie on
// a miss and warming the cache with the result so the flow is hot next time.
static __always_inline __u8 *resolve(__be32 saddr) {
    __u8 *value = bpf_map_lookup_elem(&flow_cache, &saddr);
    if (value)
        return value; // fast path: hot flow, single hash access

    // slow path: full LPM trie walk, then promote the flow into the cache
    struct ipv4_lpm_key key = {.prefixlen = 32, .data = saddr};
    value = bpf_map_lookup_elem(&lpm, &key);
    if (value)
        bpf_map_update_elem(&flow_cache, &saddr, value, BPF_ANY);
    return value;
}

SEC("xdp")
int torouter(struct xdp_md *ctx) {
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);
    struct ethhdr* eth_hdr = data;
    struct iphdr* ip_hdr;
    __u16 protocol = 0;
    __u32 src_ip = 0;
    // __u8 value = 0;

    if (data + sizeof(struct ethhdr) < (void*)(long)ctx->data_end) {
    	protocol = eth_hdr->h_proto;
    	if (protocol == htons(ETH_P_IP) ) {
    		ip_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr));
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <  data_end){
                src_ip = ip_hdr->saddr;

                __u8 *value = resolve(src_ip);

                if(value){
       //             bpf_printk("Matched with rule %u\n",value[0]);
                    // return XDP_DROP;
                    goto end;
                }else{
     //               bpf_printk("Not Matched\n");
                    // return XDP_DROP;
                    goto end;
                }
            }
        }
    }
    // return XDP_PASS;
end:
    return XDP_TX;
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
