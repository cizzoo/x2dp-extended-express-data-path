/*
 * router — IPv4 longest-prefix-match lookup, single-packet baseline.
 *
 * NF:      parses Ethernet + IPv4 and does one lookup of the source address in
 *          a BPF_MAP_TYPE_LPM_TRIE (1M entries, BPF_F_NO_PREALLOC), filled by
 *          the loader from <rules_dir>/<prefixlen>.txt (default RCC25). The
 *          key is built with prefixlen=32; the trie does the longest-prefix
 *          match. Non-IPv4 or short frames skip the lookup. The result is only
 *          looked at, not acted on — this measures the lookup, not forwarding.
 * Variant: baseline — standard XDP, one invocation per packet.
 * Opt:     none.
 * Verdict: bare XDP_DROP on every path.
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


struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);

} lpm SEC(".maps") ;

SEC("xdp")
int router(struct xdp_md *ctx) {
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

                struct ipv4_lpm_key key;
                key.prefixlen = 32;
                key.data = src_ip;
                
                __u8 *value = bpf_map_lookup_elem(&lpm, &key);

                if(value){
                    // bpf_printk("Matched with rule %u\n",value[0]);
                    // return XDP_DROP;
                    goto end;
                }else{
                    // bpf_printk("Not Matched\n");
                    // return XDP_DROP;
                    goto end;
                }
            }
        }
    }
    // return XDP_PASS;
end:
    return XDP_DROP;
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";