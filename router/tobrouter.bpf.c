/*
 * tobrouter — IPv4 LPM lookup behind an LRU flow cache, batched, forwarding
 * path (t).
 *
 * NF:      torouter's resolve(): BPF_MAP_TYPE_LRU_HASH flow_cache (64k, keyed
 *          by the /32 source IP) first, LPM trie (1M entries) on a miss, and a
 *          trie hit is inserted into the cache. handle_pkt() takes the source
 *          address without checking the ethertype.
 * Variant: batched, same batch loop as tbrouter: up to 16 slots gated by the
 *          `valid` bitmap, lengths read inline at data_meta + 2 + 2*i and
 *          bounds-checked against data, offset masked with 0x7FFF and advanced
 *          for every slot. A slot that fails to parse is skipped on its own.
 * Opt:     the flow cache only; parse and resolve stay interleaved per packet
 *          (no unrolling or reordering).
 * Verdict: packed nibbles, XDP_TX in all 8. Only a missing bitmap header
 *          returns a packed XDP_DROP.
 */

#include <linux/bpf.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

} lpm SEC(".maps");

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

static __always_inline int handle_pkt(void *data, void *data_end,
                                      __be32 *saddr) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end)
    return -1;

  __u16 h_proto = eth->h_proto;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end)
    return -1;
  *saddr = ip->saddr;
  // bpf_printk("src_ip: %pI4\n", saddr);

  return 0;
}

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
int tobrouter(struct xdp_md *ctx) {
  void *data = (void *)(long)(ctx->data);
  void *data_end = (void *)(long)(ctx->data_end);
  void *data_meta = (void *)(long)ctx->data_meta;

  // Per-packet lengths live in the long header at m + 2 + 2*i (network order),
  // where m = data_meta and the header spans [data_meta, data). Each length is
  // read inline in the loop below, bounds-checked against the header end, so any
  // batch size works (4/6/8/12/16) and missing packets (past the header) count
  // as length 0. Inline (not an array via size tiers) keeps the verifier cheap.
  __u8 *m = (__u8 *)data_meta;
  if (m + 2 > (__u8 *)data)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);

  __u16 valid = bpf_ntohs(*(__u16 *)m);
  // The mask on lentot below is 0x7FFF, not 0x1FFF: it must cover the WHOLE
  // batch (16 * 1518 + 32 = 24320 B, in the driver 32 KB RX buffer) or the
  // offset wraps and the tail packets are parsed from the start of the
  // buffer. It only bounds the offset for the verifier; the real protection
  // stays the data_end checks in the per-packet parser.
  __u16 lentot = 0;
  for (int i = 0; i < 16; i++) {
    if (valid & (1 << i)) {
      __be32 saddr;

      // on parse failure skip only this packet, never abort the batch
      if (handle_pkt(data + (lentot & 0x7FFF), data_end, &saddr) == 0) {
        __u8 *value = resolve(saddr);
        (void)value;
      }
    }

    // advance by this slot's real length (0 if past the header), outside the
    // validity test so invalid/skipped slots still move the offset
    __u8 *lp = m + 2 + (i << 1);
    if (lp + 2 <= (__u8 *)data)
      lentot += bpf_ntohs(*(__u16 *)lp);
  }

  return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12) + (XDP_TX << 16) + (XDP_TX << 20) + (XDP_TX << 24) + (XDP_TX << 28);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
