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

#define BATCH_SIZE 16

struct ipv4_lpm_key {
  __u32 prefixlen;
  __u32 data;
};

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
};

// LPM trie only — no flow cache. This variant keeps the exact same map as
// tbrouter and speeds up the batch purely by restructuring the code.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1000000);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u8);
  __uint(map_flags, BPF_F_NO_PREALLOC);

} lpm SEC(".maps");

static __always_inline int parse_saddr(void *data, void *data_end,
                                       __be32 *saddr) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end)
    return -1;

  __u16 h_proto = eth->h_proto;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end)
    return -1;
  *saddr = ip->saddr;

  return 0;
}

SEC("xdp")
int toorouter(struct xdp_md *ctx) {
  void *data = (void *)(long)(ctx->data);
  void *data_end = (void *)(long)(ctx->data_end);
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if (md + 1 > data) {
    bpf_printk("metadata header is not valid\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u8 *m = (__u8 *)data_meta;
  __u16 valid = bpf_ntohs(md->valid);

  // ---- Pass 1: parse (no map access) --------------------------------------
  // A packet's offset is the prefix sum of the previous packets' lengths, and
  // those lengths live entirely in the meta header (read inline at m + 2 + 2*i,
  // bounds-checked against the header end so any batch size 4/6/8/12/16 works;
  // packets past the header count as length 0). So every source IP can be
  // resolved up front, with zero dependency on any map lookup. Loop unrolled so
  // the parses issue back-to-back.
  struct ipv4_lpm_key keys[BATCH_SIZE];
  __u16 lentot = 0;
#pragma unroll
  for (int i = 0; i < BATCH_SIZE; i++) {
    keys[i].prefixlen = 32;
    keys[i].data = 0;
    if (valid & (1 << i)) {
      __be32 saddr = 0;
      if (parse_saddr(data + (lentot & 0x1FFF), data_end, &saddr) == 0)
        keys[i].data = saddr;
    }
    __u8 *lp = m + 2 + (i << 1);
    if (lp + 2 <= data)
      lentot += bpf_ntohs(*(__u16 *)lp);
  }

  // ---- Pass 2: lookups (code reordering / MLP) ----------------------------
  // Every key is already known, so the trie walks — each a chain of dependent,
  // cache-missing loads — carry no dependency on one another. Issuing them
  // back-to-back (unrolled) lets the CPU keep several lookups' memory accesses
  // in flight at once instead of serializing them behind the parse/advance work
  // of the next packet, as the single interleaved loop in tbrouter does.
  __u8 hits = 0;
#pragma unroll
  for (int i = 0; i < BATCH_SIZE; i++) {
    if (valid & (1 << i)) {
      __u8 *value = bpf_map_lookup_elem(&lpm, &keys[i]);
      if (value)
        hits++;
    }
  }
  (void)hits;

  return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
