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
int tbnat(struct xdp_md *ctx) {
  void *data = (void *)(long)(ctx->data);
  void *data_end = (void *)(long)(ctx->data_end);
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if ((void *)(md + 1) > data) {
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
  }

  // Per-packet lengths live in the long header at m + 2 + 2*i (network order),
  // where m = data_meta and the header spans [data_meta, data). Each length is
  // read inline in the loop below, bounds-checked against the header end, so any
  // batch size works (4/6/8/12/16) and missing packets (past the header) count
  // as length 0. Inline (not an array via size tiers) keeps the verifier cheap.
  __u8 *m = (__u8 *)data_meta;
  // The mask on lentot below is 0x7FFF, not 0x1FFF: it must cover the WHOLE
  // batch (16 * 1518 + 32 = 24320 B, in the driver 32 KB RX buffer) or the
  // offset wraps and the tail packets are parsed from the start of the
  // buffer. It only bounds the offset for the verifier; the real protection
  // stays the data_end checks in the per-packet parser.
  __u16 lentot = 0;
  // bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
  for (int i = 0; i < 16; i++) {
    if (bpf_ntohs(md->valid) & (1 << i)) {

      __be32 ip = get_ip(data + (lentot & 0x7FFF), data_end);
      if (ip < 0) {
        bpf_printk("get ip failed\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
      }

      __be32 *nat_ip = bpf_map_lookup_elem(&external_map, &ip);
      if (nat_ip == NULL) {
        bpf_printk("nat_ip failed\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
      }

      if (update_ipaddr(data+ (lentot & 0x7FFF), data_end, *nat_ip) < 0) {
        bpf_printk("update_ipaddr failed\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
      }

      // advance by this packet's real length (0 if past the header)
      __u8 *lp = m + 2 + (i << 1);
      if (lp + 2 <= data)
        lentot += bpf_ntohs(*(__u16 *)lp);
    }
  }

  return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12) + (XDP_TX << 16) + (XDP_TX << 20) + (XDP_TX << 24) + (XDP_TX << 28);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
