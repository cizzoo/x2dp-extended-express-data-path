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

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1000000);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u8);
  __uint(map_flags, BPF_F_NO_PREALLOC);

} lpm SEC(".maps");

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct ipv4_lpm_key *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end)
    return -1;

  __u16 h_proto = eth->h_proto;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end)
    return -1;
  pkt->data = ip->saddr;
  pkt->prefixlen = 32;
  // bpf_printk("src_ip: %pI4\n", &pkt->data);

  return 0;
}

SEC("xdp")
int tbrouter(struct xdp_md *ctx) {
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
      struct ipv4_lpm_key key;

      // on parse failure skip only this packet, never abort the batch
      if (handle_pkt(data + (lentot & 0x7FFF), data_end, &key) == 0) {
        __u8 *value = bpf_map_lookup_elem(&lpm, &key);
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
