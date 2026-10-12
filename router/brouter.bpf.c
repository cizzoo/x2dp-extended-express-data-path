/*
 * brouter — IPv4 LPM lookup, batched.
 *
 * NF:      same LPM trie lookup as router.bpf.c (1M entries, key built with
 *          prefixlen=32 from the source address); handle_pkt() builds the key
 *          per packet. Unlike router.bpf.c it does not check the ethertype:
 *          any frame long enough for Ethernet + IPv4 headers is looked up.
 * Variant: batched — one XDP invocation per batch of up to 16. A loop over 16
 *          slots gated by the `valid` bitmap (bit i = slot i); each length is
 *          read inline at data_meta + 2 + 2*i, bounds-checked against data (a
 *          slot past the header counts as 0), so one binary serves any batch
 *          size. The offset is masked with 0x7FFF and advanced for every slot,
 *          valid or not. A slot that fails handle_pkt() is skipped; the rest
 *          of the batch is still looked up.
 * Opt:     none beyond batching — one trie lookup per packet, in a loop.
 * Verdict: packed nibbles, XDP_DROP in all 8 (also when the bitmap is missing).
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
int brouter(struct xdp_md *ctx) {
  void *data = (void *)(long)(ctx->data);
  void *data_end = (void *)(long)(ctx->data_end);
  void *data_meta = (void *)(long)ctx->data_meta;

  // Batch header in [data_meta, data): __u16 bitmap, then per-packet __u16
  // lengths at m + 2 + 2*i (network order). Each length is read inline and
  // bounds-checked against data, so any batch size up to 16 works and slots
  // past the header count as length 0. The 0x7FFF mask covers the whole batch
  // (16 * 1518 + 32 B); it only bounds the offset for the verifier.
  __u8 *m = (__u8 *)data_meta;
  if (m + 2 > (__u8 *)data)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);

  __u16 valid = bpf_ntohs(*(__u16 *)m);
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
    // advance by this slot's length even if the slot is invalid or skipped
    __u8 *lp = m + 2 + (i << 1);
    if (lp + 2 <= (__u8 *)data)
      lentot += bpf_ntohs(*(__u16 *)lp);
  }

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) + (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
