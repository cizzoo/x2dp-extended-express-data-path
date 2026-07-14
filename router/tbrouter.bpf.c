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

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
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
  struct t_meta *md = data_meta;
  if (md + 1 > data) {
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  // Read the real per-packet lengths from the long batch header, which is
  // [data_meta, data): a 2-byte bitmap + (batch_size-1) 2-byte lengths, so
  // batch_size = (data - data_meta) / 2. Bounds-check once per size tier
  // (batch 16/8/4) instead of once per length: a per-element check inside the
  // loop forks verifier state on every packet and can blow past the 1M insn
  // limit in the heavier programs.
  __u16 lens[16] = {0};
  __u8 *m = (__u8 *)data_meta;
  if (m + 32 <= data) {          // batch 16: 15 explicit lengths
#pragma unroll
    for (int j = 0; j < 15; j++) lens[j] = bpf_ntohs(*(__u16 *)(m + 2 + (j << 1)));
  } else if (m + 16 <= data) {   // batch 8: 7 explicit lengths
#pragma unroll
    for (int j = 0; j < 7; j++) lens[j] = bpf_ntohs(*(__u16 *)(m + 2 + (j << 1)));
  } else if (m + 8 <= data) {    // batch 4: 3 explicit lengths
#pragma unroll
    for (int j = 0; j < 3; j++) lens[j] = bpf_ntohs(*(__u16 *)(m + 2 + (j << 1)));
  }
  __u16 lentot = 0;
  for (int i = 0; i < 16; i++) {
    if (bpf_ntohs(md->valid) & (1 << i)) {
      struct ipv4_lpm_key key;

      int ret = handle_pkt(data + (lentot & 0x1FFF), data_end, &key);
      if (ret)
        return ret;

      __u8 *value = bpf_map_lookup_elem(&lpm, &key);

      // if (!value) {
      //   bpf_printk("Not Matched");
      //   // return XDP_DROP;
      //   goto end;
      // }
      // // }else{
      //     // bpf_printk("Not Matched pkt 1\n");
      //     // return XDP_DROP;
      //     // goto end;
      // }

      lentot += lens[i];
    }
  }

end:
  return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
