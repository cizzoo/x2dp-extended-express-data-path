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
int brouter(struct xdp_md *ctx) {
  void *data = (void *)(long)(ctx->data);
  void *data_end = (void *)(long)(ctx->data_end);
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if (md + 1 > data) {
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),
                   bpf_ntohs(md->len3), bpf_ntohs(md->len3)};
  __u16 lentot = 0;
  for (int i = 0; i < 4; i++) {
    if (bpf_ntohs(md->valid) & (1 << i)) {
      struct ipv4_lpm_key key;

      int ret = handle_pkt(data + (lentot & 0x1FFF), data_end, &key);
      if (ret){
        return ret;
      }
      __u8 *value = bpf_map_lookup_elem(&lpm, &key);

      // if (value) {
      //   // bpf_printk("Matched pkt 1 with rule %u\n", value[0]);
      //   //     // return XDP_DROP;
      //   goto end;
        
      //   }// }else{
        //     // bpf_printk("Not Matched pkt 1\n");
        //     // return XDP_DROP;
        //     // goto end;
        // }

        lentot += lens[0];
      }
    }

  end:
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  };

  char LICENSE[] SEC("license") = "Dual BSD/GPL";
