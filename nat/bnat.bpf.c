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

#define BATCH_SIZE 16
// Packed per-slot verdict, 4 bits per slot (all 8 nibbles of the u32).
#define ALL_ACT(a) ((a) + ((a) << 4) + ((a) << 8) + ((a) << 12) + \
                    ((a) << 16) + ((a) << 20) + ((a) << 24) + ((a) << 28))

SEC("xdp")
int bnat(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;

    // Batch header in [data_meta, data): [u16 bitmap][u16 len_0]...[u16 len_14]
    // (network order, 16th length implicit). Each length is read inline and
    // bounds-checked against data, so a slot past the header counts as 0.
    // The offset mask is 0x7FFF (not 0x1FFF): it must cover the whole batch
    // (16 * 1518 + 32 B, inside the 32 KB RX buffer). It only bounds the offset
    // for the verifier; the data_end checks in get_ip/update_ipaddr are the
    // real protection.
    __u8 *m = (__u8 *)data_meta;
    if (m + 2 > (__u8 *)data)
        return ALL_ACT(XDP_DROP);
    __u16 valid = bpf_ntohs(*(__u16 *)m);

    __u16 lentot = 0;
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (valid & (1 << i)) {
            void *pkt = data + (lentot & 0x7FFF);
            // A bad frame (too short, lookup miss) skips only this slot.
            __be32 ip = get_ip(pkt, data_end);
            __be32 *nat_ip = bpf_map_lookup_elem(&external_map, &ip);
            if (nat_ip)
                update_ipaddr(pkt, data_end, *nat_ip);
        }
        // advance by this slot's length even when the slot is skipped
        __u8 *lp = m + 2 + (i << 1);
        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    return ALL_ACT(XDP_DROP);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
