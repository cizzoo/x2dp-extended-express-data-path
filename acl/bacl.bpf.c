/*
 * bacl — access control list, batched.
 *
 * NF:      same rule table as acl.bpf.c — an array of struct pkt5 swept with
 *          bpf_for_each_map_elem().
 * Variant: batched, legacy fixed 4-slot header; the loop parses every valid
 *          slot into a pkts[4] array carried inside the callback context.
 * Opt:     the point of the variant — the rule table is swept ONCE for the
 *          whole batch instead of once per packet. apply_rule() checks the rule
 *          it was handed against all four 5-tuples in the context, accumulating
 *          one nibble of the packed verdict per packet and decrementing
 *          batch_size so the sweep can stop early once every packet has
 *          matched. That turns N sweeps of a 100k-entry table into one.
 * Verdict: packed nibbles — the accumulated per-packet verdict on a match,
 *          otherwise packed XDP_DROP.
 */

#include "common.h"
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// DEBUG
static __u64 dropped = 0;
static __u64 passed = 0;
static __u64 map_calls = 0;
static __u64 pkt_cnt = 0;


struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u32);
  __type(value, struct pkt5);
} rule_tbl SEC(".maps");

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt5 *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 > data_end)
    return XDP_DROP;

  __u16 h_proto = eth->h_proto;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 > data_end)
    return XDP_DROP;

  pkt->src_ip = ip->saddr;
  pkt->dst_ip = ip->daddr;
  pkt->proto = ip->protocol;

  switch (ip->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > data_end)
      return XDP_DROP;
    pkt->src_port = tcp->source;
    pkt->dst_port = tcp->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (udp + 1 > data_end)
      return XDP_DROP;
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    break;
  }
  default:
    return XDP_DROP;
  }
  return 0;
}

struct callback_data {
  struct pkt5 pkts[4];
  int verdict;
  __u16 valid;
  int batch_size;
};

static __always_inline __u64 hash_pkt5(const struct pkt5 *pkt) {
  __u64 hash = 0;
  hash ^= (__u64)pkt->src_ip << 32 | pkt->dst_ip;
  hash ^= (__u64)pkt->src_port << 16 | pkt->dst_port;
  hash ^= pkt->proto;
  return hash;
}

static __always_inline int compare_pkt5(const struct pkt5 *a,
                                        const struct pkt5 *b) {
  return hash_pkt5(a) == hash_pkt5(b);
}

static __always_inline int my_cmp_eq(const unsigned char *a,
                                     const unsigned char *b) {
  for (int i = 0; i < sizeof(struct pkt5); i++) {
    if (a[i] != b[i]) {
      return 1;
    }
  }
  return 0;
}

static __always_inline int my_is_eq(const unsigned char *a,
                                    const unsigned char *b) {
  for (int i = 0; i < sizeof(struct pkt5); i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

static __u64 apply_rule2(struct bpf_map *map, const void *key, void *value,
                        void *ctx) {
    
  return 0;
              
}

static __u64 apply_rule(struct bpf_map *map, const void *key, void *value,
                        void *ctx) {
  struct callback_data *cb_data = ctx;

  // if (cb_data->batch_size == 0)
  //   return 1;

  struct pkt5 *rule = value;

  struct pkt5 *pkt;
  // the verifier complains about the following loop, so I'm using the unrolled
  // version below
  // The sequence of 8193 jumps is too complex.
  for (int i = 0; i < 4; i++) {
    pkt = &cb_data->pkts[i];
    // if (pkt->dst_ip == rule->dst_ip && pkt->src_ip == rule->src_ip &&
    //     pkt->dst_port == rule->dst_port && pkt->src_port == rule->src_port &&
    //     pkt->proto == rule->proto) {
    //   cb_data->verdict += (XDP_DROP << (4 * i));
    //   pkt->dst_ip = -1; // mark as matched
    //   cb_data->batch_size--;
    // }
    if (pkt->dst_ip != rule->dst_ip && pkt->src_ip != rule->src_ip &&
        pkt->dst_port != rule->dst_port && pkt->src_port != rule->src_port &&
        pkt->proto != rule->proto) {
      cb_data->verdict += (XDP_DROP << (4 * i));
      pkt->dst_ip = -1; // mark as matched
      cb_data->batch_size--;
    }

  }

  // memcmp seems to be to slow, so I'm using a custom function
  //  for (int i = 0; i < 4; i++) {
  //    pkt = &cb_data->pkts[i];
  //    if (my_cmp_eq((unsigned char *)pkt, (unsigned char *)rule)) {
  //      cb_data->verdict += (XDP_DROP << (4 * i));
  //      pkt->dst_ip = -1; // mark as matched
  //      cb_data->batch_size--;
  //    }
  //  }
  map_calls++;
  // XDP_PASS is 0, so if the verdict is changed, this mean we found a match,
  // returning 1 the loop will stop
  return 0;
}

struct t_meta {
  __u16 valid;
  __u16 len1;
  __u16 len2;
  __u16 len3;
};

static long check_rule(__u64 index, void *ctx) {
  struct callback_data *cb_data = ctx;
  struct pkt5 *pkt;
  struct pkt5 *rule;

  for (int i = 0; i < 4; i++) {
    pkt = &cb_data->pkts[i];
    rule = bpf_map_lookup_elem(&rule_tbl, &index);
    if (rule) {
      if (my_is_eq((unsigned char *)pkt, (unsigned char *)rule)) {
        cb_data->verdict += (XDP_DROP << (4 * i));
        pkt->dst_ip = -1; // mark as matched
        cb_data->batch_size--;
      }
    }
  }
  return 0;
}

SEC("xdp") int bacl(struct xdp_md *ctx) {
  // pkt_cnt++;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  struct t_meta *meta = data_meta;
  if (meta + 1 > data)
    return XDP_DROP;

  struct pkt5 pkts[4]={0};
  __u16 lens[4] = {meta->len1, meta->len2, meta->len3, 0};

  struct callback_data cb_data = {
      .pkts = {0},
      .verdict = XDP_PASS,
      .valid = bpf_ntohs(meta->valid),
      .batch_size = 0,
  };

  __u16 lentot = 0;
  for (int i = 0; i < 4; i++) {
    if (bpf_ntohs(meta->valid) & (1 << i)) {
      cb_data.batch_size++;
      if (handle_pkt(data + (lentot & 0x0FF), data_end, &pkts[i]))
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

      cb_data.pkts[i] = pkts[i];
      lentot += bpf_ntohs(lens[i]);
    }
  }

  // __u64 start2 = bpf_ktime_get_ns();
  bpf_for_each_map_elem(&rule_tbl, &apply_rule, &cb_data, 0);
  // __u64 end2 = bpf_ktime_get_ns();

  // bpf_printk("Time: %llu\n", end2 - start2);

  // map_calls = bpf_loop(MAX_ENTRIES, &check_rule, &cb_data, 0);

  if (cb_data.verdict ==
      (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12))) {
    dropped++;
    return cb_data.verdict;
  } else {
    passed++;
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
}

char _license[] SEC("license") = "GPL";