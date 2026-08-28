/*
 * acl — access control list, single-packet baseline.
 *
 * NF:      the packet's 5-tuple is compared against a rule table held in a
 *          BPF_MAP_TYPE_ARRAY of struct pkt5 (MAX_ENTRIES, loaded from the
 *          *_rules.txt files; the evaluation sweeps 10 to 100k rules). The
 *          sweep itself is a bpf_for_each_map_elem() over the whole table with
 *          apply_rule() as the callback, which sets the verdict to XDP_DROP on
 *          an exact field-by-field match.
 * Variant: baseline — standard XDP, one invocation per packet, one full table
 *          sweep per packet.
 * Opt:     none — the callback compares fields directly, and the alternative
 *          hash/memcmp forms of the comparison are left commented out beside
 *          it. The static dropped/passed/map_calls/pkt_cnt counters are debug
 *          instrumentation.
 * Verdict: bare XDP_DROP on a rule match, bare XDP_TX otherwise.
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
  struct pkt5 pkt;
  int verdict;
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

static __u64 apply_rule(struct bpf_map *map, const void *key, void *value,
                        void *ctx) {
  struct callback_data *cb_data = ctx;
  struct pkt5 *rule = value;

  struct pkt5 *pkt = &cb_data->pkt;

  // if (memcmp(rule, pkt, sizeof(struct pkt5)) == 0) {
  //   cb_data->verdict = XDP_DROP;
  // }

  if (rule->src_ip == pkt->src_ip && rule->dst_ip == pkt->dst_ip &&
      rule->src_port == pkt->src_port && rule->dst_port == pkt->dst_port &&
      rule->proto == pkt->proto) {
    cb_data->verdict = XDP_DROP;
  }

  // if (compare_pkt5(rule, pkt)) {
  //   cb_data->verdict = XDP_DROP;
  //   return 1;
  // }

  // if (!my_cmp_eq((const unsigned char *)rule, (const unsigned char *)pkt)) {
  //   cb_data->verdict = XDP_DROP;
  //   return 1;
  // }
  map_calls++;
  return 0;
}

SEC("xdp") int acl(struct xdp_md *ctx) {
  pkt_cnt++;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct pkt5 pkt = {0};
  if (handle_pkt(data, data_end, &pkt))
    return XDP_DROP;

  struct callback_data cb_data = {
      .pkt = pkt,
      .verdict = XDP_PASS,
  };

  bpf_for_each_map_elem(&rule_tbl, &apply_rule, &cb_data, 0);

  if (cb_data.verdict == XDP_DROP) {
    dropped++;
    return XDP_DROP;
  } else {
    passed++;
    return XDP_TX;
  }
}

char _license[] SEC("license") = "GPL";