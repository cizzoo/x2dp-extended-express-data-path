/*
 * abacl — access control list, batched + AVX-512 rule comparison (ab).
 *
 * NF:      same rule table as acl.bpf.c — an array of struct pkt5 swept with
 *          bpf_for_each_map_elem().
 * Variant: batched, legacy fixed 4-slot header; the loop parses every valid
 *          slot into a 4-entry pkts[] array.
 * Opt:     one sweep per batch (as in bacl) plus SIMD matching. The batch's
 *          four 5-tuples are loaded into a 512-bit register once, before the
 *          sweep, with the load_mm512i() kfunc; then each rule visited by
 *          apply_rule() is compared against all four packets in a single
 *          cmp_512_128_simd() kfunc call instead of a scalar field-by-field
 *          loop. The sweep still stops early once the batch is fully matched.
 * Needs:   the ACL helper module loaded first —
 *          `make -C acl/kernel_helpers load` (exports cmp_512_128_simd and
 *          load_mm512i).
 * Verdict: packed nibbles, XDP_DROP.
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
#include <string.h>

int cmp_512_128_simd(const struct pkt5 *arr2) __ksym;
void load_mm512i(const struct pkt5 *p) __ksym;

// DEBUG
// static __u64 passed = 0;
// static __u64 map_calls = 0;
// static __u64 pkt_cnt = 0;
// static __u64 avg_time = 0;

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
  int verdict;
  __u16 valid;
  int batch_size;
};

static __u64 apply_rule(struct bpf_map *map, const void *key, void *value,
                        void *ctx) {

  struct callback_data *cb_data = ctx;

  // if (cb_data->batch_size == 0)
  //   return 1;

  // struct pkt5 rule_copy[4] __attribute__((aligned(32)));
  // copy the rule to the stack 4 times
  // for (int i = 0; i < 4; i++) {
  //   memcpy(&rule_copy[i], value, sizeof(struct pkt5));
  // }

  if (cmp_512_128_simd(value)) {
    cb_data->verdict =
        XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    cb_data->batch_size = 0;
  }

  // XDP_PASS is 0, so if the verdict is changed, this mean we found a match,
  // returning 1 the loop will stop
  // map_calls++;
  return cb_data->batch_size ? 0 : 1;
}

struct t_meta {
  __u16 valid;
  __u16 len1;
  __u16 len2;
  __u16 len3;
};


SEC("xdp") int abacl(struct xdp_md *ctx) {
  // pkt_cnt++;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  struct t_meta *meta = data_meta;
  if (meta + 1 > data)
    return XDP_DROP;

  struct pkt5 pkts[4];
  __u16 lens[4] = {meta->len1, meta->len2, meta->len3, 0};

  struct callback_data cb_data = {
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
      lentot += bpf_ntohs(lens[i]);
    }
  }

  load_mm512i(pkts);
  // __u64 start2 = bpf_ktime_get_ns();

  bpf_for_each_map_elem(&rule_tbl, &apply_rule, &cb_data, 0);
  // map_calls = bpf_loop(MAX_ENTRIES, &check_rule, &cb_data, 0);
  // __u64 end2 = bpf_ktime_get_ns();
  // bpf_printk("Time: %llu\n", end2 - start2);

  if (cb_data.verdict ==
      (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12))) {
    return cb_data.verdict;
  } else {
    // passed++;
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
}

char _license[] SEC("license") = "GPL";