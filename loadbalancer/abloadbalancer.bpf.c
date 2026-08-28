// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

/*
 * abloadbalancer — L4 load balancer, batched, unrolled + SIMD hashing (ab).
 *
 * NF:      same as loadbalancer.bpf.c — a hash of the 5-tuple modulo
 *          MAX_SERVERS (512) selects a backend from the `servers` array, then
 *          the Ethernet header is rewritten towards it.
 * Variant: batched, legacy fixed 4-slot header, fully unrolled — no loop and
 *          no `valid` test: four straight-line handle_pkt() calls into a
 *          32-byte-aligned pkts[4], then four backend selections, then four
 *          update_eth() rewrites, so each phase of the batch runs together.
 * Opt:     this file carries both hashing paths. The active one is
 *          singlehash(), a scalar xxhash64 per packet with a different seed
 *          each (77/91/93/61) so the four packets spread across backends; the
 *          batched hash() above it feeds all four 5-tuples to the xxhash16x4()
 *          kfunc in one AVX-512 call and is left in place for the SIMD
 *          comparison.
 * Needs:   the xxhash kernel module loaded first when the kfunc path is used —
 *          `make -C xxhash load`.
 * Verdict: packed nibbles, XDP_DROP in every slot.
 */

#include "common.h"
#include "fasthash.h"
#include "xxhash64.h"
#include "jhash.h"
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

void xxhash16x4(const __u8 *buf, const __u32 seed, __u8 *out) __ksym;

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u32 proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SERVERS);
  __type(key, __u64);
  __type(value, struct dest_info);
} servers SEC(".maps");

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt_5tuple *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end) {
    bpf_printk("eth + 1 >= data_end\n");
    return XDP_DROP;
  }

  __u16 h_proto = eth->h_proto;

  switch (h_proto) {
  case bpf_htons(ETH_P_IP):
    break;
  default:
    bpf_printk("hproto\n");
    return XDP_DROP;
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end) {
    bpf_printk("ip\n");
    return XDP_DROP;
  }
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
    bpf_printk("l4\n");
    return XDP_DROP;
  }
  return 0;
}
static __always_inline void set_ethhdr(struct ethhdr *new_eth,
                                       const struct ethhdr *old_eth,
                                       const struct dest_info *tnl,
                                       __be16 h_proto) {

  memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
  memcpy(new_eth->h_dest, tnl->dmac, sizeof(new_eth->h_dest));
  new_eth->h_proto = h_proto;
}

static __always_inline struct dest_info *singlehash(const void *pkt,
                                              const __u64 len, __u32 seed) {
  struct dest_info *tnl;

  __u64 key =
      xxhash64(pkt, sizeof(struct pkt_5tuple), seed) % MAX_SERVERS;
  // bpf_printk("hash key: %\n", key);
  tnl = bpf_map_lookup_elem(&servers, &key);
  if (!tnl) {
    key = 0;
    tnl = bpf_map_lookup_elem(&servers, &key);
    if (!tnl) {
      bpf_printk("tnl is null\n");
      return NULL;
    }
  }
  return tnl;
}



static __always_inline __u64 hash(const struct pkt_5tuple *pkts,
                                  struct dest_info *tnls[4]) {
  __u64 h[8] = {0}; // 512 bit

  xxhash16x4((__u8 *)pkts, _SEED_HASHFN, (__u8 *)h);

  for (int i = 0; i < 4; i++) {
    __u64 key = h[i * 2] % MAX_SERVERS;
    tnls[i] = bpf_map_lookup_elem(&servers, &key);
    // bpf_printk("hash key: %d\n", h[i * 2]);

    if (!tnls[i]) {
      key = 0;
      tnls[i] = bpf_map_lookup_elem(&servers, &key);
      if (!tnls[i]) {
        return 1;
      }
    }
  }
  return 0;
}

static __always_inline int update_eth(void *data, void *data_end, __u64 off,
                                      struct dest_info *tnl) {
  struct iphdr *iph;
  __u16 payload_len = bpf_ntohs(iph->tot_len);
  __u16 *next_iph_u16;
  __u32 csum = 0;

  iph = data + off;
  if (iph + 1 > data_end) {
    bpf_printk("iph + 1 > data_end\n");
    return XDP_DROP;
  }
  struct iphdr iph_tnl;
  // set_ethhdr(data, tnl, bpf_htons(ETH_P_IP));
  struct ethhdr *new_eth = data;
  struct ethhdr *old_eth = data + sizeof(*iph);
  set_ethhdr(new_eth, old_eth, tnl, bpf_htons(ETH_P_IP));

  /* create an additional ip header for encapsulation */
  iph_tnl.version = 4;
  iph_tnl.ihl = sizeof(*iph) >> 2;
  iph_tnl.frag_off = 0;
  iph_tnl.protocol = IPPROTO_IPIP;
  iph_tnl.check = 0;
  iph_tnl.id = 0;
  iph_tnl.tos = 0;
  iph_tnl.tot_len = bpf_htons(payload_len + sizeof(*iph));
  iph_tnl.daddr = tnl->daddr;
  iph_tnl.saddr = tnl->saddr;
  iph_tnl.ttl = 8;

  /* calculate ip header checksum */
  next_iph_u16 = (__u16 *)&iph_tnl;
#pragma clang loop unroll(full)
  for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
    csum += *next_iph_u16++;
  iph_tnl.check = ~((csum & 0xffff) + (csum >> 16));

  // iph = data + sizeof(*new_eth);
  *iph = iph_tnl;

  return 0;
}

SEC("xdp")
int abloadbalancer(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if ((void *)(md + 1) > data) {
    bpf_printk("md + 1 > data\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 lentot = 0;
  __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),
                   bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

  struct ethhdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  int err;

  nh_off = sizeof(struct ethhdr);
  if (data + nh_off > data_end) {
    bpf_printk("data + nh_off > data_end\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
  eth_proto = eth->h_proto;

  struct pkt_5tuple pkts[4] __attribute__((aligned(32)));
  struct dest_info *tnls[4];
  __u64 pkts_hashes[4];

  int ret1 = handle_pkt(data, data_end, &pkts[0]);
  int ret2 = handle_pkt(data + (lens[0] & 0x1FFF), data_end, &pkts[1]);
  int ret3 =
      handle_pkt(data + ((lens[0] + lens[1]) & 0x1FFF), data_end, &pkts[2]);
  int ret4 = handle_pkt(data + ((lens[0] + lens[1] + lens[2]) & 0x1FFF), data_end,
                        &pkts[3]);
  if (ret1 || ret2 || ret3 || ret4) {
    // if (ret1 || ret2 || ret3){
    // if (ret1 || ret2){
    // bpf_printk("ret1: %d ret2: %d ret3: %d ret4:%d\n", ret1, ret2, ret3,
    // ret4);
    bpf_printk("ret1: %d ret2: %d\n", ret1, ret2);
    bpf_printk("handle_pkt failed\n");
    return ret1;
  }
  //err = 
  // hash(pkts, tnls);
  tnls[0] = singlehash(&pkts[0], sizeof(pkts[0]), 77);
  tnls[1] = singlehash(&pkts[1], sizeof(pkts[1]), 91);
  tnls[2] = singlehash(&pkts[2], sizeof(pkts[2]), 93);
  tnls[3] = singlehash(&pkts[3], sizeof(pkts[3]), 61);

  // tnls[0] = singlehash(&pkts[0], sizeof(pkts[0]), 77);
  // tnls[1] = singlehash(&pkts[0], sizeof(pkts[0]), 91);
  // tnls[2] = singlehash(&pkts[0], sizeof(pkts[0]), 93);
  // tnls[3] = singlehash(&pkts[0], sizeof(pkts[0]), 61);

  if (!tnls[0] || !tnls[1] || !tnls[2] || !tnls[3]) {
    bpf_printk("hash failed\n");
    return XDP_DROP;
  }
  //if (err) {
  //  bpf_printk("hash failed\n");
  //  return XDP_DROP;
  //}


  ret1 = update_eth(data, data_end, nh_off, tnls[0]);
  ret2 = update_eth(data + (lens[0] & 0x1FFF), data_end, nh_off, tnls[1]);
  ret3 = update_eth(data + ((lens[0] + lens[1]) & 0x1FFF), data_end, nh_off,
                    tnls[2]);
  ret4 = update_eth(data + ((lens[0] + lens[1] + lens[2]) & 0x1FFF), data_end,
                    nh_off, tnls[3]);

  if (ret1 || ret2 || ret3 || ret4) {
    // if (ret1 || ret2 || ret3){
    // if (ret1 || ret2){
     bpf_printk("ret1: %d ret2: %d ret3: %d ret4:%d\n", ret1, ret2, ret3,
     ret4);
    //bpf_printk("ret1: %d ret2: %d\n", ret1, ret2);
    bpf_printk("update eth\n");
    return ret1;
  }

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char __license[] SEC("license") = "GPL";
