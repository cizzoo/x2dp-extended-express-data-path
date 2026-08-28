// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

/*
 * bloadbalancer — hash-based L4 load balancer, batched.
 *
 * NF:      same as loadbalancer.bpf.c — xxhash64 over the 5-tuple modulo
 *          MAX_SERVERS (512) selects a backend from the `servers` array, then
 *          the Ethernet header is rewritten towards it.
 * Variant: batched, legacy fixed 4-slot header; lens[] is read from
 *          `struct t_meta` and the loop walks 4 slots gated by the `valid`
 *          bitmap.
 * Opt:     none beyond batching — parse, hash, backend lookup and MAC rewrite
 *          per packet, in a loop.
 * Verdict: packed nibbles, XDP_DROP in every slot.
 */

#include "common.h"
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
  __u8 proto;
} __attribute__((packed));

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

static __always_inline struct dest_info *hash(const void *pkt,
                                              const __u64 len) {
  struct dest_info *tnl;

  __u64 key =
      xxhash64(pkt, sizeof(struct pkt_5tuple), _SEED_HASHFN) % MAX_SERVERS;
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
int bloadbalancer(struct xdp_md *ctx) {
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

  struct dest_info *tnl;

  nh_off = sizeof(struct ethhdr);
  if (data + nh_off > data_end) {
    bpf_printk("data + nh_off > data_end\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
  eth_proto = eth->h_proto;

  for (int i = 0; i < 4; i++) {
    if (bpf_ntohs(md->valid) & 1 << i) {

      struct pkt_5tuple pkt;

      int ret = handle_pkt(data + (lentot & 0x1FFF), data_end, &pkt);
      if (ret) {
        bpf_printk("handle_pkt failed\n");
        return ret;
      }
      __u64 key;
      tnl = hash(&pkt, sizeof(pkt));

      if (!tnl) {
        bpf_printk("hash failed\n");
        return XDP_DROP;
      }
      err = update_eth(data + (lentot & 0x1FFF), data_end, nh_off, tnl);
      if (err) {
        bpf_printk("update_eth failed\n");
      }

      lentot += lens[i];
    }
  }

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char __license[] SEC("license") = "GPL";
