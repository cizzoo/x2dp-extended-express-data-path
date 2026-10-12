/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fasthash.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

struct t_meta {
  unsigned short valid;
  unsigned short len[15];   // 15 explicit per-packet lengths (batch 16)
};

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576

#ifndef ALGN
#define ALGN 64
#endif

struct countmin {
  __u64 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct countmin);
} countmin SEC(".maps");

void xxhash16x4(const __u64 *buf, const __u32 seed, __u8 *out) __ksym;
void xxhash16x16(const __u64 *buf, const __u32 seed, __u64 *out) __ksym;

static __always_inline void hash(const struct pkt_5tuple *pkt,
                                 __u16 hashes[4][4], __u64 valid_cnt) {
  __u64 h[8] = {0}; // 512 bit

  xxhash16x4((__u64 *)pkt, 0, (__u8 *)h);

  int j = 0;
  for (int i = 0; i < 4; i++) {
    hashes[i][0] = (h[j] & 0xFFFF);
    hashes[i][1] = h[j] >> 16 & 0xFFFF;
    hashes[i][2] = h[j] >> 32 & 0xFFFF;
    hashes[i][3] = h[j] >> 48 & 0xFFFF;
    j += 2;
  }
  return;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static __always_inline void countmin_add(struct countmin *cm,
                                         const __u16 hashes[4]) {
  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);
    //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash
    //clang
    cm->values[i][target_idx]++;
  }
  return;
}

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt_5tuple *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end) {
    bpf_printk("eth + 1 >= data_end\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 h_proto = eth->h_proto;

  switch (h_proto) {
  case bpf_htons(ETH_P_IP):
    break;
  default:
    bpf_printk("eth\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) >= data_end)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  pkt->src_ip = ip->saddr;
  pkt->dst_ip = ip->daddr;
  pkt->proto = ip->protocol;
  // bpf_printk("src_ip: %pI4\n", &ip->saddr);
  switch (ip->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > data_end)
      return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    pkt->src_port = tcp->source;
    pkt->dst_port = tcp->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udp + 1) > data_end) {
      bpf_printk("udp\n");
      return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    break;
  }
  default:
    bpf_printk("proto\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
  return 0;
}

SEC("xdp")
int aobnitro1(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if ((void *)(md + 1) > data) {
    bpf_printk("md + 1 > data\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 lens[15];
  #pragma unroll
  for (int i = 0; i < 15; i++)
    lens[i] = bpf_ntohs(md->len[i]);

  int samplerate = 4;
  __u32 mask = (1 << samplerate) - 1;

  // Whole-batch sampling, same structure as aobnitro2 (which drops per batch via
  // the geometric counter). One PRNG draw decides the entire batch: with
  // probability 1/2^samplerate it is processed, otherwise dropped. The mean
  // sampling fraction is identical to the per-packet variant
  // (E[counted] = 16/2^samplerate per batch), but now when a batch IS processed
  // all 16 lanes are needed, so the fixed-width xxhash16x16 is never wasted --
  // that waste is exactly why per-packet aobnitro1 lost to scalar obnitro1.
  if ((bpf_get_prandom_u32() & mask) != 0)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  __u32 zero = 0;
  struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
  if (!cm)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  struct pkt_5tuple pkts[16] __attribute__((aligned(32))) = {0};
  __u64 pkt_hashes[16] = {0};

  // Parse all 16 packets into the contiguous buffer, hash them in ONE SIMD call
  // (4 interleaved chains inside the kfunc, one FPU region), then update the
  // sketch for all 16 (deferred). Rolled loops: pkts[16] (256 B) leaves no room
  // to unroll on the 512 B BPF stack.
  __u16 lentot = 0;
  int ret = 0;
  for (int i = 0; i < 16; i++) {
    ret |= handle_pkt(data + (lentot & 0x1FFF), data_end, &pkts[i]);
    if (i < 15)
      lentot += lens[i];
  }
  if (ret) {
    bpf_printk("handle_pkt failed\n");
    return ret;
  }

  xxhash16x16((const __u64 *)pkts, _SEED_HASHFN, pkt_hashes);

  for (int i = 0; i < 16; i++) {
    __u16 h4[4];
    h4[0] = pkt_hashes[i] & 0xFFFF;
    h4[1] = (pkt_hashes[i] >> 16) & 0xFFFF;
    h4[2] = (pkt_hashes[i] >> 32) & 0xFFFF;
    h4[3] = (pkt_hashes[i] >> 48) & 0xFFFF;
    countmin_add(cm, h4);
  }

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
