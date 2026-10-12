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
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>


void xxhash16x4(const __u64 *buf, const __u32 seed, __u8 *out) __ksym;

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576

struct t_meta {
  __u16 valid;
  __u16 len[15];   // 15 explicit per-packet lengths (batch 16)
};

struct countmin {
  __u64 values[HASHFN_N][COLUMNS];
};

#ifndef ALGN
#define ALGN 64
#endif

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

static __always_inline void hash(const struct pkt_5tuple *pkt,
                                 __u16 hashes[4][4]) {
  __u64 h[8] = {0}; // 512 bit
  // bpf_printk("is alligned %d\n", ((unsigned long)pkt) % 64);
  // bpf_printk("valid_cnt: %d\n", valid_cnt);
  xxhash16x4((__u64 *)pkt, _SEED_HASHFN, (__u8 *)h);

  // bpf_printk("non crash: %x\n %x\n %x\n %x\n", h[0], h[1], h[2], h[3]);
  // bpf_printk("hashe:ws:\n%x\n %x\n %x\n %x\n", h[0], h[1], h[2], h[3]);
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
                                         const __u16 hashes[4][4]) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      __u32 target_idx = hashes[i][j] & (COLUMNS - 1);
      //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash
      // clang
      cm->values[i][target_idx]++;
    }
  }
  return;
}

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt_5tuple *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  __u16 h_proto = eth->h_proto;

  switch (h_proto) {
  case bpf_htons(ETH_P_IP):
    break;
  default:
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  pkt->src_ip = ip->saddr;
  pkt->dst_ip = ip->daddr;
  pkt->proto = ip->protocol;
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
    if (udp + 1 > data_end)
      return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    break;
  }
  default:
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
  return 0;
}

SEC("xdp")
int abcms(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if (md + 1 > data)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  __u16 lentot = 0;
  __u16 lens[15];
  #pragma unroll
  for (int i = 0; i < 15; i++)
    lens[i] = bpf_ntohs(md->len[i]);

  __u32 zero = 0;
  struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
  if (!cm)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  // Unpacked pkt_5tuple is 16 B, so 4 of them are a 64 B (512-bit) SIMD block.
  struct pkt_5tuple pkts[16] __attribute__((aligned(32))) = {0};
  __u16 pkts_hashes[16][4] = {0};

  // Parse the whole batch of 16 (bitmap-aware).
  for (int i = 0; i < 16; i++) {
    if (bpf_ntohs(md->valid) & (1 << i)) {
      int ret = handle_pkt(data + (lentot & 0x1FFF), data_end, &pkts[i]);
      if (ret) {
        bpf_printk("handle_pkt failed at i %d\n", i);
        return ret;
      }
    }
    if (i < 15)
      lentot += lens[i];
  }

  // SIMD hash 4 packets per call -> 4 calls for the batch of 16.
  hash(&pkts[0],  pkts_hashes + 0);
  hash(&pkts[4],  pkts_hashes + 4);
  hash(&pkts[8],  pkts_hashes + 8);
  hash(&pkts[12], pkts_hashes + 12);

  // Update the sketch, one group of 4 per call.
  countmin_add(cm, pkts_hashes + 0);
  countmin_add(cm, pkts_hashes + 4);
  countmin_add(cm, pkts_hashes + 8);
  countmin_add(cm, pkts_hashes + 12);

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
