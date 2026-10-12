/* SPDX-License-Identifier: GPL-2.0 */

/*
 * redirect — bpf_redirect_map() forwarding, single-packet.
 *
 * Microbenchmark: the third way out of XDP, next to tx.bpf.c (bounce back out
 * the same NIC) and pass.bpf.c (up the stack) — forwarding to another device
 * through a DEVMAP.
 *
 * NF:      parses Ethernet + IPv4, looks the source MAC up in the
 *          `redirect_params` hash to get a destination MAC, writes it into the
 *          frame and redirects to port 0 of the `tx_port` DEVMAP. Both maps are
 *          filled by the loader.
 * Variant: baseline — plain per-packet XDP, one invocation per packet. Not
 *          an X2DP program: the X2DP driver does not support XDP_REDIRECT, so
 *          this only runs on a stock driver.
 * Opt:     none.
 * Verdict: bare bpf_redirect_map() result; bare XDP_DROP when the packet is
 *          malformed, is not IPv4, or its source MAC has no entry.
 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <string.h>

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 256);
} tx_port SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, unsigned char[ETH_ALEN]);
  __type(value, unsigned char[ETH_ALEN]);
  __uint(max_entries, 1);
} redirect_params SEC(".maps");

SEC("xdp")
int redirect(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  int action = XDP_DROP;
  unsigned char *dst;

  struct ethhdr *eth = data;
  if (data + sizeof(*eth) > data_end)
    return XDP_DROP;

  struct iphdr *ip = data + sizeof(*eth);
  if (data + sizeof(*ip) > data_end)
    return XDP_DROP;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_DROP;

  dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
  if (!dst)
    goto out;

  /* Set a proper destination address */
  memcpy(eth->h_dest, dst, ETH_ALEN);
  action = bpf_redirect_map(&tx_port, 0, 0);

out:
  return action;
}

char _license[] SEC("license") = "GPL";
