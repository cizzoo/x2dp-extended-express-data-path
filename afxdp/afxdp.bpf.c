/* SPDX-License-Identifier: GPL-2.0 */

/*
 * afxdp — AF_XDP baseline.
 *
 * Not an X2DP network function: this is the kernel-side half of the AF_XDP
 * comparison point, the redirect program the userspace socket app in this
 * directory attaches. The network function itself runs in user space on the
 * packets this program hands over.
 *
 * NF:      none — looks up the RX queue index in the XSKMAP and, if a socket is
 *          bound to that queue, redirects the packet to it.
 * Variant: single-packet, standard XDP.
 * Opt:     none.
 * Verdict: bare bpf_redirect_map() result, XDP_DROP as the fallback and when no
 *          socket is bound.
 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int afxdp(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;

	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, XDP_DROP);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";