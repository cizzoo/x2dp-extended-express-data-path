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

/*
 * bpcounter — per-source-IP counting, batched, overlapped map lookups (p).
 *
 * Microbenchmark: isolates the prefetch effect of batching. Against bcounter,
 * the only thing that changes is WHEN the map lookups happen.
 *
 * NF:      same as counter.bpf.c — bump the counter keyed by ip->saddr in
 *          `proto_count_map` (BPF_MAP_TYPE_HASH, 16k entries here), inserting
 *          on first sight.
 * Variant: batched, legacy fixed 4-slot header, fully unrolled — no loop and no
 *          `valid` test; handle_pkt() is a plain (non-inlined) function that
 *          just returns each packet's source address.
 * Opt:     the four source addresses are extracted first, then all four
 *          bpf_map_lookup_elem() calls are issued back to back BEFORE any
 *          result is used, and only afterwards are the four counters
 *          incremented. The four independent hash probes are therefore in
 *          flight together, so a miss on one overlaps the others instead of
 *          stalling the packet that follows it.
 * Verdict: packed nibbles, XDP_DROP in every slot.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct t_meta
{
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
    // unsigned short len4;

};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256*64);
    __type(key, __u32);     // protocol number
    __type(value, __u64);  // packet count
} proto_count_map SEC(".maps");


__u32 handle_pkt(void *data, void *data_end) {
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return 0;

    // Controlla se è un pacchetto IP
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    __u8 proto = ip->protocol;
    __u32 src_ip = ip->saddr;
    return src_ip;
}

SEC("xdp")
int bpcounter(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data)
    {
        bpf_printk("md + 1 > data\n");
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
        // return XDP_PASS + (XDP_PASS << 4) + (XDP_PASS << 8) + (XDP_PASS << 12);
    }

    __u16 lentot = 0;
    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

    // bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
    // bpf_printk("lens: %d %d %d %d\n", lens[0], lens[1], lens[2], lens[3]);
    __u32 sip0;
    __u32 sip1;
    __u32 sip2;
    __u32 sip3;
    //for( int i = 0; i < 4; i++ ) {
        //if(bpf_ntohs(md->valid) & (1 << i)) {
    sip0 = handle_pkt(data + (lentot & 0x1FFF), data_end);
    sip1 = handle_pkt(data + (lentot +lens[0] & 0x1FFF), data_end);
    sip2 = handle_pkt(data + (lentot +lens[0] +lens[1]  & 0x1FFF), data_end);
    sip3 = handle_pkt(data + (lentot +lens[0] +lens[1] +lens[2] & 0x1FFF), data_end);
        //    lentot += lens[i];
        //}
    //}
    __u64 *count = bpf_map_lookup_elem(&proto_count_map, &sip0);
    __u64 *count1 = bpf_map_lookup_elem(&proto_count_map, &sip1);
    __u64 *count2 = bpf_map_lookup_elem(&proto_count_map, &sip2);
    __u64 *count3 = bpf_map_lookup_elem(&proto_count_map, &sip3);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_count_map, &sip0, &init_val, BPF_ANY);
    }
    if (count1) {
        __sync_fetch_and_add(count1, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_count_map, &sip1, &init_val, BPF_ANY);
    }
    if (count2) {
        __sync_fetch_and_add(count2, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_count_map, &sip2, &init_val, BPF_ANY);
    }
    if (count3) {
        __sync_fetch_and_add(count3, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_count_map, &sip3, &init_val, BPF_ANY);
    }
    
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
