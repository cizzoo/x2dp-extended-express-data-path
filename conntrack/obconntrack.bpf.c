/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Part of the code has been taken and adapted from the Polycube project
 * (https://github.com/polycube-network/polycube) */

/* Copyright (c) 2017 The Polycube Authors */
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

#define ALL_DROP                                                               \
    (XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12) +         \
     (XDP_DROP << 16) + (XDP_DROP << 20) + (XDP_DROP << 24) + (XDP_DROP << 28))

/* Debug/error logging compiled out, as in salbconntrack and (l)pobconntrack:
 * even gated by the const volatile log_level, each site costs a .rodata load
 * and a branch that the verifier walks once per packet of the batch. */
#undef bpf_log_debug
#define bpf_log_debug(fmt, ...) do {} while (0)
#undef bpf_log_err
#define bpf_log_err(fmt, ...) do {} while (0)

/* Takes the batch timestamp as a parameter: one bpf_ktime_get_ns() per batch,
 * see the note above obconntrack(). */
static FORCE_INLINE int track(struct packetHeaders *pkt, uint64_t timestamp){
    struct ct_k key;
    /* No memset: ct_k is packed (no padding) and all five fields are assigned
     * below on every path. */
    uint8_t ipRev = 0;
    uint8_t portRev = 0;
    if (pkt->srcIp <= pkt->dstIp) {
        key.srcIp = pkt->srcIp;
        key.dstIp = pkt->dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt->dstIp;
        key.dstIp = pkt->srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt->l4proto;

    if (pkt->srcPort < pkt->dstPort) {
        key.srcPort = pkt->srcPort;
        key.dstPort = pkt->dstPort;
        portRev = 0;
    } else if (pkt->srcPort > pkt->dstPort) {
        key.srcPort = pkt->dstPort;
        key.dstPort = pkt->srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt->srcPort;
        key.dstPort = pkt->dstPort;
        portRev = ipRev;
    }

    /* newEntry is only consumed by the two bpf_map_update_elem() calls below,
     * so it is zeroed there instead of on every packet (bpf_map_update_elem
     * copies sizeof(ct_v), so the padding and the unused lock field do have to
     * be initialized -- but only when we actually insert). */
    struct ct_v newEntry;
    struct ct_v *value;

    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            goto PASS_ACTION;
        }
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            // ctr_spin_lock(&value->lock);
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto TCP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto TCP_REVERSE;
            } else {
                // ctr_spin_unlock(&value->lock);
                goto TCP_MISS;
            }

        TCP_FORWARD:;

            // Found in forward direction
            if (value->state == SYN_SENT) {
                // Still haven't received a SYN,ACK To the SYN
                if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
                    // Another SYN. It is valid, probably a retransmission.
                    value->ttl = timestamp + TCP_SYN_SENT;

                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                } else {
                    // Receiving packets outside the 3-Way handshake without
                    // completing the handshake
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_SENT state. Flags: %x\n",
                                  pkt->flags);
                    pkt->connStatus = INVALID;

                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == SYN_RECV) {
                // Expecting an ACK here
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags | TCPHDR_ACK) == TCPHDR_ACK &&
                    (pkt->ackN == value->sequence)) {
                    // Valid ACK to the SYN, ACK
                    value->state = ESTABLISHED;
                    value->ttl = timestamp + TCP_ESTABLISHED;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "SYN_RECV to ESTABLISHED\n");

                    goto PASS_ACTION;
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // Received first FIN from "original" direction.
                    // Changing state to FIN_WAIT_1
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt->ackN;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %u\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                // Received FIN in reverse direction, waiting for ack from this
                // side
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == value->sequence)) {
                    // Received ACK
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    // ctr_spin_lock(&value->lock);
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in rev direction, waiting the
                // FIN from the this side
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt->ackN;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    // Still receiving packets
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt->flags & TCPHDR_ACK && pkt->seqN == value->sequence) != 0) {
                    // Ack to the last FIN.
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");
                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt->connStatus == NEW) {
                    // ctr_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            // ctr_spin_unlock(&value->lock);
            bpf_log_debug("[FW_DIRECTION] Should not get here. "
                          "Flags: %x. State: %d. \n",
                          pkt->flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;

            // Found in reverse direction
            if (value->state == SYN_SENT) {
                // This should be a SYN, ACK answer
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                    (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt->ackN == value->sequence) {
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt->seqN + HEX_BE_ONE;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");

                    goto PASS_ACTION;
                }
                // Here is an unexpected packet, only a SYN, ACK is acepted as
                // an answer to a SYN
                pkt->connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == SYN_RECV) {
                // The only acceptable packet in SYN_RECV here is a SYN,ACK
                // retransmission
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                    (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt->ackN == value->sequence) {
                    value->ttl = timestamp + TCP_SYN_RECV;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
                pkt->connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt->ackN;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %x\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                // Received FIN in reverse direction, waiting for ack from this
                // side
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == value->sequence)) {
                    // Received ACK
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    // ctr_spin_lock(&value->lock);

                    // Don't forward packet, we can continue performing the
                    // check in case the current packet is a ACK,FIN. In this
                    // case we match the next if statement
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in "original" direction,
                // waiting the FIN from this side
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt->ackN;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    // Still receiving packets
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                                  pkt->flags, value->sequence);

                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt->flags & TCPHDR_ACK && pkt->seqN == value->sequence) != 0) {
                    // Ack to the last FIN.
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    // ctr_spin_unlock(&value->lock);

                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");

                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt->connStatus == NEW) {
                    // ctr_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            // ctr_spin_unlock(&value->lock);
            bpf_log_debug("[REV_DIRECTION] Should not get here. "
                          "Flags: %d. "
                          "State: %d. \n",
                          pkt->flags, value->state);
            goto PASS_ACTION;
        }

    TCP_MISS:;

        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            __builtin_memset(&newEntry, 0, sizeof(newEntry));
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt->seqN + HEX_BE_ONE;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            goto PASS_ACTION;
        }
    }

    if (pkt->l4proto == IPPROTO_UDP) {
        /* UDP is not tracked, as in the conntrack baseline (TCP only). */
        return ALL_DROP;
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            // ctr_spin_lock(&value->lock);
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto UDP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto UDP_REVERSE;
            } else {
                // ctr_spin_unlock(&value->lock);
                goto UDP_MISS;
            }

        UDP_FORWARD:;

            // Valid entry
            if (value->state == NEW) {
                // An entry was already present with the NEW state. This means
                // that there has been no answer, from the other side.
                // Connection is still NEW.
                // For now I am refreshing the TTL, this can lead to an
                // DoS attack where the attacker prevents the entry from being
                // deleted by continuosly sending packets.
                value->ttl = timestamp + UDP_NEW_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            } else {
                // value->state == ESTABLISHED
                value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

        UDP_REVERSE:;

            if (value->state == NEW) {
                // An entry was present in the rev direction with the NEW state.
                // This means that this is an answer, from the other side.
                // Connection is now ESTABLISHED.
                value->ttl = timestamp + UDP_NEW_TIMEOUT;
                value->state = ESTABLISHED;

                bpf_log_debug("[REV_DIRECTION] Changing state "
                              "from "
                              "NEW to ESTABLISHED\n");
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            } else {
                // value->state == ESTABLISHED
                value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }
        }

    UDP_MISS:;

        // No entry found in both directions. Create one.
        __builtin_memset(&newEntry, 0, sizeof(newEntry));
        newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
        newEntry.state = NEW;
        newEntry.sequence = 0;

        newEntry.ipRev = ipRev;
        newEntry.portRev = portRev;

        bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
        goto PASS_ACTION;
    }

PASS_ACTION:;

    //increase pkt counter
    // struct pkt_md *md;
    // __u32 md_key = 0;
    // md = bpf_map_lookup_elem(&metadata, &md_key);
    // if (md == NULL) {
    //     bpf_log_err("No elements found in metadata map\n");
    //     goto DROP;
    // }

    // uint16_t pkt_len = (uint16_t)(data_end - data);


    // // NO_TEAR_INC(md->cnt);
    // md->cnt++;
    // // NO_TEAR_ADD(md->bytes_cnt, pkt_len);
    // md->bytes_cnt += pkt_len;

    // if (conntrack_cfg.if_index_if2 == 0) {
    //     bpf_log_err("Redirection is disabled\n");
    //     goto DROP;
    // }

    if (pkt->connStatus == INVALID) {
        bpf_log_err("Connection status is invalid\n");
    }
    //swap mac for redirection
    // data_end = (void *)(long)ctx->data_end;
    // data = (void *)(long)ctx->data;

    // if (data + ETH_HLEN > data_end) {
    //     bpf_log_err("Packet after modification is invalid! DROP\n");
    //     return -1;
    // }

    // struct ethhdr *eth = (struct ethhdr *)data;
    // eth->h_proto = bpf_htons(ETH_P_IP);

    // __builtin_memcpy(eth->h_source, (void *)conntrack_mac_cfg.if2_src_mac, sizeof(eth->h_source));
    // __builtin_memcpy(eth->h_dest, (void *)conntrack_mac_cfg.if2_dst_mac, sizeof(eth->h_dest));
    // bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);

    // return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    return ALL_DROP;
}


/* Parser used on the hot path instead of parse_packet() from
 * conntrack_parser.h. Same job, but:
 *
 *   - no bpf_printk(): the two in parse_packet() ("Invalid ethertype",
 *     "L3 protocol: ...") were NOT gated by conntrack_cfg.log_level (they
 *     have since been removed from the header), so every
 *     ARP/IPv6/non-TCP-UDP frame in the trace paid a ~1 us trace-buffer write.
 *
 *   - the L4 header is located from nh_off, so a VLAN-tagged frame is parsed
 *     at the right offset (parse_packet() hardcodes ETH_HLEN + sizeof(iphdr)).
 *
 *   - it returns void and has a single exit. A packet that must not be
 *     tracked (slot not set in the bitmap, not IPv4, not TCP/UDP, truncated)
 *     comes back zeroed, and l4proto 0 makes track() fall straight through to
 *     PASS_ACTION without touching the connections map. That is what lets the
 *     caller invoke track() unconditionally: an "if (parsed_ok)" around each
 *     track() forks the verifier state per packet, and four of those in a row
 *     cost 297k processed instructions for a single group of 4 (the old
 *     4-packet obconntrack, which aborted the whole batch on the first
 *     failure and so kept one path, cost 35k).
 */
static FORCE_INLINE void parse_pkt_fast(void *data, void *data_end, int present,
                                        struct packetHeaders *pkt) {
    __u16 nh_off = ETH_HLEN;
    __u16 h_proto;

    __builtin_memset(pkt, 0, sizeof(*pkt));

    if (!present)
        return;

    if (data + nh_off > data_end)
        return;

    h_proto = ((struct ethhdr *)data)->h_proto;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct _vlan_hdr *vhdr = (struct _vlan_hdr *)(data + nh_off);

            nh_off += sizeof(struct _vlan_hdr);
            if (data + nh_off > data_end)
                return;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return;

    struct iphdr *iph = (struct iphdr *)(data + nh_off);

    if ((void *)(iph + 1) > data_end)
        return;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcp_hdr *tcp = (struct tcp_hdr *)((void *)iph + sizeof(*iph));

        if ((void *)(tcp + 1) > data_end)
            return;
        pkt->srcPort = tcp->source;
        pkt->dstPort = tcp->dest;
        pkt->seqN = tcp->seq;
        pkt->ackN = tcp->ack_seq;
        pkt->flags = tcp->flags;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)iph + sizeof(*iph));

        if ((void *)(udp + 1) > data_end)
            return;
        pkt->srcPort = udp->source;
        pkt->dstPort = udp->dest;
    } else {
        return;
    }

    pkt->srcIp = iph->saddr;
    pkt->dstIp = iph->daddr;
    /* Committed last: track() keys off l4proto, so it stays 0 (= ignore this
     * packet) on every path that did not reach a complete L4 header. */
    pkt->l4proto = iph->protocol;
}

/* Optimized batched conntrack, batch of up to 16, connections in the
 * BPF_MAP_TYPE_HASH from conntrack_maps.h (pobconntrack / lpobconntrack are
 * the same program on an open-addressed array table).
 *
 * Compared with bconntrack (the plain loop over the per-packet code):
 *   - ONE bpf_ktime_get_ns() per batch instead of one per packet: every packet
 *     in a batch is delivered by the same DMA transfer;
 *   - no bpf_printk() anywhere (parse_pkt_fast, logging compiled out);
 *   - no per-packet memset of the key, newEntry zeroed only on insert;
 *   - a packet that must not be tracked is skipped at no branch cost via
 *     l4proto 0 (see parse_pkt_fast), so track() is called unconditionally.
 *
 * The 4-packet version of this program parsed all packets up front and then
 * ran all the state machines (code reordering). That is NOT done here: at
 * batch 16 every extra packet kept in flight multiplies the verifier states
 * explored by track(). Measured on lpobconntrack: 2 or 4 packets in flight
 * exceed the 1M-instruction limit, 1 in flight is accepted (755k). Hence one
 * packet per iteration, in a bounded (not unrolled) loop.
 */
SEC("xdp")
int obconntrack(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *data_meta = (void *)(long)ctx->data_meta;

    /* Batch header in [data_meta, data): [u16 valid bitmap][u16 len_0]...
     * [u16 len_14], network order. Lengths are read inline, bounds-checked
     * against the end of the header (== data), so any batch size works and a
     * slot past the header counts as length 0. */
    __u8 *m = (__u8 *)data_meta;

    if (m + 2 > (__u8 *)data)
        return ALL_DROP;

    __u16 valid = bpf_ntohs(*(__u16 *)m);
    __u64 timestamp = bpf_ktime_get_ns();
    __u16 lentot = 0;

    for (int i = 0; i < 16; i++) {
        struct packetHeaders pkt;

        /* 0x7FFF covers the whole batch (16 * 1518 + 32 B, in the driver's
         * 32 KB RX buffer); it only bounds the offset for the verifier. */
        parse_pkt_fast(data + (lentot & 0x7FFF), data_end, valid & (1 << i),
                       &pkt);
        track(&pkt, timestamp);

        /* Advance OUTSIDE the validity test: an invalid slot still takes up
         * its bytes in the batch. */
        __u8 *lp = m + 2 + (i << 1);

        if (lp + 2 <= (__u8 *)data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }

    return ALL_DROP;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
