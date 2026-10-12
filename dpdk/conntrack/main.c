/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_mbuf_core.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_member.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>

#include <time.h>
#include <rte_jhash.h>
#include <rte_string_fns.h>

static volatile bool force_quit;

/* cost of the per-packet work, and NIC-side loss */
static uint64_t work_cycles;
static uint64_t work_pkts;


/* MAC updating enabled by default */
static int mac_updating = 1;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

struct __rte_cache_aligned port_pair_params {
#define NUM_PORTS 2
  uint16_t port[NUM_PORTS];
};

static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t nb_port_pair_params;

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct __rte_cache_aligned lcore_queue_conf {
  unsigned n_rx_port;
  unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
};
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_conf port_conf = {
    .txmode =
        {
            // .mq_mode = RTE_ETH_MQ_TX_NONE,
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

struct rte_mempool *l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct __rte_cache_aligned l2fwd_port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
};
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 second */

static void app_print_stats(void);

/* Print out statistics on packets dropped */
static void print_stats(void) {
  uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
  unsigned portid;

  total_packets_dropped = 0;
  total_packets_tx = 0;
  total_packets_rx = 0;

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

  /* Static variables to store previous statistics */
  static uint64_t prev_tx[RTE_MAX_ETHPORTS] = {0};
  static uint64_t prev_rx[RTE_MAX_ETHPORTS] = {0};
  static uint64_t prev_dropped[RTE_MAX_ETHPORTS] = {0};
  static uint64_t prev_total_rx = 0;

  /* Clear screen and move to top left */
  printf("%s%s", clr, topLeft);
  printf("\nPort statistics ====================================");

  for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
    /* skip disabled ports */
    if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
      continue;

    uint64_t diff_tx = port_statistics[portid].tx - prev_tx[portid];
    uint64_t diff_rx = port_statistics[portid].rx - prev_rx[portid];
    uint64_t diff_dropped =
        port_statistics[portid].dropped - prev_dropped[portid];

    printf("\nStatistics for port %u ------------------------------"
           "\nPackets received: %20" PRIu64 " (diff: %" PRIu64 ")"
           "\nPackets dropped: %21" PRIu64 " (diff: %" PRIu64 ")",
           portid,
           port_statistics[portid].rx, diff_rx, port_statistics[portid].dropped,
           diff_dropped);

    total_packets_dropped += port_statistics[portid].dropped;
    total_packets_tx += port_statistics[portid].tx;
    total_packets_rx += port_statistics[portid].rx;

    /* Update previous statistics */
    prev_tx[portid] = port_statistics[portid].tx;
    prev_rx[portid] = port_statistics[portid].rx;
    prev_dropped[portid] = port_statistics[portid].dropped;
  }

  {
    uint64_t period = timer_period / rte_get_timer_hz();
    uint64_t diff_total = total_packets_rx - prev_total_rx;

    if (period == 0)
      period = 1;
    printf("\nTotals ==============================================="
           "\nTotal packets received: %14" PRIu64
           "\nTotal packets dropped: %15" PRIu64
           "\nReceive rate: %14" PRIu64 " pkt/s  (%.3f Mpps)",
           total_packets_rx, total_packets_dropped, diff_total / period,
           (double)diff_total / period / 1e6);
    if (work_pkts) {
      double cpp = (double)work_cycles / (double)work_pkts;

      printf("\nPer-packet work: %14.1f cycles  -> ceiling ~%.3f Mpps",
             cpp, (double)rte_get_tsc_hz() / cpp / 1e6);
    }
    {
      struct rte_eth_stats es;

      if (rte_eth_stats_get(0, &es) == 0)
        printf("\nNIC imissed: %23" PRIu64 "  ierrors: %" PRIu64 "  rx_nombuf: %" PRIu64,
               es.imissed, es.ierrors, es.rx_nombuf);
    }
    app_print_stats();
    prev_total_rx = total_packets_rx;
  }
  printf("\n====================================================\n");

  fflush(stdout);
}

static void l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid) {
  struct rte_ether_hdr *eth;
  void *tmp;

  eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

  /* 02:00:00:00:00:xx */
  // tmp = &eth->dst_addr.addr_bytes[0];
  tmp = &eth->d_addr.addr_bytes[0];

  *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

  /* src addr */
  // rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->src_addr);
  rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);

}

/* ------------------------------------------------------------------ *
 * Conntrack, ported from the unoptimized XDP program
 * conntrack/conntrack.bpf.c (plus its parser, conntrack_parser.h).
 *
 * The state machine below is that file's, verbatim, with the BPF helpers
 * swapped for their userspace equivalents:
 *   bpf_map_lookup_elem(&connections, ...) -> ct_lookup()   (rte_hash)
 *   bpf_map_update_elem(&connections, ...) -> ct_update()   (rte_hash)
 *   bpf_ktime_get_ns()                     -> get_time_ns() (CLOCK_MONOTONIC)
 * The logging macros compile to nothing, which is what they do in the XDP
 * build too (its loader sets conntrack_cfg.log_level = DISABLED).
 * ------------------------------------------------------------------ */

#define bpf_log_debug(fmt, ...) do {} while (0)
#define bpf_log_err(fmt, ...) do {} while (0)

#define CONNTRACK_DROP -1
#define CONNTRACK_MAP_MAX_SIZE 65536

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_ACK 0x10

#define HEX_BE_ONE 0x1000000

/* ns, from conntrack_common.h */
#define UDP_ESTABLISHED_TIMEOUT 180000000000
#define UDP_NEW_TIMEOUT 30000000000
#define ICMP_TIMEOUT 30000000000
#define TCP_ESTABLISHED 432000000000000
#define TCP_SYN_SENT 120000000000
#define TCP_SYN_RECV 60000000000
#define TCP_LAST_ACK 30000000000
#define TCP_FIN_WAIT 120000000000
#define TCP_TIME_WAIT 120000000000

typedef enum {
  NEW,
  ESTABLISHED,
  RELATED,
  INVALID,
  SYN_SENT,
  SYN_RECV,
  FIN_WAIT_1,
  FIN_WAIT_2,
  LAST_ACK,
  TIME_WAIT
} conntrack_states_t;

/* from conntrack_structs.h */
struct packetHeaders {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t l4proto;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t flags;
  uint32_t seqN;
  uint32_t ackN;
  uint8_t connStatus;
};

struct ct_k {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t l4proto;
  uint16_t srcPort;
  uint16_t dstPort;
} __attribute__((packed));

struct ct_v {
  uint64_t ttl;
  uint8_t state;
  uint8_t ipRev;
  uint8_t portRev;
  uint32_t sequence;
  uint32_t lock; /* stands in for the unused bpf_spin_lock */
};

/* the BPF program reads the flags byte directly, tcp.h does not allow that */
struct tcp_hdr_flags {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t res1 : 4, doff : 4;
  uint8_t flags;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__((packed));

struct vlan_hdr_ct {
  uint16_t h_vlan_TCI;
  uint16_t h_vlan_encapsulated_proto;
};

/* connections map: BPF_MAP_TYPE_HASH with the same key and capacity */
static struct rte_hash *ct_connections;
static struct ct_v *ct_values;
static uint64_t ct_passed;
static uint64_t ct_dropped;

static void app_print_stats(void) {
  printf("\nConntrack passed: %20" PRIu64 "\nConntrack dropped: %19" PRIu64
         "\nConnections tracked: %17" PRIi32,
         ct_passed, ct_dropped,
         ct_connections ? rte_hash_count(ct_connections) : 0);
}

static inline uint64_t get_time_ns(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline struct ct_v *ct_lookup(const struct ct_k *key) {
  int32_t pos = rte_hash_lookup(ct_connections, key);

  if (pos < 0)
    return NULL;
  return &ct_values[pos];
}

static inline void ct_update(const struct ct_k *key, const struct ct_v *value) {
  int32_t pos = rte_hash_add_key(ct_connections, key);

  /* a full table fails the insert, exactly like bpf_map_update_elem on a
   * BPF_MAP_TYPE_HASH that has reached max_entries */
  if (pos < 0)
    return;
  ct_values[pos] = *value;
}

static void conntrack_init(void) {
  struct rte_hash_parameters params = {
      .name = "connections",
      .entries = CONNTRACK_MAP_MAX_SIZE,
      .key_len = sizeof(struct ct_k),
      .hash_func = rte_jhash,
      .hash_func_init_val = 0,
      .socket_id = (int)rte_socket_id(),
  };

  ct_connections = rte_hash_create(&params);
  if (ct_connections == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create the connections hash table\n");

  ct_values = rte_zmalloc(NULL, sizeof(struct ct_v) * CONNTRACK_MAP_MAX_SIZE, 64);
  if (ct_values == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate the connections values\n");
  printf("Conntrack table ready: %u entries, key %zu bytes\n",
         CONNTRACK_MAP_MAX_SIZE, sizeof(struct ct_k));
}

/* conntrack_parser.h, ported */
static inline bool validate_ethertype(uint8_t *data, uint8_t *data_end,
                                      uint16_t *h_proto, uint16_t *nh_off) {
  *nh_off = RTE_ETHER_HDR_LEN;

  if (data + *nh_off > data_end)
    return false;

  *h_proto = ((struct rte_ether_hdr *)data)->ether_type;

  if (rte_be_to_cpu_16(*h_proto) < 0x0600)
    return false; /* non-Ethernet II unsupported */

  for (int i = 0; i < 2; i++) {
    if (*h_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
        *h_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
      struct vlan_hdr_ct *vhdr = (struct vlan_hdr_ct *)(data + *nh_off);

      *nh_off += sizeof(struct vlan_hdr_ct);
      if (data + *nh_off > data_end)
        return false;
      *h_proto = vhdr->h_vlan_encapsulated_proto;
    }
  }

  return true;
}

static inline int parse_packet(uint8_t *data, uint8_t *data_end,
                               struct packetHeaders *pkt) {
  uint16_t l3_proto;
  uint16_t nh_off;
  struct rte_ipv4_hdr *iph;

  memset(pkt, 0, sizeof(*pkt));

  if (!validate_ethertype(data, data_end, &l3_proto, &nh_off)) {
    bpf_log_err("Unrecognized L3 protocol\n");
    goto DROP;
  }

  if (l3_proto != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    /* IPv6 and ARP are dropped by the XDP parser too */
    bpf_log_err("Unsupported L3 protocol\n");
    goto DROP;
  }

  iph = (struct rte_ipv4_hdr *)(data + nh_off);
  if ((uint8_t *)iph + sizeof(*iph) > data_end) {
    bpf_log_err("Invalid IPv4 packet\n");
    goto DROP;
  }

  pkt->srcIp = iph->src_addr;
  pkt->dstIp = iph->dst_addr;
  pkt->l4proto = iph->next_proto_id;

  if (iph->next_proto_id == IPPROTO_TCP) {
    struct tcp_hdr_flags *tcp =
        (struct tcp_hdr_flags *)(data + RTE_ETHER_HDR_LEN + sizeof(*iph));

    if (data + RTE_ETHER_HDR_LEN + sizeof(*iph) + sizeof(*tcp) > data_end) {
      bpf_log_err("Invalid TCP packet\n");
      goto DROP;
    }
    pkt->srcPort = tcp->source;
    pkt->dstPort = tcp->dest;
    pkt->seqN = tcp->seq;
    pkt->ackN = tcp->ack_seq;
    pkt->flags = tcp->flags;
  } else if (iph->next_proto_id == IPPROTO_UDP) {
    struct rte_udp_hdr *udp =
        (struct rte_udp_hdr *)(data + RTE_ETHER_HDR_LEN + sizeof(*iph));

    if (data + RTE_ETHER_HDR_LEN + sizeof(*iph) + sizeof(*udp) > data_end) {
      bpf_log_err("Invalid UDP packet\n");
      goto DROP;
    }
    pkt->srcPort = udp->src_port;
    pkt->dstPort = udp->dst_port;
  } else {
    bpf_log_err("Unsupported L4 protocol\n");
    goto DROP;
  }

  return 0;

DROP:;
  bpf_log_debug("Dropping packet.\n");
  return CONNTRACK_DROP;
}

/* One packet, mirroring the body of conntrack.bpf.c. */
static void conntrack_handle_pkt(struct rte_mbuf *m) {
  int rc;
  struct packetHeaders pkt;
  uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
  uint8_t *data_end = data + rte_pktmbuf_data_len(m);

  bpf_log_debug("Received packet on interface.\n");

  rc = parse_packet(data, data_end, &pkt);

  if (rc < 0) {
    bpf_log_err("Packet parsing failed.\n");
    goto DROP;
  }
  bpf_log_debug("Packet parsed, now starting the conntrack.\n");

    struct ct_k key;
    memset(&key, 0, sizeof(key));
    uint8_t ipRev = 0;
    uint8_t portRev = 0;

    if (pkt.srcIp <= pkt.dstIp) {
        key.srcIp = pkt.srcIp;
        key.dstIp = pkt.dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt.dstIp;
        key.dstIp = pkt.srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt.l4proto;

    if (pkt.srcPort < pkt.dstPort) {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = 0;
    } else if (pkt.srcPort > pkt.dstPort) {
        key.srcPort = pkt.dstPort;
        key.dstPort = pkt.srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = ipRev;
    }

    struct ct_v newEntry;
    memset(&newEntry, 0, sizeof(newEntry));
    struct ct_v *value;

    uint64_t timestamp;
    timestamp = get_time_ns();

    /* == TCP  == */
    if (pkt.l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt.flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            goto PASS_ACTION;
        }
        value = ct_lookup(&key);
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
                if ((pkt.flags & TCPHDR_SYN) != 0 && (pkt.flags | TCPHDR_SYN) == TCPHDR_SYN) {
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
                                  pkt.flags);
                    pkt.connStatus = INVALID;

                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == SYN_RECV) {
                // Expecting an ACK here
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags | TCPHDR_ACK) == TCPHDR_ACK &&
                    (pkt.ackN == value->sequence)) {
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
                    pkt.connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    // Received first FIN from "original" direction.
                    // Changing state to FIN_WAIT_1
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.ackN;

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
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.seqN == value->sequence)) {
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
                    pkt.connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in rev direction, waiting the
                // FIN from the this side
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.ackN;

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
                if ((pkt.flags & TCPHDR_ACK && pkt.seqN == value->sequence) != 0) {
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
                if (pkt.connStatus == NEW) {
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
                          pkt.flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;

            // Found in reverse direction
            if (value->state == SYN_SENT) {
                // This should be a SYN, ACK answer
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags & TCPHDR_SYN) != 0 &&
                    (pkt.flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt.ackN == value->sequence) {
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt.seqN + HEX_BE_ONE;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");

                    goto PASS_ACTION;
                }
                // Here is an unexpected packet, only a SYN, ACK is acepted as
                // an answer to a SYN
                pkt.connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == SYN_RECV) {
                // The only acceptable packet in SYN_RECV here is a SYN,ACK
                // retransmission
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags & TCPHDR_SYN) != 0 &&
                    (pkt.flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt.ackN == value->sequence) {
                    value->ttl = timestamp + TCP_SYN_RECV;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.ackN;
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
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.seqN == value->sequence)) {
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
                    pkt.connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in "original" direction,
                // waiting the FIN from this side
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.ackN;
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
                                  pkt.flags, value->sequence);

                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt.flags & TCPHDR_ACK && pkt.seqN == value->sequence) != 0) {
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
                if (pkt.connStatus == NEW) {
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
                          pkt.flags, value->state);
            goto PASS_ACTION;
        }

    TCP_MISS:;

        // New entry. It has to be a SYN.
        if ((pkt.flags & TCPHDR_SYN) != 0 && (pkt.flags | TCPHDR_SYN) == TCPHDR_SYN) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt.seqN + HEX_BE_ONE;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            ct_update(&key, &newEntry);
            goto PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt.flags);
            goto PASS_ACTION;
        }
    }

    if (pkt.l4proto == IPPROTO_UDP) {
        value = ct_lookup(&key);
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
        newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
        newEntry.state = NEW;
        newEntry.sequence = 0;

        newEntry.ipRev = ipRev;
        newEntry.portRev = portRev;

        ct_update(&key, &newEntry);
        goto PASS_ACTION;
    }

PASS_ACTION:;

  if (pkt.connStatus == INVALID) {
    bpf_log_err("Connection status is invalid\n");
  }

  if (data + RTE_ETHER_HDR_LEN > data_end) {
    bpf_log_err("Packet after modification is invalid! DROP\n");
    goto DROP;
  }

  ((struct rte_ether_hdr *)data)->ether_type =
      rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  ct_passed++;
  return;

DROP:;
  bpf_log_err("Dropping packet!\n");
  ct_dropped++;
}

/* >8 End of simple forward. */

/* main processing loop */
static void l2fwd_main_loop(void) {
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  int sent;
  unsigned lcore_id;
  uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
  unsigned i, j, portid, nb_rx;
  struct lcore_queue_conf *qconf;
  const uint64_t drain_tsc =
      (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

  prev_tsc = 0;
  timer_tsc = 0;

  lcore_id = rte_lcore_id();
  qconf = &lcore_queue_conf[lcore_id];

  if (qconf->n_rx_port == 0) {
    RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
    return;
  }

  RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

  for (i = 0; i < qconf->n_rx_port; i++) {

    portid = qconf->rx_port_list[i];
    RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id, portid);
  }
  uint64_t m4[8];

  while (!force_quit) {
    /* Drains TX queue in its main loop. 8< */
    cur_tsc = rte_rdtsc();

    /*
     * TX burst queue drain
     */
    diff_tsc = cur_tsc - prev_tsc;
    if (unlikely(diff_tsc > drain_tsc)) {
      /* if timer is enabled */
      if (timer_period > 0) {

        /* advance the timer */
        timer_tsc += diff_tsc;

        /* if timer has reached its timeout */
        if (unlikely(timer_tsc >= timer_period)) {

          /* do this only on main core */
          if (lcore_id == rte_get_main_lcore()) {
            print_stats();
            /* reset the timer */
            timer_tsc = 0;
          }
        }
      }

      prev_tsc = cur_tsc;
    }
    /* >8 End of draining TX queue. */

    /* Read packet from RX queues. 8< */

    // for (i = 0; i < qconf->n_rx_port; i++) {
    //   portid = qconf->rx_port_list[i];
    //   nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);

    //   if (unlikely(nb_rx == 0))
    //     continue;

    //   //   //     //   fprintf(stderr, "%u\n", nb_rx);
    //   port_statistics[portid].rx += nb_rx;
    //   for (j = 0; j < nb_rx; j++) {
    //     m = pkts_burst[j];
    //     // for (int x = 0; x < 8; x++) {
    //     //   fprintf(stderr, "0x%lx ", (uint8_t *)m);
    //     // }
    //     // fprintf(stderr, "nb_rx %u\n", nb_rx);

    //     // fprintf(stderr, " %x\n", *rte_pktmbuf_mtod(m, uint8_t *));
    //     rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    //     memcpy(&m4[j % 4], rte_pktmbuf_mtod(m, uint8_t *) + 26, 13);
    //     // fprintf(stderr, "m4 %lx\n", m4[j % 4]);
    //     if ((j + 1) % 4 == 0) {
    //       count_add_simd((uint64_t *)m4);
    //       rte_pktmbuf_free_bulk(&pkts_burst[j-4], 4);
    //     }
    //     //       // fprintf(stderr, "count_add\n");
    //     // rte_pktmbuf_free(m);
    //   }
    // }

    /* >8 End of read packet from RX queues. */

      for (i = 0; i < qconf->n_rx_port; i++) {
        portid = qconf->rx_port_list[i];
        nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);

        if (unlikely(nb_rx == 0))
          continue;

        //   fprintf(stderr, "%u\n", nb_rx);
        port_statistics[portid].rx += nb_rx;
        {
          uint64_t t0 = rte_rdtsc();

          for (j = 0; j < nb_rx; j++) {
            m = pkts_burst[j];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
            conntrack_handle_pkt(m);
            rte_pktmbuf_free(m);
          }
          work_cycles += rte_rdtsc() - t0;
          work_pkts += nb_rx;
        }
      }
  }
  /* >8 End of read packet from RX queues. */
}

static int l2fwd_launch_one_lcore(__rte_unused void *dummy) {
  l2fwd_main_loop();
  return 0;
}

/* display usage */
static void l2fwd_usage(const char *prgname) {
  printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
         "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
         "  -P : Enable promiscuous mode\n"
         "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
         "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to "
         "disable, 10 default, 86400 maximum)\n"
         "  --no-mac-updating: Disable MAC addresses updating (enabled by "
         "default)\n"
         "      When enabled:\n"
         "       - The source MAC address is replaced by the TX port MAC "
         "address\n"
         "       - The destination MAC address is replaced by "
         "02:00:00:00:00:TX_PORT_ID\n"
         "  --portmap: Configure forwarding port pair mapping\n"
         "	      Default: alternate port pairs\n\n",
         prgname);
}

static int l2fwd_parse_portmask(const char *portmask) {
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return 0;

  return pm;
}

static int l2fwd_parse_port_pair_config(const char *q_arg) {
  enum fieldnames { FLD_PORT1 = 0, FLD_PORT2, _NUM_FLD };
  unsigned long int_fld[_NUM_FLD];
  const char *p, *p0 = q_arg;
  char *str_fld[_NUM_FLD];
  unsigned int size;
  char s[256];
  char *end;
  int i;

  nb_port_pair_params = 0;

  while ((p = strchr(p0, '(')) != NULL) {
    ++p;
    p0 = strchr(p, ')');
    if (p0 == NULL)
      return -1;

    size = p0 - p;
    if (size >= sizeof(s))
      return -1;

    memcpy(s, p, size);
    s[size] = '\0';
    if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
      return -1;
    for (i = 0; i < _NUM_FLD; i++) {
      errno = 0;
      int_fld[i] = strtoul(str_fld[i], &end, 0);
      if (errno != 0 || end == str_fld[i] || int_fld[i] >= RTE_MAX_ETHPORTS)
        return -1;
    }
    if (nb_port_pair_params >= RTE_MAX_ETHPORTS / 2) {
      printf("exceeded max number of port pair params: %hu\n",
             nb_port_pair_params);
      return -1;
    }
    port_pair_params_array[nb_port_pair_params].port[0] =
        (uint16_t)int_fld[FLD_PORT1];
    port_pair_params_array[nb_port_pair_params].port[1] =
        (uint16_t)int_fld[FLD_PORT2];
    ++nb_port_pair_params;
  }
  port_pair_params = port_pair_params_array;
  return 0;
}

static unsigned int l2fwd_parse_nqueue(const char *q_arg) {
  char *end = NULL;
  unsigned long n;

  /* parse hexadecimal string */
  n = strtoul(q_arg, &end, 10);
  if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
    return 0;
  if (n == 0)
    return 0;
  if (n >= MAX_RX_QUEUE_PER_LCORE)
    return 0;

  return n;
}

static int l2fwd_parse_timer_period(const char *q_arg) {
  char *end = NULL;
  int n;

  /* parse number string */
  n = strtol(q_arg, &end, 10);
  if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
    return -1;
  if (n >= MAX_TIMER_PERIOD)
    return -1;

  return n;
}

static const char short_options[] = "p:" /* portmask */
                                    "P"  /* promiscuous */
                                    "q:" /* number of queues */
                                    "T:" /* timer period */
    ;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_PORTMAP_CONFIG "portmap"

enum {
  /* long options mapped to a short option */

  /* first long only option value must be >= 256, so that we won't
   * conflict with short options */
  CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
  CMD_LINE_OPT_PORTMAP_NUM,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
     CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
    {CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
    {NULL, 0, 0, 0}};

/* Parse the argument given in the command line of the application */
static int l2fwd_parse_args(int argc, char **argv) {
  int opt, ret, timer_secs;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];

  argvopt = argv;
  port_pair_params = NULL;

  while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                            &option_index)) != EOF) {

    switch (opt) {
    /* portmask */
    case 'p':
      l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
      if (l2fwd_enabled_port_mask == 0) {
        printf("invalid portmask\n");
        l2fwd_usage(prgname);
        return -1;
      }
      break;
    case 'P':
      promiscuous_on = 1;
      break;

    /* nqueue */
    case 'q':
      l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
      if (l2fwd_rx_queue_per_lcore == 0) {
        printf("invalid queue number\n");
        l2fwd_usage(prgname);
        return -1;
      }
      break;

    /* timer period */
    case 'T':
      timer_secs = l2fwd_parse_timer_period(optarg);
      if (timer_secs < 0) {
        printf("invalid timer period\n");
        l2fwd_usage(prgname);
        return -1;
      }
      timer_period = timer_secs;
      break;

    /* long options */
    case CMD_LINE_OPT_PORTMAP_NUM:
      ret = l2fwd_parse_port_pair_config(optarg);
      if (ret) {
        fprintf(stderr, "Invalid config\n");
        l2fwd_usage(prgname);
        return -1;
      }
      break;

    case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
      mac_updating = 0;
      break;

    default:
      l2fwd_usage(prgname);
      return -1;
    }
  }

  if (optind >= 0)
    argv[optind - 1] = prgname;

  ret = optind - 1;
  optind = 1; /* reset getopt lib */
  return ret;
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int check_port_pair_config(void) {
  uint32_t port_pair_config_mask = 0;
  uint32_t port_pair_mask = 0;
  uint16_t index, i, portid;

  for (index = 0; index < nb_port_pair_params; index++) {
    port_pair_mask = 0;

    for (i = 0; i < NUM_PORTS; i++) {
      portid = port_pair_params[index].port[i];
      if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
        printf("port %u is not enabled in port mask\n", portid);
        return -1;
      }
      if (!rte_eth_dev_is_valid_port(portid)) {
        printf("port %u is not present on the board\n", portid);
        return -1;
      }

      port_pair_mask |= 1 << portid;
    }

    if (port_pair_config_mask & port_pair_mask) {
      printf("port %u is used in other port pairs\n", portid);
      return -1;
    }
    port_pair_config_mask |= port_pair_mask;
  }

  l2fwd_enabled_port_mask &= port_pair_config_mask;

  return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
  uint16_t portid;
  uint8_t count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  int ret;
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("\nChecking link status");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    if (force_quit)
      return;
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(portid) {
      if (force_quit)
        return;
      if ((port_mask & (1 << portid)) == 0)
        continue;
      memset(&link, 0, sizeof(link));
      ret = rte_eth_link_get_nowait(portid, &link);
      if (ret < 0) {
        all_ports_up = 0;
        if (print_flag == 1)
          printf("Port %u link get failed: %s\n", portid, rte_strerror(-ret));
        continue;
      }
      /* print link status if flag set */
      if (print_flag == 1) {
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        printf("Port %d %s\n", portid, link_status_text);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      // if (link.link_status == RTE_ETH_LINK_DOWN) {
      if (link.link_status == ETH_LINK_DOWN) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1)
      break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}

int main(int argc, char **argv) {
  struct lcore_queue_conf *qconf;
  int ret;
  uint16_t nb_ports;
  uint16_t nb_ports_available = 0;
  uint16_t portid, last_port;
  unsigned lcore_id, rx_lcore_id;
  unsigned nb_ports_in_mask = 0;
  unsigned int nb_lcores = 0;
  unsigned int nb_mbufs;

  /* Init EAL. 8< */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* parse application arguments (after the EAL ones) */
  ret = l2fwd_parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
  /* >8 End of init EAL. */

  printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

  /* convert to number of cycles */
  timer_period *= rte_get_timer_hz();

  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports == 0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

  if (port_pair_params != NULL) {
    if (check_port_pair_config() < 0)
      rte_exit(EXIT_FAILURE, "Invalid port pair config\n");
  }

  /* check port mask to possible port mask */
  if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
    rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
             (1 << nb_ports) - 1);

  /* Initialization of the driver. 8< */

  /* reset l2fwd_dst_ports */
  for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
    l2fwd_dst_ports[portid] = 0;
  last_port = 0;

  /* populate destination port details */
  if (port_pair_params != NULL) {
    uint16_t idx, p;

    for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
      p = idx & 1;
      portid = port_pair_params[idx >> 1].port[p];
      l2fwd_dst_ports[portid] = port_pair_params[idx >> 1].port[p ^ 1];
    }
  } else {
    RTE_ETH_FOREACH_DEV(portid) {
      /* skip ports that are not enabled */
      if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
        continue;

      if (nb_ports_in_mask % 2) {
        l2fwd_dst_ports[portid] = last_port;
        l2fwd_dst_ports[last_port] = portid;
      } else {
        last_port = portid;
      }

      nb_ports_in_mask++;
    }
    if (nb_ports_in_mask % 2) {
      printf("Notice: odd number of ports in portmask.\n");
      l2fwd_dst_ports[last_port] = last_port;
    }
  }
  /* >8 End of initialization of the driver. */

  rx_lcore_id = 0;
  qconf = NULL;

  /* Initialize the port/queue configuration of each logical core */
  RTE_ETH_FOREACH_DEV(portid) {
    /* skip ports that are not enabled */
    if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
      continue;

    /* get the lcore_id for this port */
    while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
           lcore_queue_conf[rx_lcore_id].n_rx_port ==
               l2fwd_rx_queue_per_lcore) {
      rx_lcore_id++;
      if (rx_lcore_id >= RTE_MAX_LCORE)
        rte_exit(EXIT_FAILURE, "Not enough cores\n");
    }

    if (qconf != &lcore_queue_conf[rx_lcore_id]) {
      /* Assigned a new logical core in the loop above. */
      qconf = &lcore_queue_conf[rx_lcore_id];
      nb_lcores++;
    }

    qconf->rx_port_list[qconf->n_rx_port] = portid;
    qconf->n_rx_port++;
    printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id, portid,
           l2fwd_dst_ports[portid]);
  }

  nb_mbufs = RTE_MAX(
      nb_ports * (nb_rxd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
      8192U);

  /* Create the mbuf pool. 8< */
  l2fwd_pktmbuf_pool =
      rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (l2fwd_pktmbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
  /* >8 End of create the mbuf pool. */

  /* Initialise each port */
  RTE_ETH_FOREACH_DEV(portid) {
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    /* skip ports that are not enabled */
    if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
      printf("Skipping disabled port %u\n", portid);
      continue;
    }
    nb_ports_available++;

    /* init port */
    printf("Initializing port %u... ", portid);
    fflush(stdout);

    ret = rte_eth_dev_info_get(portid, &dev_info);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));

    /* Configure the number of queues for a port. */
    ret = rte_eth_dev_configure(portid, 1, 0, &local_port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               portid);
    /* >8 End of configuration of the number of queues for a port. */

    ret = rte_eth_macaddr_get(portid, &l2fwd_ports_eth_addr[portid]);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
               portid);

    /* init one RX queue */
    fflush(stdout);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    /* RX queue setup. 8< */
    ret =
        rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid),
                               &rxq_conf, l2fwd_pktmbuf_pool);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
               portid);
    /* >8 End of RX queue setup. */

    /* Init one TX queue on each port. 8< */
    fflush(stdout);

    /* Initialize TX buffers */
    // ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
    // if (ret < 0)
    //   printf("Port %u, Failed to disable Ptype parsing\n", portid);
    // /* Start device */
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret,
               portid);

    printf("done: \n");
    // if (promiscuous_on) {
    //   ret = rte_eth_promiscuous_enable(portid);
    //   if (ret != 0)
    //     rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable:err=%s, port=%u\n",
    //              rte_strerror(-ret), portid);
    // }

    printf("Port %u, MAC address:\n\n", portid);

    /* initialize port stats */
    memset(&port_statistics, 0, sizeof(port_statistics));
  }

  if (!nb_ports_available) {
    rte_exit(EXIT_FAILURE,
             "All available ports are disabled. Please set portmask.\n");
  }

  // start

  conntrack_init();

  /* launch per-lcore init on every lcore */

  check_all_ports_link_status(l2fwd_enabled_port_mask);

  ret = 0;
  /* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      ret = -1;
      break;
    }
  }

  RTE_ETH_FOREACH_DEV(portid) {
    if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
      continue;
    printf("Closing port %d...", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0)
      printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
    rte_eth_dev_close(portid);
    printf(" Done\n");
  }

  printf("Conntrack passed: %" PRIu64 ", dropped: %" PRIu64 ", tracked: %d\n",
         ct_passed, ct_dropped, rte_hash_count(ct_connections));
  rte_free(ct_values);
  rte_hash_free(ct_connections);

  /* clean up the EAL */
  rte_eal_cleanup();

  printf("Bye...\n");

  return ret;
}
