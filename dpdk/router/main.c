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

#include <arpa/inet.h>
#include <rte_lpm.h>
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
  static uint64_t prev_total_tx = 0;

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
           "\nReceive rate: %14" PRIu64 " pkt/s  (%.3f Mpps)"
           "\nTotal packets sent: %18" PRIu64
           "\nTransmit rate: %13" PRIu64 " pkt/s  (%.3f Mpps)",
           total_packets_rx, total_packets_dropped, diff_total / period,
           (double)diff_total / period / 1e6, total_packets_tx,
           (total_packets_tx - prev_total_tx) / period,
           (double)(total_packets_tx - prev_total_tx) / period / 1e6);
    prev_total_tx = total_packets_tx;
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
 * Router, ported from the unoptimized XDP program router/router.bpf.c.
 *
 * That program keeps an LPM trie (BPF_MAP_TYPE_LPM_TRIE) filled by its
 * loader from RCC25/<prefixlen>.txt, and for every IPv4 packet looks the
 * SOURCE address up in it, then drops the packet on both the match and the
 * no-match path. This does the same with rte_lpm and the same files, so the
 * two see exactly the same table and do exactly the same work per packet.
 * ------------------------------------------------------------------ */

#define ROUTER_RULES_DIR "/home/vladimiro/bxdp/router/RCC25"
/* the table is ~936k prefixes today; leave room to grow */
#define ROUTER_MAX_RULES 1500000
/* only ~9k prefixes are longer than /24, so tbl8 demand is modest */
#define ROUTER_NUM_TBL8S (1 << 15)

static struct rte_lpm *router_lpm;
static uint64_t router_matched;
static uint64_t router_unmatched;

static void app_print_stats(void) {
  printf("\nLPM lookups matched: %17" PRIu64 "\nLPM lookups unmatched: %15" PRIu64,
         router_matched, router_unmatched);
}

static void router_init(void) {
  struct rte_lpm_config cfg = {
      .max_rules = ROUTER_MAX_RULES,
      .number_tbl8s = ROUTER_NUM_TBL8S,
      .flags = 0,
  };
  uint64_t total = 0;
  unsigned int depth;

  router_lpm = rte_lpm_create("router_lpm", rte_socket_id(), &cfg);
  if (router_lpm == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create the LPM table\n");

  /* Same loop as updatelpm() in router/router.c: one file per prefix
   * length, one dotted-quad network address per line, and the prefix
   * length itself stored as the value. */
  for (depth = 8; depth <= 32; depth++) {
    char path[256];
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    uint64_t count = 0;

    snprintf(path, sizeof(path), "%s/%u.txt", ROUTER_RULES_DIR, depth);
    fp = fopen(path, "r");
    if (fp == NULL) {
      printf("Map file %s not found\n", path);
      continue;
    }
    while (getline(&line, &len, fp) != -1) {
      uint32_t ip;

      line[strcspn(line, "\n")] = 0;
      if (line[0] == '\0')
        continue;
      /* inet_addr returns network order, rte_lpm works in host order */
      ip = rte_be_to_cpu_32((uint32_t)inet_addr(line));
      if (rte_lpm_add(router_lpm, ip, depth, depth) < 0) {
        printf("rte_lpm_add failed for %s/%u\n", line, depth);
        continue;
      }
      count++;
      total++;
    }
    fclose(fp);
    free(line);
    if (count)
      printf("prefix length /%u: %" PRIu64 " rules\n", depth, count);
  }
  printf("LPM table built: %" PRIu64 " rules\n", total);
}

/* One packet, mirroring the body of router.bpf.c. */
static void router_handle_pkt(struct rte_mbuf *m) {
  const uint8_t *data = rte_pktmbuf_mtod(m, const uint8_t *);
  const uint8_t *data_end = data + rte_pktmbuf_data_len(m);
  const struct rte_ether_hdr *eth_hdr = (const struct rte_ether_hdr *)data;
  const struct rte_ipv4_hdr *ip_hdr;
  uint16_t protocol;
  uint32_t src_ip;
  uint32_t next_hop;

  if (data + sizeof(struct rte_ether_hdr) < data_end) {
    protocol = eth_hdr->ether_type;
    if (protocol == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
      ip_hdr = (const struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
      if (data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) <
          data_end) {
        src_ip = ip_hdr->src_addr;

        if (rte_lpm_lookup(router_lpm, rte_be_to_cpu_32(src_ip), &next_hop) == 0)
          router_matched++;
        else
          router_unmatched++;
      }
    }
  }
  /* the XDP program returns XDP_DROP on every path; the caller frees */
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

          uint16_t nb_tx;

          for (j = 0; j < nb_rx; j++) {
            m = pkts_burst[j];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
            router_handle_pkt(m);
          }
          /* send the packets back out of the same port, like XDP_TX does */
          nb_tx = rte_eth_tx_burst(portid, 0, pkts_burst, nb_rx);
          port_statistics[portid].tx += nb_tx;
          if (unlikely(nb_tx < nb_rx)) {
            port_statistics[portid].dropped += nb_rx - nb_tx;
            for (j = nb_tx; j < nb_rx; j++)
              rte_pktmbuf_free(pkts_burst[j]);
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
    struct rte_eth_txconf txq_conf;
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
    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
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
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                 rte_eth_dev_socket_id(portid), &txq_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
               portid);
    /* >8 End of TX queue setup. */

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

  router_init();

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

  printf("LPM lookups matched: %" PRIu64 ", unmatched: %" PRIu64 "\n",
         router_matched, router_unmatched);
  rte_lpm_free(router_lpm);

  /* clean up the EAL */
  rte_eal_cleanup();

  printf("Bye...\n");

  return ret;
}
