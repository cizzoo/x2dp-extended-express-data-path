#!/usr/bin/env python3
"""Generate the synthetic trace used in the evaluation.

N_PKTS minimum-size packets spread over N_FLOWS random 5-tuples. With the
UNIFORM distribution every flow gets the same number of packets, in random
order (the paper uses 1M packets and 100K flows). ZIPF draws the flow of each
packet from a Zipf distribution with parameter --zipf.

Example: gen_trace.py --n-pkts 1M --n-flows 100K -o uniform_1M_100K.pcap
"""

import argparse
import math
import random

import numpy
from scapy.all import IP, TCP, UDP, Ether, PcapWriter, RandIP
from tqdm import tqdm


def count(arg):
    mult = {"K": 10**3, "M": 10**6, "G": 10**9}
    return int(arg[:-1]) * mult[arg[-1]] if arg[-1] in mult else int(arg)


def make_flows(args):
    flows = set()
    while len(flows) < args.n_flows:
        proto = args.l4_proto if args.l4_proto != "MIX" else random.choice(["TCP", "UDP"])
        flows.add((str(RandIP(args.s_subnet)), str(RandIP(args.d_subnet)), proto,
                   random.randint(1, 65535), random.randint(1, 65535)))
    return list(flows)


def flow_sequence(args):
    if args.distribution == "UNIFORM":
        rep = math.ceil(args.n_pkts / args.n_flows)
        seq = [i for i in range(args.n_flows) for _ in range(rep)][: args.n_pkts]
        random.shuffle(seq)
        return seq
    return [(z - 1) % args.n_flows
            for z in numpy.random.zipf(a=args.zipf, size=args.n_pkts)]


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument("--n-pkts", type=count, default=count("1M"), help="packets (accepts K/M/G)")
    p.add_argument("--n-flows", type=count, default=count("100K"), help="flows (accepts K/M/G)")
    p.add_argument("--l4-proto", choices=["TCP", "UDP", "MIX"], default="UDP")
    p.add_argument("--distribution", choices=["UNIFORM", "ZIPF"], default="UNIFORM")
    p.add_argument("--zipf", type=float, default=1.1, help="Zipf parameter (> 1)")
    p.add_argument("--s-subnet", default="0.0.0.0/0", help="source IP subnet")
    p.add_argument("--d-subnet", default="0.0.0.0/0", help="destination IP subnet")
    p.add_argument("--smac", default="00:00:00:00:00:01", help="source MAC")
    p.add_argument("--dmac", default="00:00:00:00:00:02",
                   help="destination MAC (the MAC of the X2DP port)")
    p.add_argument("--seed", type=int, help="random seed, for a reproducible trace")
    p.add_argument("-o", "--output", default="trace.pcap")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        numpy.random.seed(args.seed)

    flows = make_flows(args)
    writer = PcapWriter(args.output, sync=False)
    for i, f in enumerate(tqdm(flow_sequence(args), unit="pkt")):
        src, dst, proto, sport, dport = flows[f]
        l4 = TCP if proto == "TCP" else UDP
        writer.write(Ether(src=args.smac, dst=args.dmac) / IP(src=src, dst=dst)
                     / l4(sport=sport, dport=dport) / str(i))
    writer.close()
    print(f"wrote {args.n_pkts} packets over {args.n_flows} flows to {args.output}")


if __name__ == "__main__":
    main()
