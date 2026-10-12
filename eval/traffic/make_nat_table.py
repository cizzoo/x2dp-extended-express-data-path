#!/usr/bin/env python3
"""Build a NAT address table from one or more traces.

Collects the unique IPv4 source addresses of every packet in the given pcaps
and writes them one per line: the format the nat/ loaders take as their
second argument (nat/nat_tbl.txt comes from the synthetic trace,
nat/caida.txt from the CAIDA one).

Example: make_nat_table.py uniform_1M_100K.pcap -o ../../nat/nat_tbl.txt
"""

import argparse

from scapy.all import IP, PcapReader
from tqdm import tqdm


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument("pcaps", nargs="+")
    p.add_argument("-o", "--output", default="nat_tbl.txt")
    args = p.parse_args()

    addrs = set()
    for path in args.pcaps:
        with PcapReader(path) as reader:
            for pkt in tqdm(reader, desc=path, unit="pkt"):
                if IP in pkt:
                    addrs.add(pkt[IP].src)

    with open(args.output, "w") as f:
        f.writelines(a + "\n" for a in sorted(addrs))
    print(f"wrote {len(addrs)} addresses to {args.output}")


if __name__ == "__main__":
    main()
