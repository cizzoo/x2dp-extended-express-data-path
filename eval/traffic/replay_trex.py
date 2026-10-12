#!/usr/bin/env python3
"""Replay a pcap in a continuous loop from a TRex stateless server.

Run on the traffic generator, with the TRex server already started
(./t-rex-64 -i) and the TRex python API on PYTHONPATH. Stops on Ctrl-C.

Example: replay_trex.py uniform_1M_100K.pcap --rate 100
"""

import argparse

from trex.stl.api import STLClient, STLPcap, STLStream, STLTXCont


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument("pcap")
    p.add_argument("--rate", type=float, default=100, help="percent of line rate")
    p.add_argument("--server", default="127.0.0.1", help="TRex server address")
    p.add_argument("--port", type=int, default=0, help="TRex port to send on")
    args = p.parse_args()

    client = STLClient(server=args.server)
    try:
        client.connect()
        client.reset(ports=[args.port])
        stream = STLStream(packet=STLPcap(args.pcap),
                           mode=STLTXCont(percentage=args.rate))
        client.add_streams(stream, ports=[args.port])
        client.start(ports=[args.port], force=True)
        print(f"replaying {args.pcap} at {args.rate}% of line rate, Ctrl-C to stop")
        client.wait_on_traffic(ports=[args.port])
    except KeyboardInterrupt:
        client.stop(ports=[args.port])
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
