# Evaluation

These scripts reproduce the measurements in the paper. The traffic is sent from a separate machine, directly connected to the Alveo, which replays the traces at line rate. The scripts here run on the host with the Alveo, plus the generators of the traces.

| Path | Runs on | Contents |
|---|---|---|
| `run.py` | host | Suite runner |
| `suites/` | host | One suite per experiment of the paper |
| `traffic/gen_trace.py` | anywhere | Synthetic trace generator (paper: 1M minimum-size packets, 100K flows, uniform) |
| `traffic/make_nat_table.py` | anywhere | Builds the NAT address table from the trace(s) |
| `traffic/conntrack/` | anywhere | Generator of complete TCP sessions, for the connection tracker |

```sh
pip install -r eval/requirements.txt
```

## 1. Traffic

```sh
cd eval/traffic
./gen_trace.py --n-pkts 1M --n-flows 100K --dmac <MAC of the X2DP port> -o uniform_1M_100K.pcap
./make_nat_table.py uniform_1M_100K.pcap -o ../../nat/nat_tbl.txt   # optional, a table is already in nat/
conntrack/generate_pcap_conntrack.py -c conntrack/config.yaml -o tcp_sessions.pcap
```

`conntrack/config.yaml` contains the MAC addresses of our test bed. Change them to match your setup.

Replay the trace in a loop from the traffic machine with any packet generator. Conntrack uses the TCP-session trace; all other applications use the uniform trace.

The real-trace results (Table IV) use a CAIDA anonymized trace, which cannot be redistributed. `nat/caida.txt` is the NAT table built from that trace.

The NAT table must match the trace being replayed: the suites pass `nat/nat_tbl.txt`, which is built from the generated trace. When you replay the CAIDA trace, change the NAT `args` in the suite to `@/nat/caida.txt`.

## 2. Host setup

- Program the card and load the modified driver (see the top-level README).
- Build the programs with `make`, and also `make kfunc && make -C xxhash load` for `simd.json`.
- Send all traffic to a single RX queue/core, and set `cpu` in the suite to that core.
- Pin the core frequency and disable turbo boost. The paper used 3.1 GHz with turbo off.
- Leave `kernel.bpf_stats_enabled=0`, which the runner checks, because statistics collection slows the programs down.
- `ipc` and `stalls` require a `perf` built with BPF skeleton support (`perf stat -b <prog id>`). Pass it with `--perf` if it is not the `perf` in `PATH`.

## 3. Running a suite

```sh
sudo eval/run.py eval/suites/apps.json --ifname <onic interface> --ioctl <onic-driver>/utility/ioctl
```

The runner drives the card through the `ioctl` utility that comes with the driver:

| Command | Effect |
|---|---|
| `ioctl -c 0` | **Baseline**: vanilla XDP. X²DP is disabled, the NIC behaves as plain OpenNIC, and XDP runs once per packet. It is reported as batch size 1 |
| `ioctl -c 1` + `ioctl -c 9 -w N` | **X²DP** with batches of N packets (2–16); N = 1 is the baseline |
| `ioctl -c 3 -w T` | Number of packets received in T seconds, used for throughput |

Each run in a suite selects a mode and, for X²DP, a list of `batch-sizes`. For each batch size and each program, the runner does the following, `repetitions` times:

1. Starts the loader.
2. Measures every metric for `time` seconds.
3. Stops the loader.

When the suite ends, the card is put back in baseline mode.

Results are written to `eval/results/<suite>/`:
- `results.csv`: mean and standard deviation per program and batch size;
- `all_results.csv`: one row per repetition;
- `log.txt`.

| Suite | Paper | Metrics |
|---|---|---|
| `micro.json` | Fig. 5–7 | Throughput of `XDP_PASS`/`XDP_DROP`/`XDP_TX` vs batch size |
| `apps.json` | Fig. 8–9, Table IV | Throughput and CPU of the six applications vs batch size |
| `latency.json` | Fig. 10 | Keeps each `XDP_TX` program loaded for 40 s while the traffic machine measures the RTT |
| `optimizations.json` | Fig. 11–13 | Batched vs optimized variants, with IPC and stalled cycles |
| `simd.json` | Fig. 14 | Optimized vs AVX-512 kfunc variants of the sketches |

Available metrics:

| Metric | What it measures |
|---|---|
| `throughput` | Packets per second received by the NIC |
| `cpu` | Utilization of core `cpu` |
| `ipc` | Instructions per cycle of the BPF program |
| `stalls` | `cycle_activity.stalls_total` per program run |
| `l1-misses` | `L1-dcache-load-misses` per program run |

The NitroSketch sampling rate is a compile-time constant: `samplerate` in the `*nitro1*` programs and the geometric parameter in the `*nitro2*` loaders, both set to 1/16. To reproduce the other sampling rates of Fig. 11, change it and rebuild.
