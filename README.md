# X²DP: eXtended eXpress Data Path

This repository contains the XDP programs, the SIMD kfunc module and the FPGA bitstream used to evaluate **X²DP**. X²DP is a framework that changes the XDP event granularity from one packet to a **batch of packets**.

A standard XDP program runs once per received packet. In X²DP, an FPGA SmartNIC (AMD Alveo U55N with a modified [OpenNIC shell](https://github.com/Xilinx/open-nic-shell)) merges up to 16 packets into a single memory page and prepends a compact batching header. A modified OpenNIC driver then runs the XDP program **once per batch**. Processing a whole batch per invocation:

- removes the per-packet invocation overhead;
- allows loop unrolling and code reordering, which raise IPC;
- lets map lookups and helper calls be shared across the batch;
- makes SIMD (AVX-512) hashing worthwhile through a kfunc.

Across the evaluated applications, throughput improves by up to 3.3× over per-packet XDP.

## Repository layout

| Path | Contents |
|---|---|
| `pass/`, `drop/`, `tx/` | Microbenchmarks: one-line programs that return `XDP_PASS`, `XDP_DROP` or `XDP_TX` |
| `router/` | LPM-trie router; `router/RCC25/` holds the routing table, one file per prefix length |
| `conntrack/` | TCP/UDP connection tracking (derived from Polycube) |
| `nat/` | Source NAT built around an eBPF hash table; `*.txt` hold the address tables |
| `cms/` | Count-Min Sketch |
| `nitroSketch/` | NitroSketch: `nitro1` samples with `bpf_get_prandom_u32()`, `nitro2` with precomputed geometric random variables |
| `xxhash/` | Kernel module that exposes an AVX-512 xxhash64 as an XDP kfunc |
| `fpga/` | X²DP bitstream for the Alveo U55N, and `program_fpga.sh` to load it |
| `eval/` | Suite runner, experiment configurations and traffic generators used for the paper's results (see [`eval/README.md`](eval/README.md)) |

Each application directory contains several **variants** of the same program. A variant `X` consists of `X.bpf.c` (the eBPF program) and `X.c` (a libbpf loader). The variant name is the application name with prefixes added in front of it:

| Prefix | Meaning |
|---|---|
| *(none)* | Standard per-packet XDP (baseline) |
| `b` | Batched: per-packet logic unchanged, wrapped in a loop over the batch |
| `o` | Optimized: loop unrolling and code reordering (e.g. all parses, then all hashes, then all map updates) |
| `a` | Uses the AVX-512 hash kfunc from `xxhash/` |
| `t` | Returns `XDP_TX` instead of `XDP_DROP` (used for the latency tests) |

For example, `aobcms` is the batched, optimized CMS that uses the SIMD kfunc, and `tbrouter` is the batched router that sends packets back out. Other prefixes mark experiment-specific variants; the comment at the top of each `.bpf.c` file describes them.

## Requirements

- **NIC.** An AMD Alveo U55N programmed with `fpga/xdp_batch.bit`, plus the modified OpenNIC driver (`onic`) that decodes the batch and invokes XDP once per batch. The driver will be released in a separate repository. <!-- TODO: link to the driver repository -->
- **OS.** Linux 6.8. The evaluation used Ubuntu 24.04 on an Intel Xeon W5-3435X. AVX-512 is required for the kfunc.
- **Toolchain.** clang/LLVM (tested with 18), `bpftool`, libbpf, and gcc. The NitroSketch loaders also need GSL (`libgsl-dev`).
- **FPGA tooling.** Vitis/Vivado `xsdb` to load the bitstream, and [`pcimem`](https://github.com/billfarrow/pcimem) to set the shell registers.

## Build

```sh
make                 # every XDP application (pass drop tx router conntrack nat cms nitroSketch)
make -C cms          # a single application (all of its variants)
make -C cms aobcms   # a single variant
make kfunc           # the AVX-512 kfunc module (needs the headers of the running kernel)
```

A per-application `make` cleans that directory first. Each variant is built like this:

```sh
clang -g -O2 --target=bpf -c X.bpf.c -o X.bpf.o
bpftool gen skeleton X.bpf.o > X.bpf.skel.h
gcc -g -O2 -o X X.c -lbpf
```

## Running

1. Program the FPGA and bind the card to the modified driver:

   ```sh
   sudo insmod onic.ko                      # modified OpenNIC driver
   sudo XSDB=/path/to/xsdb PCIMEM=/path/to/pcimem \
        PCI_FUNCS="<domain:bus:dev.0> <domain:bus:dev.1>" fpga/program_fpga.sh
   ```

   `PCI_FUNCS` lists the two PCI functions of the card, one per 100G port. You can find them with `lspci -D -d 10ee:` (`10ee` is the Xilinx vendor ID). If you don't set it, the script uses `0000:16:00.0 0000:16:00.1`, which is where the card sits on our test machine.

   After a warm reboot the bitstream stays loaded, so `--no-program` is enough to redo the register setup and the driver binding.

2. If you are running an `a*` variant, load the kfunc module:

   ```sh
   make -C xxhash load
   ```

3. Start a loader. It attaches the program to the interface, fills the maps, and runs until you press Ctrl-C, which detaches it:

   ```sh
   cd router && sudo ./tbrouter <ifname> [rules_dir]   # rules_dir defaults to ./RCC25
   cd nat    && sudo ./bnat <ifname> nat_tbl.txt
   cd cms    && sudo ./obcms <ifname>
   ```

To reproduce the paper's experiments, see [`eval/README.md`](eval/README.md).

## Writing a batched program

The NIC prepends a batching header that the driver exposes as XDP metadata, i.e. the range `[ctx->data_meta, ctx->data)`:

```
data_meta: | valid bitmap (u16) | len_0 (u16) | len_1 (u16) | ... |   (network byte order)
data:      | pkt_0 | pkt_1 | ... | pkt_N-1 |                          (back to back)
```

A batched program does the following:

- Loops over at most 16 slots, skips any slot whose bit is not set in the bitmap, and advances the packet offset by `len_i`. Each length is read inside the loop and bounds-checked against `ctx->data`, so the same code works for any batch size.
- Masks the running offset with `& 0x7FFF` so the verifier sees it as bounded. A whole batch can grow past 8 KB.
- Returns its verdict packed as one 4-bit action per slot: `ACT | ACT << 4 | ... | ACT << 28`.

`cms/bcms.bpf.c` and `router/tbrouter.bpf.c` are minimal examples to start from. All batched programs are written for batches of 16 packets.

To check that every program passes the verifier, build and run `sudo scripts/verify.sh` (or `sudo scripts/verify.sh cms` for a single application). It loads each object without attaching it and prints the number of processed instructions. The `a*` variants need the kfunc module loaded.

Batch size is capped at 16 because the verifier allows a 512-byte stack and one million instructions, and both grow linearly with the number of packets per batch. Several variants contain comments that record measured verifier limits; read them before restructuring a program.

## Citation

<!-- TODO: add the BibTeX entry once the paper is published -->
V. Paschali, A. Monterubbiano, F. Fazzari, S. Miano, S. Pontarelli, *X²DP: eXtended eXpress Data Path*.

## License

The repository is released under the [Apache License 2.0](LICENSE). Files derived from third-party code keep their original license headers:

- Polycube conntrack: GPL-2.0 OR BSD-3-Clause.
- Hash function headers: their respective authors' licenses.

The eBPF programs declare a GPL-compatible license, which the kernel requires, and the kernel module in `xxhash/` is GPL.
