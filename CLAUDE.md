# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

eBPF/XDP benchmark programs for **X²DP (eXtended eXpress Data Path)**, described in `XDPBatch_ToN.pdf`. An FPGA SmartNIC (AMD Alveo U55N running a modified OpenNIC shell; the bitstream is `fpga/xdp_batch.bit`, loaded with `fpga/program_fpga.sh`) merges up to N=16 received packets into a single memory page with an in-band batching header. A modified OpenNIC driver then calls the XDP program **once per batch** instead of once per packet. The modified driver and the HDL are **not** in this repo. This repo holds the XDP programs, their userspace loaders, an AVX-512 kfunc kernel module, and DPDK comparison baselines.

The paper's argument is that batching removes the per-packet invocation overhead (B1). That in turn makes three more optimizations possible: code reordering/loop unrolling for better IPC (B2), sharing map lookups and helper calls across the batch (B3), and SIMD hashing through a kfunc (B4). Most of the files here are variants of one application that switch these optimizations on or off.

## Build

Each application directory has its own Makefile with a `TARGETS` list. Every target `X` is built from `X.bpf.c` (the BPF program) and `X.c` (the libbpf loader):

```sh
clang -g -O2 --target=bpf -c X.bpf.c -o X.bpf.o
bpftool gen skeleton X.bpf.o > X.bpf.skel.h
gcc -g -O2 -o X X.c -lbpf          # nitroSketch also links -lgsl -lgslcblas -lm
```

- `make -C <dir>` runs `clean` first and then rebuilds every target in that directory. To build a single variant, run `make -C <dir> <target>`. A new variant needs to be added to `TARGETS`.
- The top-level `make` builds only the XDP applications. `make kfunc` builds `xxhash/`, and `make dpdk` builds the DPDK baselines.
- `xxhash/` is an out-of-tree **kernel module** (built with `bear -- make -C /lib/modules/$(uname -r)/build`). Use `make load`, `make unload` and `make reload` to manage it, and pass `LLVM=1` to build it with clang. It has to be loaded before any `a*` program that uses the kfunc.
- `dpdk/`, `dpdk/router/` and `dpdk/conntrack/` contain DPDK (pkg-config `libdpdk`) versions that serve as the comparison baseline.

There is no test suite. The checks are: the program has to pass the verifier at load time (`sudo scripts/verify.sh [dir]` loads every built object without attaching it and prints the processed instruction count), and then it is benchmarked on the real NIC. To run a loader, use `sudo ./X <ifname>`. It attaches the program, fills its maps, and spins until SIGINT, which detaches it. Router loaders take the rules directory as an optional second argument (default `./RCC25`). NAT loaders take the address table file as their second argument. Use `bpftool prog`/`bpftool map` to inspect loaded state and `llvm-objdump -d X.bpf.o` to inspect the generated code.

## Variant naming convention

The prefixes on a base name (`cms`, `nat`, `router`, `conntrack`, `nitro1`/`nitro2`, ...) are combined, e.g. `aobcms`:

| prefix | meaning |
|---|---|
| (none) | standard per-packet XDP, used as the baseline |
| `b` | batched: a for-loop over the slots in the batch, with unchanged per-packet logic (paper Listing 1) |
| `ob` | optimized batched: loop unrolling plus code reordering (all parses → all hashes/lookups → all updates; Listing 2) |
| `a` | uses the AVX-512 hash kfunc from `xxhash/` (SIMD, B4) |
| `t` | returns `XDP_TX` instead of `XDP_DROP`, for the latency tests (e.g. `tbrouter`, `tbnat`) |
| `s`, `u`, `p`, `lp`, `sal`, `oo`, ... | experiment-specific variants (e.g. `pobconntrack` uses an open-addressing array table, and `torouter` puts an LRU flow cache in front of the LPM trie). Before changing one, read the comment block at the top of the file or above the `SEC("xdp")` function |

## Batch format (what every batched program must handle)

- **Header location:** the batching header is in the XDP metadata area `[ctx->data_meta, ctx->data)`. The first `__u16` (network order) is the valid-packet **bitmap**. It is followed by per-packet `__u16` lengths at `data_meta + 2 + 2*i`. Packets are stored back to back starting at `ctx->data`.
- **Batch size:** all batched programs target batch 16. At batch 16 the header is 32 B (bitmap plus 15 explicit lengths). The FPGA rounds the header up to 4, 8 or 16 slots, and the length of the last packet is implicit.
- **Current pattern:** the current pattern (from commit `4885b49` onward) reads each length inline inside the loop, with a bounds check against `data` (`if (lp + 2 <= data) lentot += ...`). This lets the same code work for batch sizes 4, 6, 8, 12 and 16, and a slot past the end of the header counts as length 0.
- **Offset mask:** mask the running offset with `lentot & 0x7FFF`, **not** `0x1FFF`. The mask only exists so the verifier sees a bounded offset. It has to cover the whole batch (16 × 1518 + header, which fits in the driver's 32 KB RX buffer). With `0x1FFF` the offset wraps once the batch is larger than 8 KB, and the tail packets get parsed from the start of the buffer. The `data_end` checks in the per-packet parser are what actually provide safety.
- **Skipping a slot:** advance the offset even for slots you skip. Skip a single packet with `continue` or a sentinel (e.g. `l4proto = 0`) rather than `return`, so one bad frame (ARP, IPv6) doesn't abort processing of the whole batch.
- **Return value:** the return value packs one XDP action per slot, 4 bits each, all 8 nibbles: `ACT + (ACT<<4) + ... + (ACT<<28)`. The current driver (`onic-driver`, branch `main`, not in this repo) reads only `ret & 0xF` and applies it to the whole batch, so return the same action for every slot. On `XDP_TX` the whole page is sent back with an updated bitmap and the NIC filters it. `XDP_REDIRECT` is not supported.

## Verifier constraints that shape the code

- N is capped at 16 because of the 512 B BPF stack and the 1M-instruction verifier limit. Both grow linearly with batch size.
- Unrolling the whole batch can blow the instruction limit, especially with variable-offset packet **writes** (NAT `update_ipaddr`). `nat/obnat.bpf.c` uses 4-way partial unrolling so the verifier converges on the loop back-edge. In `conntrack/lpobconntrack.bpf.c`, keeping several packets in flight through the state machine multiplies verifier states: only 1 packet in flight is accepted at batch 16. These header comments record measured results, so read them before restructuring.
- Remove `bpf_printk` from hot paths. Each call costs about 1 µs, and several existing parsers are not gated by a log level.
- Share per-batch work across the batch. Do one map lookup for the CMS array, one `bpf_ktime_get_ns()` per batch, and one `bpf_get_prandom_u32()` for NitroSketch, instead of one per packet.

## SIMD kfunc

`xxhash/xxhash_avx.c` registers kfuncs for `BPF_PROG_TYPE_XDP` and wraps them in `kernel_fpu_begin/end`. It exports `xxhash16x16(const __u64 *buf, __u32 seed, __u64 *out)`, which hashes 16 keys of 16 B (an unpacked, zero-initialized `struct pkt_5tuple`) into 16 u64 values with a single call per batch, plus `xxhash16x16_gather`, which is the same function with a gather-based load path. The `a*` programs declare it with `__ksym`. The verifier only checks the first 8 bytes behind each pointer argument, so `buf` and `out` must be stack arrays owned by the program (256 B + 128 B of the 512 B stack). The name a program declares has to match a symbol the loaded module exports, otherwise the load fails. Other headers (`xxhash64.h`, `fasthash.h`, `lookup3.h`, `jhash.h`) are copied into each application directory instead of shared.

## Repo hygiene

`.gitignore` starts with `*` and then re-includes only directories and files that have an extension. As a result, loader binaries (which have no extension) are ignored. Build outputs, logs, `*.pdf` and `.claude/` are ignored explicitly. `LICENSE` and `Makefile` are re-included by name. If you add a new kind of generated file, add it to `.gitignore`.
