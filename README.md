# X2DP 

Standard XDP invokes the eBPF program **once per packet**. X2DP hands the program a **batch** of
packets in a single invocation, so a network function can amortise per-call overhead, prefetch
across packets, and apply the same operation to several packets at once with SIMD.

This repository contains the eBPF/XDP network functions used in the evaluation, each in a
single-packet baseline version and one or more batched versions, plus the DPDK / AF_XDP / socket
baselines, the SIMD kernel modules, and the FPGA bitstream that produces the batches.

---

## The batching contract

A batched program sees the packets of a batch laid out back-to-back in the XDP frame, preceded by a
**batch header placed in the XDP metadata area** (`ctx->data_meta` … `ctx->data`).

**Header layout** (all fields big-endian / network order):

| Offset | Field | Meaning |
| --- | --- | --- |
| `0` | `valid` (`u16`) | Bitmap: bit `i` set ⇒ slot `i` of the batch carries a packet |
| `2 + 2*i` | `len[i]` (`u16`) | Length of packet `i`, used to advance to packet `i+1` |

Older programs declare this as a fixed struct:

```c
struct t_meta {
    unsigned short valid;
    unsigned short len1, len2, len3;
};
```

The most recent programs (e.g. [cms/bcms.bpf.c](cms/bcms.bpf.c)) read each length **inline** from
`data_meta + 2 + 2*i`, bounds-checked against `ctx->data`. That makes a single binary work for any
batch size (4 / 6 / 8 / 12 / 16) — slots whose length field falls past the end of the header simply
contribute 0 — and keeps the verifier's job cheap by avoiding an intermediate array.

**Return value.** One 4-bit XDP verdict per packet, packed into the return code:

```c
return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
```

so slot `i`'s action lives in nibble `i`. The driver unpacks it and applies each verdict to its
packet.

**Walking the batch** is therefore:

```c
__u16 lentot = 0;
for (int i = 0; i < 16; i++) {
    if (bpf_ntohs(md->valid) & (1 << i)) {
        handle_pkt(data + (lentot & 0x1FFF), data_end, &pkt);
        __u8 *lp = (__u8 *)data_meta + 2 + (i << 1);
        if (lp + 2 <= data)
            lentot += bpf_ntohs(*(__u16 *)lp);
    }
}
```

The `& 0x1FFF` mask is there to keep the verifier happy about the offset bound.

---

## Naming convention

Every network function directory holds several variants of the same program. The prefix encodes
what changed; the pattern is consistent across `cms`, `nitroSketch`, `nat`, `conntrack`, `router`,
`acl`, `loadbalancer`, `sampler`:

| Prefix | Meaning |
| --- | --- |
| *(none)* | Baseline: one packet per XDP invocation |
| `b` | **Batched** — one XDP invocation per batch |
| `o` | Other optimizations, loop unrolling, instructions reordering, less branching  or less map access|
| `sob` | Unrolled + **split map access**: load all counters, then store them, so the loads can overlap |
| `ub` | Batched with **one map access per packet** (vs. one per batch in `b`) |
| `ab` / `aob` | **AVX** variant — hashes several packets at once via a SIMD kfunc |
| `t` / `tb` | Same program but returning `XDP_TX` instead of `XDP_DROP` (forwarding path) |
| `r` / `rb` / `rob` | **Random sampling** variants (used by the NitroSketch/CMS sampling experiments) |

Each variant is a pair: `<name>.bpf.c` (the XDP program) and `<name>.c` (the libbpf loader, which
takes the interface name as its only argument).

---

## Repository layout

### Network functions

| Directory | What it is |
| --- | --- |
| [cms/](cms/) | Count-Min Sketch — the main case study; all variants incl. AVX and TX |
| [cmsOptimizations/](cmsOptimizations/) | CMS variants isolating one optimisation at a time (unrolling, split access, sampling) |
| [nitroSketch/](nitroSketch/) | NitroSketch, two flavours (`nitro1`, `nitro2`) × all variants |
| [conntrack/](conntrack/) | Stateful connection tracking |
| [nat/](nat/) | NAT (address rewriting), with `XDP_TX` forwarding variants |
| [router/](router/) | LPM IPv4 router; [router/RCC25/](router/RCC25/) holds the prefix tables by prefix length |
| [acl/](acl/) | Access control lists; `abacl` uses AVX-512 rule comparison via a kfunc. Rule sets from 10 to 100k rules |
| [loadbalancer/](loadbalancer/) | Consistent-hash load balancer over 512 backends |
| [sampler/](sampler/) | Per-packet random sampling inside a batch |

### Microbenchmarks

| Directory | What it measures |
| --- | --- |
| [drop/](drop/) | Bare `XDP_DROP` — the floor of the batching overhead |
| [pass/](pass/) | Bare `XDP_PASS` |
| [tx/](tx/) | `XDP_TX` / MAC-swap / `bpf_redirect` paths |
| [map/](map/) | Cost of map lookups in a batch |
| [counter/](counter/) | Per-source-IP counting; `bpcounter` isolates the prefetch effect |

### Baselines and support

| Directory | Contents |
| --- | --- |
| [dpdk/](dpdk/) | DPDK implementation of CMS/NitroSketch (`l2fwd`-based) with the AVX xxhash |
| [afxdp/](afxdp/) | AF_XDP baseline |
| [udp-socket/](udp-socket/) | Plain UDP socket baseline (`socketCMS.c`) |
| [xxhash/](xxhash/) | Kernel module exporting the AVX-512 kfuncs `xxhash16x4` / `xxhash16x2` (4 or 2 keys hashed in parallel) |
| [acl/kernel_helpers/](acl/kernel_helpers/) | Kernel module exporting `cmp_512_128_simd` / `load_mm512i` for the ACL |
| [bsoftware/](bsoftware/) | Software-batched copies of CMS, NitroSketch, conntrack, NAT, router |

---

## Building

### Requirements

* Linux with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and kernel headers installed
* `clang` ≥ 15 with the BPF target, `llvm`, `bpftool`, `libbpf-dev`, `gcc`
* `libgsl-dev` (only for `nitroSketch`, which links `-lgsl -lgslcblas -lm`)
* An AVX-512 capable CPU for the `a*` variants and the SIMD kernel modules
* DPDK ≥ 20.11 for [dpdk/](dpdk/)

### All XDP programs

```sh
make
```

The top-level [Makefile](Makefile) recurses into every network-function directory. Each one compiles
`<name>.bpf.c` with `clang --target=bpf`, generates a skeleton with `bpftool gen skeleton`, and links
the userspace loader against `libbpf`.

To build a single one:

```sh
make -C cms          # every CMS variant
```

`make clean` at the top level cleans all subdirectories.

### SIMD kernel modules

The `a*` (AVX) programs call kfuncs that must be loaded first:

```sh
make -C xxhash  && make -C xxhash load             # xxhash16x4 / xxhash16x2
make -C acl/kernel_helpers && make -C acl/kernel_helpers load   # ACL compare
```

Both Makefiles expose `load` / `unload` / `reload` targets. Adjust `GCC_VERSION` /
`CLANG_VERSION` if the intrinsics headers are not found:

```sh
make -C xxhash GCC_VERSION=12
```

### DPDK baseline

```sh
make -C dpdk        # builds the `l2fwd`-style app in dpdk/build/
```

---

## Running

Every loader takes the interface to attach to and stays in the foreground until `SIGINT`/`SIGTERM`,
detaching the program on exit:

```sh
sudo ./cms/bcms ens1f0np0        # batched Count-Min Sketch
sudo ./cms/cms  ens1f0np0        # single-packet baseline, same NF
sudo ./drop/bdrop ens1f0np0      # batched drop microbenchmark
```

For the batched programs to see real batches, the interface must be backed by the FPGA NIC
programmed with [xdp_batch.bit](xdp_batch.bit); otherwise use the software-batched copies in
[bsoftware/](bsoftware/).

Some programs read their tables from the text files next to them — `nat/nat_tbl.txt`,
`acl/*_rules.txt`, `loadbalancer/512dest.csv`, `router/RCC25/<prefixlen>.txt` — check the
corresponding loader for the exact expectations.

---

## Notes

* The batch size is a compile-time property of the program (the loop bound) and a runtime property
  of the producer. The current `cms/bcms` iterates 16 slots and works for any actual batch size;
  older variants are fixed at 4.
* Several programs still contain `bpf_printk` calls on the error paths. They are cheap only when
  the paths are not taken — remove them before measuring if you hit them.
* `__sync_fetch_and_add` on the sketch counters is commented out in favour of a plain increment;
  the atomic version caused clang codegen the verifier rejected.

## License

Mixed. Files derived from Sebastiano Miano's original network functions carry an Apache-2.0 header;
the BPF objects declare `Dual BSD/GPL` or `GPL` licenses as required by the kernel. See the headers
of individual files.
