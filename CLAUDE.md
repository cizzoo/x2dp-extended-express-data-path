# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

X2DP: XDP network functions that process a **batch** of packets per eBPF invocation instead of one.
Each network function exists as a single-packet baseline plus several batched/optimised variants, so
the repo is a matrix of *(network function) × (variant)* rather than a single application.
[README.md](README.md) documents the batching contract, the variant-prefix naming table
(`b`/`o`/`sob`/`ub`/`ab`/`aob`/`t`/`r`), and the per-directory map — read it before touching a
`.bpf.c`.

There are no tests, no linter, and no CI. Correctness is checked by loading the program (the
verifier is the gate) and by running it against traffic.

## Build

```sh
make                 # every directory listed in the top-level Makefile
make -C cms          # all CMS variants
make -C cms bcms     # one variant
make clean
```

Each subdirectory Makefile follows the same three-step recipe per target: `clang --target=bpf -c
<name>.bpf.c`, `bpftool gen skeleton` into `<name>.bpf.skel.h`, then `gcc <name>.c -lbpf`.

Build quirks that bite:

* Every subdirectory declares `all: clean $(TARGETS)`, and the target rules have no prerequisites —
  so `make -C <dir>` is always a full rebuild and `make` never does incremental work. Name the
  single target explicitly while iterating.
* The top-level `SUBDIRS` **omits** `counter`, `afxdp`, `udp-socket`, `xxhash`, and
  `acl/kernel_helpers`. Build those with `make -C <dir>` directly.
* `cms/Makefile` passes `-DALGN=$(ALGN)` (default 64); only `abcms` reads it.
* `nitroSketch` and `bsoftware/nitroSketch` link `-lgsl -lgslcblas -lm`.
* `map/` compiles with `-DDEBUG`.

The `a*`/`aob*` variants call kfuncs that must be present before the program will load:

```sh
make -C xxhash && make -C xxhash load                          # xxhash16x4 / xxhash16x2
make -C acl/kernel_helpers && make -C acl/kernel_helpers load  # cmp_512_128_simd / load_mm512i
```

Both module Makefiles expose `load` / `unload` / `reload`, and take `GCC_VERSION=` /
`CLANG_VERSION=` overrides when the intrinsics headers are not found.

## Run

Every loader takes exactly one argument, the interface name, and stays in the foreground until
`SIGINT`/`SIGTERM` (its handler calls `bpf_xdp_detach` and destroys the skeleton). Root required.

```sh
sudo ./cms/bcms ens1f0np0
```

Batched programs only see real batches on an interface backed by the FPGA NIC programmed with
[xdp_batch.bit](xdp_batch.bit). Without it, use the [bsoftware/](bsoftware/) copies, which assume a
fixed `PAGE_SIZE` (4096 B) stride between packets and a 4-slot loop instead of reading real lengths.

## Adding or editing a variant

The skeleton-based loader ties three names together — **the `SEC("xdp")` function name, the file
basename, and the Makefile target must all match**. `make -C cms bcms` produces `bcms.bpf.skel.h`,
which declares `struct bcms_bpf`, `bcms_bpf__open_and_load()`, and `skel->progs.bcms`; the loader
`cms/bcms.c` uses exactly those. Adding a variant means: copy the `.bpf.c`/`.c` pair, rename the
program function to the new basename, fix the `#include "<name>.bpf.skel.h"` and the three
`<name>_bpf` symbols in the loader, and append the name to `TARGETS`.

New variants are almost always copy-then-diverge from an existing one in the same directory rather
than a shared header — the duplication across `cms/*.bpf.c` is deliberate, since each variant is a
separate measurement point. Do not refactor variants into a common implementation.

### Batched-program invariants

Modelled by [cms/bcms.bpf.c](cms/bcms.bpf.c), the most current program:

* Every return path — including *all* error paths — must return the packed nibble verdict
  (`XDP_DROP + (XDP_DROP << 4) + ...`), not a bare `XDP_DROP`. A bare verdict on an error path
  silently mis-applies to the whole batch.
* Read per-packet lengths inline from `data_meta + 2 + 2*i` with a `lp + 2 <= data` bounds check,
  rather than through the fixed `struct t_meta`. That is what makes one binary work for any batch
  size (4/6/8/12/16) — slots past the header contribute length 0. Older programs still use the
  fixed struct and a hardcoded loop bound; that is legacy, not the pattern to copy.
* Keep the `data + (lentot & 0x1FFF)` mask: it exists purely to give the verifier a bounded offset.

### Verifier / codegen gotchas already hit here

* `__sync_fetch_and_add` on sketch counters produces codegen the verifier rejects; the code uses a
  plain increment instead (see `countmin_add`). Do not "fix" this back to an atomic.
* `bpf_printk` calls litter error paths. They are free only when not taken — strip them before
  measuring anything.
* Loop bounds are compile-time constants everywhere so the verifier can unroll; the `o*` variants
  exist specifically to explore unrolling and branch-reduction, so their shape is intentional.

## Related project

The additional working directory `/mnt/shared_p2p/XDP_CLONE/mellanox-clone-xdp` is a **separate**
project: a modified out-of-tree mlx5 driver adding `XDP_CLONE_PASS`/`XDP_CLONE_TX` return actions.
It has its own `AGENT.md`. It shares the "pack extra information into the XDP return value" idea
with this repo but is not part of the X2DP build.
