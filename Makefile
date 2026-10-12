# XDP programs and their libbpf loaders (clang, bpftool, libbpf).
BPF_DIRS := pass drop tx router conntrack nat cms nitroSketch

# Built separately: kernel headers for the kfunc module, libdpdk for the
# DPDK baselines.
DPDK_DIRS := dpdk dpdk/router dpdk/conntrack

.PHONY: all kfunc dpdk clean $(BPF_DIRS) $(DPDK_DIRS)

all: $(BPF_DIRS)

$(BPF_DIRS) $(DPDK_DIRS):
	@$(MAKE) -C $@

kfunc:
	@$(MAKE) -C xxhash

dpdk: $(DPDK_DIRS)

clean:
	@for dir in $(BPF_DIRS) $(DPDK_DIRS) xxhash; do \
		$(MAKE) -C $$dir clean; \
	done
