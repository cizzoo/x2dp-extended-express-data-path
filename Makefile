# XDP programs and their libbpf loaders (clang, bpftool, libbpf).
BPF_DIRS := pass drop tx router conntrack nat cms nitroSketch

.PHONY: all kfunc clean $(BPF_DIRS)

all: $(BPF_DIRS)

$(BPF_DIRS):
	@$(MAKE) -C $@

# The kfunc module needs the headers of the running kernel.
kfunc:
	@$(MAKE) -C xxhash

clean:
	@for dir in $(BPF_DIRS) xxhash; do \
		$(MAKE) -C $$dir clean; \
	done
