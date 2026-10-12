TARGETS:= tbnat nat bnat tnat obnat tobnat


.PHONY : all

all: clean $(TARGETS)

$(TARGETS): %: %.bpf.c %.c
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
