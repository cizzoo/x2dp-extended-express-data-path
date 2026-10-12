TARGETS := bnitro1 nitro1 obnitro1 nitro2 bnitro2 obnitro2 abnitro2 abnitro1 aobnitro1 aobnitro2

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): %: %.bpf.c %.c
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf -lgsl -lgslcblas -lm

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
