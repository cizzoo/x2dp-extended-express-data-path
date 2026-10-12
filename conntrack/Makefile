TARGETS := conntrack bconntrack tbconntrack tconntrack obconntrack pobconntrack lpobconntrack salbconntrack

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): %: %.bpf.c %.c
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf -DBATCH_SIZE

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
