TARGETS:=btx tx swaptx bswaptx swappass bswappass redirect 


.PHONY : all

all: $(TARGETS)

$(TARGETS): %: %.bpf.c %.c
	clang -g -O2 -target bpf -c $@.bpf.c -o $@.bpf.o 
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f *.o *.skel.h $(TARGETS)
