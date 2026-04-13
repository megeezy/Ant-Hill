# Makefile to compile eBPF code

CLANG ?= clang
LLC ?= llc
BPF_TARGET = bpf

CFLAGS = -O2 -target bpf -D__TARGET_ARCH_x86

anthill.bpf.o: src/anthill.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o *.o
