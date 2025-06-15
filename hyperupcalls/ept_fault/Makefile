CC = gcc
CFLAGS = -g -O2 -H
LDFLAGS = -lclang

all: ept_fault.guest ept_fault.bpf.o

ept_fault.guest: ept_fault.guest.c ../../hyperupcall.c ../../hyperupcall.h ./ept_fault.h
	$(CC) $(CFLAGS) $^ -o $@

ept_fault.bpf.o: ept_fault.bpf.c
	clang-12 $(CFLAGS) -target bpf -c $< -o $@

clean:
	rm -f ept_fault.guest ept_fault.bpf.o
