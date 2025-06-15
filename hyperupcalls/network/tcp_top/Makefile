CC = gcc
CFLAGS = -g -O2
LDFLAGS = -lclang

all: tcptop.guest tcptop.bpf.o

tcptop.guest: tcptop.guest.c ../../../hyperupcall.c ../../../hyperupcall.h ./tcptop.h
	$(CC) $(CFLAGS) $^ -o $@

tcptop.bpf.o: tcptop.bpf.c
	clang-12 $(CFLAGS) -target bpf -c $< -o $@

clean:
	rm -f tcptop.guest tcptop.bpf.o
