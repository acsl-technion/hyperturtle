CC = gcc
CFLAGS = -g -O2
LDFLAGS = -lclang

all: packet_counter.guest packet_counter.bpf.o

packet_counter.guest: packet_counter.guest.c ../../hyperupcall.c ../../hyperupcall.h
	$(CC) $(CFLAGS) $^ -o $@

packet_counter.bpf.o: packet_counter.bpf.c
	clang-12 $(CFLAGS) -target bpf -c $< -o $@

clean:
	rm -f packet_counter.guest packet_counter.bpf.o
