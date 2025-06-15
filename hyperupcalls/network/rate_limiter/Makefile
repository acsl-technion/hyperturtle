CC = gcc
CFLAGS = -g -O2
LDFLAGS = -lclang

all: rate_limiter.guest rate_limiter.bpf.o

rate_limiter.guest: rate_limiter.guest.c ../../hyperupcall.c ../../hyperupcall.h
	$(CC) $(CFLAGS) $^ -o $@

rate_limiter.bpf.o: rate_limiter.bpf.c
	clang-12 $(CFLAGS) -target bpf -c $< -o $@

clean:
	rm -f rate_limiter.guest rate_limiter.bpf.o
