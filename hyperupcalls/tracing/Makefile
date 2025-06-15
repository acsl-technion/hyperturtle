CC = gcc
CFLAGS = -g -O2
LDFLAGS = -lclang

all: perf_top.guest perf_top.bpf.o

# perf_top: perf_top.c ../hyperupcall.c ../hyperupcall.h
# 	$(CC) $(CFLAGS) $^ -o $@

perf_top.guest: perf_top.guest.c ../hyperupcall.c ../hyperupcall.h
	$(CC) $(CFLAGS) $^ -o $@

perf_top.bpf.o: perf_top.bpf.c
	clang-12 $(CFLAGS) -H -target bpf -c $< -o $@

clean:
	rm -f perf_top perf_top.bpf.o
