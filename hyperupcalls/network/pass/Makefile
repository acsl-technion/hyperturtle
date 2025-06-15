CC = gcc
CFLAGS = -g -O2
LDFLAGS = -lclang

all: pass.guest pass.bpf.o pass_tc_egress.guest pass_tc_ingress.guest

pass.guest: pass.guest.c ../../hyperupcall.c ../../hyperupcall.h
	$(CC) $(CFLAGS) $^ -o $@

pass_tc_egress.guest: pass.guest.c ../../hyperupcall.c ../../hyperupcall.h
	$(CC) $(CFLAGS) $^ -DHYPERUPCALL_USE_TC_EGRESS -o $@

pass_tc_ingress.guest: pass.guest.c ../../hyperupcall.c ../../hyperupcall.h
	$(CC) $(CFLAGS) $^ -DHYPERUPCALL_USE_TC_INGRESS -o $@

pass.bpf.o: pass.bpf.c
	clang-12 $(CFLAGS) -target bpf -c $< -o $@

pass.user: pass.user.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f pass.guest pass.bpf.o
