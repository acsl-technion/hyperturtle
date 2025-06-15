GCC = gcc -g -O0
CLANG = clang -g -O2 -target bpf

BPF_SRC = $(shell find . -name "*.bpf.c")
BPF_OBJ = $(BPF_SRC:.c=.o)

GUEST_SRC = $(shell find . -name "*.guest.c")
GUEST_EXE = $(GUEST_SRC:.c=)

%.bpf.o: %.bpf.c
    $(CLANG) -c $< -o $@

%.guest: %.guest.c
    $(GCC) $< ../../hyperupcall.c ../../hyperupcall.h -o $@

all: $(BPF_OBJ) $(GUEST_EXE)