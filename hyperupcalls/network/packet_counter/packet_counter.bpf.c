// #include "../../vmlinux_guest.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define MAP_SIZE 1

/**
 * This progra
*/


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAP_SIZE);
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} packets SEC(".maps");


SEC("xdp")
int packet_counter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *counter;
    __u64 new_counter = 0;
    counter = bpf_map_lookup_elem(&packets, &key);
    if (counter == NULL) {
        bpf_map_update_elem(&packets, &key, &new_counter, 0);
        return XDP_PASS;
    }

    *counter = *counter + 1;
    bpf_map_update_elem(&packets, &key, counter, 0);
    return XDP_PASS;
}


