#include <stdbool.h>
#include <signal.h>
#include <linux/bpf.h>
#include "../../hyperupcall.h"

// ip 10.0.10.1
#define IP 0x010a000a
long hyperupcall_slot, program_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
    exit(0);
}

typedef struct rule_t {
    __u32 ip;
    __u16 port;
    __u8 protocol;
    __u8 action;
};

int main() {
    hyperupcall_slot = load_hyperupcall("./packet_filter.bpf.o");
    rule pass = {.ip =  IP,.port = 11211, protocol = IPPROTO_TCP .action = XDP_PASS}, drop = {.port = 0, .action = XDP_DROP};
    rule pass = {.ip =  IP,.port = 11211, protocol = IPPROTO_UDP .action = XDP_PASS}, drop = {.port = 0, .action = XDP_DROP};
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }

    program_slot = link_hyperupcall(hyperupcall_slot, "packet_filter\0", 0, NETDEV_INDEX);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);

    while(true) {
        sleep(2);
        // hyperupcall_map_elem_get_set(hyperupcall_slot, "packets\0", sizeof("packets\0"), 0, &value, sizeof(value), false);
        // printf("packets: %ld\n", value);
    }

    return 0;
}