#include <stdbool.h>
#include <signal.h>
#include "../../hyperupcall.h"

#ifdef HYPERUPCALL_USE_TC_INGRESS
#define HOOK_ID 4
#elif HYPERUPCALL_USE_TC_EGRESS
#define HOOK_ID 2
#else
#define HOOK_ID 0
#endif

long hyperupcall_slot, program_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
    system("ssh ori@10.0.10.2 -i /home/ubuntu/.ssh/id_ed25519 sudo tc qdisc del dev tap1 clsact");
    exit(0);
}

int main() {
    hyperupcall_slot = load_hyperupcall("/home/ubuntu/shared_folder/hyperupcall_progs/network/pass/pass.bpf.o");
    long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    program_slot = link_hyperupcall(hyperupcall_slot, "pass\0", HOOK_ID, NETDEV_INDEX);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);

    while(true) {
        sleep(2);
    }

    return 0;
}