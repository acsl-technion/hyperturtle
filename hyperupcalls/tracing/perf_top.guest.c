#include <stdbool.h>
#include <signal.h>
#include "../hyperupcall.h"

#define HOOK_ID 5 // 5 for perf_event hook
#define FREQUENCY 1000 // 1000 Hz

long hyperupcall_slot, program_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
    exit(0);
}

int main() {
    hyperupcall_slot = load_hyperupcall("/home/ubuntu/shared_folder/hyperupcall_progs/tracing/perf_top.bpf.o");
    long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    program_slot = link_hyperupcall(hyperupcall_slot, "do_perf_event\0", HOOK_ID, FREQUENCY);
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