#include <stdbool.h>
#include <signal.h>
#include <libgen.h>
#include <sys/wait.h>
#include "../../../hyperupcall.h"
// #include "tcptop.bpf.h"

int hyperupcall_slot;
int nic_prog_slot, bridge_prog_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, nic_prog_slot);
    unlink_hyperupcall(hyperupcall_slot, bridge_prog_slot);
    unload_hyperupcall(hyperupcall_slot);
    system("ssh ori@10.20.0.2 -i /home/ubuntu/.ssh/id_ed25519 sudo tc qdisc del dev tap1 clsact");
    exit(0);
}

int main() {
    int fd;
    char path[2048];
    char *dir_path;
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (len != -1) {
        path[len] = '\0';
        printf("Executable path: %s\n", path);

        // Get the directory path
        dir_path = dirname(path);
        printf("Directory path: %s\n", dir_path);
    } else {
        printf("Failed to get executable path\n");
    }
    strcpy(path, dir_path);
    strcpy(dir_path + strlen(dir_path), "/tcptop.bpf.o");
    printf("Loading hyperupcall from %s\n", path);
    hyperupcall_slot = load_hyperupcall(path);
    unsigned long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    nic_prog_slot = link_hyperupcall(hyperupcall_slot, "tcptop_int\0", 2, NETDEV_IFINDEX);
    if (nic_prog_slot < 0) {
        printf("Failed to link hyperupcall nic_prog_slot\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }
    bridge_prog_slot = link_hyperupcall(hyperupcall_slot, "tcptop_br\0", 0, NETDEV_IFINDEX);
    if (bridge_prog_slot < 0) {
        printf("Failed to link hyperupcall bridge_prog_slot\n");
        unlink_hyperupcall(hyperupcall_slot, nic_prog_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }
    signal(SIGINT, sigint_handler);
    printf("Press Ctrl+C to stop\n");
    while(1) {
        sleep(1);
    }
}