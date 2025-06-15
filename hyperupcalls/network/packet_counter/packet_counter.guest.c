#include <stdbool.h>
#include <signal.h>
#include <libgen.h>
#include "../../hyperupcall.h"

long hyperupcall_slot, program_slot, map_slot;
unsigned long *map = MAP_FAILED;

void sigint_handler(int sig_num) {
    hyperupcall_unmap_map(hyperupcall_slot, map_slot, map);
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
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
    strcpy(dir_path + strlen(dir_path), "/packet_counter.bpf.o");
    printf("Loading hyperupcall from %s\n", path);
    hyperupcall_slot = load_hyperupcall(path);
    unsigned long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    program_slot = link_hyperupcall(hyperupcall_slot, "packet_counter\0", 0, NETDEV_INDEX);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    map_slot = hyperupcall_map_map(hyperupcall_slot, "packets\0", PAGE_SIZE, (void **)&map);
    if (map_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, program_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);

    int i = 0;
    printf("starting loop\n");
    while(true) {
        // printf("mmap packets: %ld\n", map[0]);
        sleep(2);
    }

    return 0;
}