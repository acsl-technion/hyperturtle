#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define NETDEV_IFINDEX 2

#define LOAD_HYPERUPCALL 13
#define UNLOAD_HYPERUPCALL 14
#define LINK_HYPERUPCALL 15
#define UNLINK_HYPERUPCALL 16
#define MAP_MAP_HYPERUPCALL 17
#define UNMAP_MAP_HYPERUPCALL 18
#define UPDATE_ELEM_HYPERUPCALL 19
#define PAGE_SIZE 4096

enum {
    HYPERUPCALL_MAJORID_XDP = 0,
    HYPERUPCALL_MAJORID_PAGEFAULT,
    HYPERUPCALL_MAJORID_TC_EGRESS,
    HYPERUPCALL_MAJORID_DIRECT_EXE,
    HYPERUPCALL_MAJORID_MAX,
};

struct map_update_attr {
    char map_name[512];
    unsigned int key;
    size_t value_size;
    bool is_set;
    char value[0];
};

unsigned long load_hyperupcall(const char* filepath);
unsigned long unload_hyperupcall(unsigned long hyperupcall_slot);
unsigned long link_hyperupcall(unsigned long hyperupcall_slot, char *prog_name, unsigned long major_id, unsigned long minor_id);
unsigned long unlink_hyperupcall(unsigned long hyperupcall_slot, unsigned long program_slot);
unsigned long hyperupcall_map_map(unsigned long hyperupcall_slot, char *map_name, size_t map_size, void **map_ptr);
unsigned long hyperupcall_unmap_map(unsigned long hyperupcall_slot, unsigned long map_slot, void *map_ptr);
unsigned long hyperupcall_map_elem_get_set(unsigned long hyperupcall_slot, char *map_name, int map_name_len, int key, void *value, size_t value_size, bool is_set);