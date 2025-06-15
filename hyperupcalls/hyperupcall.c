#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "hyperupcall.h"

#define N_MAPS 8

static char* bar_addr = "/sys/bus/pci/devices/0000:05:00.0/resource2";
static const int device_index_in_bar_addr = 27;
static int map_slot_to_fd[N_MAPS] = {-1, -1, -1, -1};
static size_t maps_size[N_MAPS] = {0};

uintptr_t getPhysicalAddress(void* addr) {
    static int pm_fd = 0;
    off_t offset = (off_t)((uintptr_t)addr / PAGE_SIZE) * sizeof(uint64_t);
    uint64_t pfn;

    if (pm_fd == 0) {
        pm_fd = open("/proc/self/pagemap", O_RDONLY);
        if (pm_fd < 0) {
            perror("Failed to open pagemap");
            return 0;
        }
        printf("Opened pagemap %d\n", pm_fd);
    }

    if (pread(pm_fd, &pfn, sizeof(uint64_t), offset) != sizeof(uint64_t)) {
        perror("Failed to read pagemap");
        return 0;
    }
    printf("pfn: %p\n", (void *)pfn);

    if ((pfn & (1ULL << 63)) == 0) {
        printf("Page not present\n");
        return 0;
    }

    // Extract the page frame number from the pagemap entry
    pfn = pfn & 0x7FFFFFFFFFFFFF;
    return (pfn << 12) + ((uintptr_t)addr & 0xFFF);
}

/**
 * Gets the physical address of the array of physical addresses to the eBPF programs in the file at file_path.
 * All physical addresses are page-aligned.
 * 
 * @file_path: The path to the file containing the eBPF programs.
 * @pptr_array: Place to store the pointer to the array of physical addresses to the eBPF programs. MUST BE ALLOCATED BY USER
 * @pptr_array_size: Place to store the size of the array of physical addresses to the eBPF programs.
 * 
 * @return: NULL on failure, virtual address of mmaped file on success. This needs to be munmaped by the user.
*/
static char *get_bpf_prog_ptr_array(const char *file_path, uintptr_t *pptr_array, size_t *pptr_array_size) {
    struct stat fileStat;
    char* fileData;
    int fd;
    
    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open file");
        return NULL;
    }

    if (fstat(fd, &fileStat) == -1) {
        perror("Failed to get file size");
        close(fd);
        return NULL;
    }
    *pptr_array_size = fileStat.st_size;

    fileData = mmap(NULL, ((*pptr_array_size / PAGE_SIZE) + 1) * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (fileData == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return NULL;
    }


    uintptr_t fileDataEnd = (uintptr_t)fileData + *pptr_array_size;
    for (uintptr_t addr = (uintptr_t)fileData; addr < fileDataEnd; addr += PAGE_SIZE) {
        int pptr_idx = (addr - (uintptr_t)fileData) / PAGE_SIZE;
        pptr_array[pptr_idx] = getPhysicalAddress((void*)addr);
        if (pptr_array[pptr_idx] == 0) {
            printf("Failed to get page frame number for address %p\n", (void*)addr);
            return NULL;
        }
        printf("idx: %d, va: %p pa: %p\n", pptr_idx,  (void*)addr, (void*)(pptr_array[pptr_idx]));
    }

    return fileData;
}

unsigned long load_hyperupcall(const char* filepath) {
    off_t fileSize;
    uintptr_t *pptr_array;
    char *fileData;
    uintptr_t pptr_array_phys;

    pptr_array = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE , -1, 0);
    pptr_array[0] = 1;
    printf("pptr_array: %p\n", (void *)pptr_array[0]);
    if (pptr_array == MAP_FAILED) {
        perror("Failed to mmap pptr_array");
        return -1;
    }
    printf("pptr_array: %p\n", pptr_array);

    pptr_array_phys = getPhysicalAddress(pptr_array);
    if (pptr_array_phys == 0) {
        printf("Failed to get physical address of pptr_array\n");
        return -1;
    }

    fileData = get_bpf_prog_ptr_array(filepath, pptr_array, &fileSize);
    if (fileData == NULL) {
        printf("Failed to get bpf prog ptr array\n");
        return -1;
    }
    
    unsigned long hypercallNumber = LOAD_HYPERUPCALL;
    unsigned long hypercallArg0 = pptr_array_phys;
    unsigned long hypercallArg1 = fileSize; // Replace with your hypercall arguments
    unsigned long hypercallResult;
    printf("Calling hypercall %ld with args %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx", "%rdi", "%rsi", "%rdx");

    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    munmap(pptr_array, PAGE_SIZE);
    munmap(fileData, fileSize);
    return hypercallResult;
}

unsigned long unload_hyperupcall(unsigned long hyperupcall_slot) {
    unsigned long hypercallNumber = UNLOAD_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallResult;
    printf("Calling hypercall %ld with args %ld\n", hypercallNumber, hypercallArg0);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0)
        : "%rax", "%rbx");

    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    return hypercallResult;
}

unsigned long link_hyperupcall(unsigned long hyperupcall_slot, char *prog_name, unsigned long major_id, unsigned long minor_id) {
    char *prog_name_aligned = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(prog_name_aligned, prog_name, strlen(prog_name) + 1);
    uintptr_t prog_name_phys = getPhysicalAddress(prog_name_aligned);
    if (prog_name_phys == 0) {
        printf("Failed to get physical address of prog_name\n");
        return -1;
    }


    unsigned long hypercallNumber = LINK_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1 = prog_name_phys;
    unsigned long hypercallArg2 = major_id;
    unsigned long hypercallArg3 = minor_id;
    unsigned long hypercallResult;
    printf("Calling hypercall %ld with args %ld %ld %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1, hypercallArg2, hypercallArg3);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "movq %4, %%rdx;"
        "movq %5, %%rsi;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1), "r"(hypercallArg2), "r"(hypercallArg3)
        : "%rax", "%rbx", "%rcx", "%rdi", "%rsi");

    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    munmap(prog_name_aligned, PAGE_SIZE);
    return hypercallResult;
}

unsigned long unlink_hyperupcall(unsigned long hyperupcall_slot, unsigned long program_slot) {
    unsigned long hypercallNumber = UNLINK_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1 = program_slot;
    unsigned long hypercallResult;
    printf("Calling hypercall %ld with args %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx");

    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    return hypercallResult;
}


/**
 * Attaches a shared memory PCI device which exposes the requested map.
*/
static unsigned long __hyperupcall_map_map(unsigned long hyperupcall_slot, char *map_name) {
    void *mmaped_map_name;
    unsigned long hypercallNumber = MAP_MAP_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1;
    unsigned long hypercallResult;

    mmaped_map_name = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (mmaped_map_name == MAP_FAILED) {
        perror("Failed to mmap map_name");
        return -1;
    }
    strncpy(mmaped_map_name, map_name, PAGE_SIZE);
    hypercallArg1 = getPhysicalAddress(mmaped_map_name);

    if (hypercallArg1 == 0) {
        printf("Failed to get physical address of map_name %s\n", map_name);
        return -1;
    }

    printf("Calling hypercall %ld with args %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r"(hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx", "%rdx");
    
    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    sleep(1);
    return hypercallResult;
}

/**
 * Remove the PCI device which exposes the map.
*/
static unsigned long __hyperupcall_unmap_map(unsigned long hyperupcall_slot, unsigned long map_slot) {
    unsigned long hypercallNumber = UNMAP_MAP_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1 = map_slot;
    unsigned long hypercallResult;
    printf("Calling hypercall %ld with args %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx");

    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);
    sleep(1);
    return hypercallResult;
}

unsigned long hyperupcall_map_map(unsigned long hyperupcall_slot, char *map_name, size_t map_size, void **map_ptr) {
    int fd;
    char str[64];
    long map_slot = (long)__hyperupcall_map_map(hyperupcall_slot, map_name);
    if (map_slot < 0) {
        return map_slot;
    }

    strcpy(str, bar_addr);
    if (str[device_index_in_bar_addr] + map_slot <= '9')
        str[device_index_in_bar_addr] = str[device_index_in_bar_addr] + map_slot;
    else
        str[device_index_in_bar_addr] = 'a' + map_slot - ('9' - str[device_index_in_bar_addr]) - 1;
    printf("Opening %s\n", str);
    fd = open(str, O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("Failed to open resource2\n");
        __hyperupcall_unmap_map(hyperupcall_slot, map_slot);
        return -1;
    }
    
    map_size = map_size + (PAGE_SIZE*((bool)(map_size % PAGE_SIZE)) - (map_size % PAGE_SIZE));
    printf("Mapping %ld bytes\n", map_size);
    *map_ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (*map_ptr == MAP_FAILED) {
        printf("Failed to mmap resource2\n");
        __hyperupcall_unmap_map(hyperupcall_slot, map_slot);
        return -1;
    }
    map_slot_to_fd[map_slot] = fd;
    maps_size[map_slot] = map_size;
    return map_slot;
}

unsigned long hyperupcall_map_elem_get_set(unsigned long hyperupcall_slot, char *map_name, int map_name_len, int key, void *value, size_t value_size, bool is_set) {
    struct map_update_attr *attr;
    unsigned long hypercallNumber = UPDATE_ELEM_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1;
    unsigned long hypercallResult;

    attr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (attr == MAP_FAILED) {
        perror("Failed to mmap map_update_attr");
        return -1;
    }

    strncpy(attr->map_name, map_name, map_name_len);
    attr->key = key;
    attr->is_set = (int)is_set;
    attr->value_size = value_size;
    if (value_size > PAGE_SIZE - sizeof(attr)) {
        printf("Value size too large\n");
        munmap(attr, PAGE_SIZE);
        return -1;
    }

    if (is_set)
        memcpy((char *)attr->value, value, value_size);
        
    hypercallArg1 = getPhysicalAddress(attr);
    if (hypercallArg1 == 0) {
        printf("Failed to get physical address of map_update_attr\n");
        munmap(attr, PAGE_SIZE);
        return -1;
    }

    printf("Calling hypercall %ld with args %ld %ld\n", hypercallNumber, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx");
    
    printf("Hypercall %ld returned %ld\n", hypercallNumber, hypercallResult);

    memcpy(value, (char *)attr->value, value_size);
    munmap(attr, PAGE_SIZE);
    return hypercallResult;
}


unsigned long hyperupcall_unmap_map(unsigned long hyperupcall_slot, unsigned long map_slot, void *map_ptr) {
    int fd;
    if (map_slot >= sizeof(map_slot_to_fd) / sizeof(map_slot_to_fd[0])) {
        printf("Invalid map_slot\n");
        return -1;
    }

    fd = map_slot_to_fd[map_slot];
    if (fd < 0) {
        printf("Invalid map_slot\n");
        return -1;
    }
    if (map_ptr != NULL)
        munmap(map_ptr, maps_size[map_slot]);
    close(fd);
    map_slot_to_fd[map_slot] = -1;
    maps_size[map_slot] = 0;
    return __hyperupcall_unmap_map(hyperupcall_slot, map_slot);
}

/**        
* int main(int argc, char** argv) {
*     off_t fileSize;
*     uintptr_t *pptr_array;
*     uintptr_t pptr_array_phys, prog_name_phys;
*     const char* filepath = "/home/ubuntu/shared_folder/hyperupcall_progs/output/ebpf_test.bpf.o";
*     int r, hyperupcall_slot, program_slot;
*
*     char *prog_name = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
*     memcpy(prog_name, "xdp_prog_simple\0", sizeof("xdp_prog_simple\0"));
*     prog_name_phys = getPhysicalAddress(prog_name);
*
*
*     hyperupcall_slot = load_hyperupcall(filepath);
*     if (hyperupcall_slot < 0) {
*         printf("Failed to load hyperupcall\n");
*         return -1;
*     }
*
*     program_slot = link_hyperupcall(prog_name_phys, 0, 2);
*     if (program_slot < 0) {
*         printf("Failed to link hyperupcall\n");
*         return -1;
*     }
*     return 0;
* }
*/
