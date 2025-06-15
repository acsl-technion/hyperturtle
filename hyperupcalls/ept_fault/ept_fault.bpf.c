// #include <linux/bpf.h>
#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include "ept_fault.h"

enum memslot_cache_key {
    MEMSLOT_CACHE_L1 = 0,
    MEMSLOT_CACHE_L0,
    N_MEMSLOT_CACHE_KEYS
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFN_CACHE_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} pfn_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_GUEST_MEM / (PAGE_SIZE*PTES_PER_TABLE));
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} sp_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, N_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_base_gfns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_npages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_userspace_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_base_gfns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_npages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_userspace_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2*NO_MAP_MAP_SIZE);
    __type(key, __u32); // gpa
    __type(value, __u64); // pfn
    // __uint(map_extra, 1); // pages array address
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} no_map_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2*REMAP_RING_SIZE);
    __type(key, __u32); // gpa
    __type(value, __u64); // pfn
    // __uint(map_extra, 1); // pages array address
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} remap_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, N_MEMSLOT_CACHE_KEYS);
    __type(key, __u32); 
    __type(value, __u32); // Index to memslot map
    // __uint(map_extra, 1); // pages array address
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} memslot_cache SEC(".maps");


static __always_inline void get_l1_memslot_at_index(__u64 **base_gfn, __u64 **npages, __u64 **userspace, __u32 index) {
    *base_gfn = bpf_map_lookup_elem(&l1_memslots_base_gfns, &index);
    *npages = bpf_map_lookup_elem(&l1_memslots_npages, &index);
    *userspace = bpf_map_lookup_elem(&l1_memslots_userspace_addr, &index);
}


static __always_inline __u64 get_l1_user_addr(__u64 gfn, __u64 *flags_ret) {
    __u64 pfn = 0;
    __u64 *base_gfn, *npages, *userspace;
    __u64 userspace_addr;
    int key, *cache_key;

    key = MEMSLOT_CACHE_L1;
    cache_key = bpf_map_lookup_elem(&memslot_cache, &key);
    if (cache_key != NULL) 
        get_l1_memslot_at_index(&base_gfn, &npages, &userspace, gfn);
    if (base_gfn != NULL && npages != NULL && userspace != NULL && *base_gfn != 0 && gfn >= *base_gfn && gfn < *base_gfn + *npages) {
        return *userspace + ((gfn - *base_gfn)*PAGE_SIZE);
    }

    for (int i = 0; i < MAX_MEMSLOTS; i++) {
        int current_i = i;
        get_l1_memslot_at_index(&base_gfn, &npages, &userspace, current_i);
        if (base_gfn == NULL || npages == NULL || userspace == NULL) {
            continue;
        }
        if (*userspace == 0) {
            break;
        }
        if (gfn >= *base_gfn && gfn < *base_gfn + *npages && *npages > 0x1000) {
            key = MEMSLOT_CACHE_L1;
            bpf_map_update_elem(&memslot_cache, &key, &current_i, BPF_ANY);
            userspace_addr = *userspace + ((gfn - *base_gfn)*PAGE_SIZE);
            return userspace_addr;
        }
    }
    return 0;
}

static __always_inline bool is_in_no_map_list(__u64 gfn) {
    __u64 *elem;
    unsigned int i = 0, cur_i, key;
    unsigned int *head, *tail, cur_tail;
    key = NO_MAP_TAIL;
    tail = bpf_map_lookup_elem(&counter, &key);
    key = NO_MAP_HEAD;
    head = bpf_map_lookup_elem(&counter, &key);
    if (head == NULL || tail == NULL) {
        return false;
    }
    cur_tail = *tail;
    do {
        cur_i = i;
        __u64 *elem = bpf_map_lookup_elem(&no_map_list, &cur_tail);
        if (elem == NULL || *elem == 0) {
            break;
        }
        // bpf_printk("elem: %llx gfn: %llx\n", *elem, gfn);
        if (*elem == gfn)
            return true;
        cur_tail = (cur_tail + 1) % NO_MAP_MAP_SIZE;
        i++;
    } while (i < NO_MAP_MAP_SIZE);
    return false;
}

static __always_inline __u64 create_epte(__u64 pfn) {
    return (pfn << 12) | RW_EPTE_FLAGS;
}

static __always_inline __u64 create_pte(__u64 pfn) {
    return (pfn << 12) | RW_PTE_FLAGS;
}


static __always_inline __u64 inc_counter(int key) {
    __u64 *counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value == NULL) {
        return 0;
    }
    (*counter_value)++;
    // bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    return *counter_value;
}

static __always_inline int do_remap(struct pt_regs *ctx, __u64 pte, __u64 flags, __u64 gpa) {
    int *counter_value;
    int key = REMAP_MAP_HEAD;
    int secondary_head;
    u64 pte_flags = pte & ~GET_PAGE_ADDR(pte);
    __u64 spte = (pte_flags == RO_PTE_FLAGS ? RO_EPTE_FLAGS : RW_EPTE_FLAGS) | GET_PAGE_ADDR(pte);
    bpf_override_return(ctx, spte);
    inc_counter(BYPASS_REMAP_SUCCESS);
    
    __u64 *head = bpf_map_lookup_elem(&counter, &key);
    if (head == NULL) {
        return REMAP_FAIL;
    }
    bpf_map_update_elem(&remap_list, head, &gpa, BPF_ANY);
    secondary_head = *head + 2048;
    bpf_map_update_elem(&remap_list, &secondary_head, &spte, BPF_ANY);
    *head = (*head + 1) % 2048;
    bpf_map_update_elem(&counter, &key, head, BPF_ANY);
    return REMAP_SUCCESS;
}

static __always_inline void get_l0_memslot_at_index(__u64 **base_gfn, __u64 **npages, __u64 **userspace, __u32 index) {
    *base_gfn = bpf_map_lookup_elem(&l0_memslots_base_gfns, &index);
    *npages = bpf_map_lookup_elem(&l0_memslots_npages, &index);
    *userspace = bpf_map_lookup_elem(&l0_memslots_userspace_addr, &index);
}

static __always_inline __u64 l1_gpa_to_l0_hva(__u64 gpa) {
    __u64 gfn = gpa >> 12;
    __u64 *spte;
    int current_i, key, *cache_key;
    __u64 *base_gfn;
    __u64 *npages;
    __u64 *userspace;
    __u64 userspace_addr;

    key = MEMSLOT_CACHE_L0;
    cache_key = bpf_map_lookup_elem(&memslot_cache, &key);
    if (cache_key != NULL) 
        get_l0_memslot_at_index(&base_gfn, &npages, &userspace, gfn);
    if (base_gfn != NULL && npages != NULL && userspace != NULL && *base_gfn != 0 && gfn >= *base_gfn && gfn < *base_gfn + *npages) {
        return *userspace + ((gfn - *base_gfn)*PAGE_SIZE);
    }


    for (int i = 0; i < MAX_MEMSLOTS; i++) {
        current_i = i;
        base_gfn = bpf_map_lookup_elem(&l0_memslots_base_gfns, &current_i);
        npages = bpf_map_lookup_elem(&l0_memslots_npages, &current_i);
        userspace = bpf_map_lookup_elem(&l0_memslots_userspace_addr, &current_i);
        if (base_gfn == NULL || npages == NULL || userspace == NULL) {
            continue;
        }
        if (gfn >= *base_gfn && gfn < *base_gfn + *npages && *npages > 0x1000) {
            key = MEMSLOT_CACHE_L0;
            bpf_map_update_elem(&memslot_cache, &key, &current_i, BPF_ANY);
            userspace_addr = *userspace + ((gfn - *base_gfn)*PAGE_SIZE);
            return userspace_addr;
        }
    }
    return 0;
}

/*
* Page walk in L1. Returns the pte if it exists, 0 otherwise.
* 0 Would mean that the page is not mapped, and we can allocate a frame there.
*/
static __always_inline __u64 page_walk_in_l1(__u64 hva, __u64 *ptep) {
    int r, key = QEMU_CR3;
    __u64 pt_index = 0;
    __u64 cr3_l0_va, l3_table, l2_table, l1_table, pte;
    __u64 *cr3_l1_pa = bpf_map_lookup_elem(&counter, &key);
    *ptep = 0;
    if (cr3_l1_pa == NULL || *cr3_l1_pa == 0) {
        // bpf_printk("no cr3!\n");
        return -1;
    }
    // bpf_printk("l1 page walk got hva: %llx\n", hva);
    if (hva == 0) {
        return -1;
    }
    pt_index = ((hva >> 39) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", *cr3_l1_pa, pt_index, *cr3_l1_pa + pt_index);
    cr3_l0_va = l1_gpa_to_l0_hva(*cr3_l1_pa);
    if (cr3_l0_va == 0) {
        // bpf_printk("cr3_l0_va: %llx\n", cr3_l0_va);
        return -1;
    }
    // bpf_printk("cr3_l0_va: %llx\n", cr3_l0_va);
    // bpf_printk("hva: %llx + %llx = %llx\n", cr3_l0_va, pt_index, cr3_l0_va + pt_index);
    r = bpf_probe_read_user(&l3_table, sizeof(l3_table), (void *)(cr3_l0_va + pt_index));
    if (r != 0 || (l3_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l3_table: %llx\n", l3_table);
        return -1;
    }   
    l3_table = GET_PAGE_ADDR(l3_table);
    pt_index = ((hva >> 30) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l3_table, pt_index, l3_table + pt_index);
    l3_table = l1_gpa_to_l0_hva(l3_table);
    if (l3_table == 0) {
        // bpf_printk("l3_table va: %llx\n", l3_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l3_table, pt_index, l3_table + pt_index);
    r = bpf_probe_read_user(&l2_table, sizeof(l2_table), (void *)(l3_table + pt_index));
    if (r != 0 || (l2_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l2_table: %llx\n", l2_table);
        return -1;
    }
    l2_table = GET_PAGE_ADDR(l2_table);
    pt_index = ((hva >> 21) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l2_table, pt_index, l2_table + pt_index);
    l2_table = l1_gpa_to_l0_hva(l2_table);
    if (l2_table == 0) {
        // bpf_printk("l2_table va: %llx\n", l2_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l2_table, pt_index, l2_table + pt_index);
    r = bpf_probe_read_user(&l1_table, sizeof(l1_table), (void *)(l2_table + pt_index));
    if (r != 0 || (l1_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l1_table: %llx\n", l1_table);
        return -1;
    }
    l1_table = GET_PAGE_ADDR(l1_table);
    pt_index = ((hva >> 12) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l1_table, pt_index, l1_table + pt_index);
    l1_table = l1_gpa_to_l0_hva(l1_table);
    if (l1_table == 0) {
        // bpf_printk("l1_table va: %llx\n", l1_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l1_table, pt_index, l1_table + pt_index);
    r = bpf_probe_read_user(&pte, sizeof(pte), (void *)(l1_table + pt_index));
    if (r != 0) {
        // bpf_printk("read user failed! r: %d pte: %llx\n", r, pte);
        return -1;
    }
    if (pte == 0) {
        *ptep = (__u64)(l1_table + pt_index);
        return 0;
    }
 //        bpf_printk("pte: %llx\n", pte);
    return pte;
}

static __always_inline __u64 page_walk_in_l1_huc(__u64 hva, __u64 *ptep) {
    int r, key = QEMU_CR3;
    __u64 pt_index = 0;
    __u64 cr3_l0_va, l3_table, l2_table, l1_table, pte;
    __u64 *cr3_l1_pa = bpf_map_lookup_elem(&counter, &key);
    *ptep = 0;
    if (cr3_l1_pa == NULL || *cr3_l1_pa == 0) {
        // bpf_printk("no cr3!\n");
        return -1;
    }
    // bpf_printk("l1 page walk got hva: %llx\n", hva);
    if (hva == 0) {
        return -1;
    }
    pt_index = ((hva >> 39) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", *cr3_l1_pa, pt_index, *cr3_l1_pa + pt_index);
    // cr3_l0_va = l1_gpa_to_l0_hva(*cr3_l1_pa);
    // if (cr3_l0_va == 0) {
    //     // bpf_printk("cr3_l0_va: %llx\n", cr3_l0_va);
    //     return -1;
    // }
    // bpf_printk("cr3_l0_va: %llx\n", *cr3_l1_pa);
    // bpf_printk("hva: %llx + %llx = %llx\n", *cr3_l1_pa, pt_index, *cr3_l1_pa + pt_index);
    r = bpf_probe_read_hyperupcall(&l3_table, sizeof(l3_table), (void *)(*cr3_l1_pa + pt_index));
    if (r != 0 || (l3_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l3_table: %llx\n", l3_table);
        return -1;
    }   
    l3_table = GET_PAGE_ADDR(l3_table);
    pt_index = ((hva >> 30) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l3_table, pt_index, l3_table + pt_index);
    // l3_table = l1_gpa_to_l0_hva(l3_table);
    if (l3_table == 0) {
        // bpf_printk("l3_table va: %llx\n", l3_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l3_table, pt_index, l3_table + pt_index);
    r = bpf_probe_read_hyperupcall(&l2_table, sizeof(l2_table), (void *)(l3_table + pt_index));
    if (r != 0 || (l2_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l2_table: %llx\n", l2_table);
        return -1;
    }
    l2_table = GET_PAGE_ADDR(l2_table);
    pt_index = ((hva >> 21) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l2_table, pt_index, l2_table + pt_index);
    // l2_table = l1_gpa_to_l0_hva(l2_table);
    if (l2_table == 0) {
        // bpf_printk("l2_table va: %llx\n", l2_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l2_table, pt_index, l2_table + pt_index);
    r = bpf_probe_read_hyperupcall(&l1_table, sizeof(l1_table), (void *)(l2_table + pt_index));
    if (r != 0 || (l1_table & PTE_PRESENT_BIT) == 0) {
        // bpf_printk("l1_table: %llx\n", l1_table);
        return -1;
    }
    l1_table = GET_PAGE_ADDR(l1_table);
    pt_index = ((hva >> 12) & 0x1FF) * 8;
    // bpf_printk("gpa: %llx + %llx = %llx\n", l1_table, pt_index, l1_table + pt_index);
    // l1_table = l1_gpa_to_l0_hva(l1_table);
    if (l1_table == 0) {
        // bpf_printk("l1_table va: %llx\n", l1_table);
        return -1;
    }

    // bpf_printk("hva: %llx + %llx = %llx\n", l1_table, pt_index, l1_table + pt_index);
    r = bpf_probe_read_hyperupcall(&pte, sizeof(pte), (void *)(l1_table + pt_index));
    if (r != 0) {
        // bpf_printk("read user failed! r: %d pte: %llx\n", r, pte);
        return -1;
    }
    if (pte == 0) {
        *ptep = (__u64)(l1_gpa_to_l0_hva(l1_table) + pt_index);
        return 0;
    }
        // bpf_printk("pte: %llx\n", pte);
    return pte;
}


// static __always_inline __u64 lock_mm_lock(__u64 gfn);
// static __always_inline __u64 unlock_mm_lock(__u64 gfn);

// static __always_inline bool lock_pte(__u64 pmd) {
//     int key = PAGES_ARRAY_ADDR; 
//     __u64 l0_va_pages_array, pmd_pfn = GET_PAGE_ADDR(pmd);
//     __u64 *base_pages_array;
//     struct page pmd_page;
//     base_pages_array = bpf_map_lookup_elem(&counter, &key);
//     if (base_pages_array == NULL) {
//         return 0;
//     }
//     l0_va_pages_array = l1_gpa_to_l0_hva(base_pages_array);
//     r = bpf_probe_read_user(&pmd_page, sizeof(pmd_page), ((struct page)l0_va_pages_array) + pmd_pfn);
//     if (r != 0) {
//         return 0;
//     }
//     if (!__cond_lock(pmd_page.lock, pmd_page.lock != 0)) {
//         return 0;
//     }

// }
// static __always_inline __u64 unlock_pte(__u64 gfn);

static __always_inline bool hyperupcall_lock() {
    u32 key;
    u64 *lock_flag1, *lock_flag2, *lock_turn;

    key = LOCK_FLAG1;
    lock_flag1 = bpf_map_lookup_elem(&counter, &key);
    if (lock_flag1 == NULL) {
        return false;
    }
    __sync_val_compare_and_swap(lock_flag1, 0, 1);
    
    key = LOCK_FLAG2;
    lock_flag2 = bpf_map_lookup_elem(&counter, &key);
    if (lock_flag2 == NULL || *lock_flag2 == 1) {
        *lock_flag1 = 0;
        return false;
    }

    // key = LOCK_TURN;
    // lock_turn = bpf_map_lookup_elem(&counter, &key);
    // if (lock_turn == NULL) {
    //     return false;
    // }
    // *lock_flag1 = 1;
    // *lock_turn = 1;
    // if (*lock_flag2 && *lock_turn == 1) {
    //     *lock_flag1 = 0;
    //     return false;
    // }
    return true;
}

static __always_inline void hyperupcall_unlock() {
    u32 key;
    u64 *lock_flag1;

    key = LOCK_FLAG1;
    lock_flag1 = bpf_map_lookup_elem(&counter, &key);
    if (lock_flag1 == NULL) {
        return;
    }
    *lock_flag1 = 0;
}


/* Fill gfn to sp struct, create pte and return it.
 * Current version returns both values
 */
SEC("kprobe")
int bypass_alloc_bpf(struct pt_regs *ctx) {
    bpf_override_return(ctx, 0);
    // return 0;
    int current_i, r;
    int key = 0;
    __u64 flags = 0;
    __u64 *pt;
    __u64 *pfn = 0, *pfn_complement = 0;
    __u64 attemps_counter_value;
    __u64 *counter_value;
    __u64 *sptep;
    __u64 *lock_flag1, *lock_turn;
    __u64 next_counter_value = 0, orig_counter_value = 0, complement_pfn_index = 0, pfn_index = 0, gpa = ctx->di & ~0xFFFULL, spte, guest_pte, ptep, hva;
    __u32 error_code = (__u32)ctx->si;
    // __u32 level = (__u32)ctx->bp;
    // lock_mm_lock(0);
    attemps_counter_value = inc_counter(BYPASS_ALLOC_ATTEMPS);
    key = BYPASS_ALLOC_ENABLE;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value == NULL || *counter_value == 0) {
        r = 0;
        goto out;
    }

    if (!hyperupcall_lock()) {
        inc_counter(BYPASS_ALLOC_FAILED_HYPERUPCALL_BUSY);
        r = 0;
        goto out;
    }

    hva = get_l1_user_addr(gpa >> 12, &flags);
    if (hva == 0) {
        inc_counter(BYPASS_ALLOC_FAILED_NO_MEMSLOT);
        r = 0;
        goto out;
    }
        // bpf_printk("gpa: %llx hva: %llx\n", gpa, hva);


    if (attemps_counter_value < N_BLANKS) {
        inc_counter(BYPASS_ALLOC_FAILED_REACHED_MAX_ALLOCS);
        r = 0;
        goto out;
    }
    // else if (*attemps_counter_value == N_BLANKS) {
    //     key = BYPASS_ALLOC_ENABLE;
    //     counter_value = bpf_map_lookup_elem(&counter, &key);
    //     if (counter_value != NULL) {
    //         (*counter_value) = 1;
    //         bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    //     }
    // }

    guest_pte = page_walk_in_l1_huc(hva, &ptep);
    // bpf_printk("gpa: %llx got guest pte: %llx ptep: %p\n", gpa, guest_pte, ptep);
    if ((guest_pte & 0x01) && guest_pte != -1) {
        do_remap(ctx, guest_pte, flags, gpa);
        r = 0;
        goto out;
    }
    // else {
    // if (guest_pte != 0 || (error_code & 0x2) == 0 || is_in_no_map_list(gpa >> 12)) { //is not write error?
    // if (is_in_no_map_list(gpa >> 12)) { //is not write error?
    //     inc_counter(BYPASS_ALLOC_FAILED_CANT_REMAP);
    //     // bpf_printk("guest_pte != 0: %llx\n", guest_pte);
    //     r = 0;
    //     goto out;
    // }
    if (guest_pte != 0) {
        inc_counter(BYPASS_ALLOC_FAILED_CANT_REMAP_GUEST_FLAGS);
        r = 0;
        goto out;
    }
    if ((error_code & 0x2) == 0) {
        inc_counter(BYPASS_ALLOC_FAILED_CANT_REMAP_FAULT_READ);
        r = 0;
        goto out;
    }
    if (is_in_no_map_list(gpa >> 12)) {
        inc_counter(BYPASS_ALLOC_FAILED_CANT_REMAP_NO_MAP_LIST);
        r = 0;
        goto out;
    }

    key = BYPASS_ALLOC_SUCCESS;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value != NULL && *counter_value >= MAX_ALLOCS) {
        r = 0;
        goto out;
    }

    key = BYPASS_ALLOCS_INDEX ;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    // bpf_printk("gpa: %llx\n", gpa);
    if (counter_value == NULL) {
        bpf_printk("failed to get counter value\n");
        r = 0;
        goto out;
    }
    orig_counter_value = *counter_value;
    next_counter_value = (*counter_value + 1) % (PFN_CACHE_SIZE);
    pfn_index = 2*orig_counter_value;
    complement_pfn_index = (2*orig_counter_value) + 1;
    pfn = bpf_map_lookup_elem(&pfn_cache, &pfn_index);
    pfn_complement = bpf_map_lookup_elem(&pfn_cache, &complement_pfn_index);
    // bpf_printk("counter value: %llu pt: %p\n", orig_counter_value, pt);
    if (pfn == NULL || *pfn == 0 || pfn_complement == NULL || *pfn_complement == 0) {
        inc_counter(BYPASS_ALLOC_FAILED_CACHE_EMPTY);
        r = 0;
        goto out;
    }
    if (*pfn != *pfn_complement) {
        inc_counter(BYPASS_ALLOC_FAILED_CACHE_DIRTY_FULL);
        r = 0;
        goto out;
    }
    // bpf_printk("counter: %llu, pfn: %llx\n", next_counter_value, *pfn);
    key = BYPASS_ALLOC_SUCCESS;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value != NULL) {
        (*counter_value)++;
        // bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    }
    
    spte = create_epte(*pfn);
    // bpf_printk("spte: %llx, gpa: %llx\n", spte, gpa);
    guest_pte = create_pte(*pfn);
    // if (ptep != 0 && flags == 0) bpf_probe_write_user((void*)ptep, &guest_pte, sizeof(guest_pte));
    bpf_override_return(ctx, spte);
    key = BYPASS_ALLOCS_INDEX;
    bpf_map_update_elem(&counter, &key, &next_counter_value, BPF_ANY);
        // bpf_printk("gpa: %llx, pfn: %llx, spte: %llx pte: %llx, ptep: %llx\n", gpa, *pfn, spte, guest_pte, ptep);
    bpf_map_update_elem(&pfn_cache, &pfn_index, &gpa, BPF_ANY);
    r = 0;

out:
    hyperupcall_unlock();
    return r;
}

SEC("kprobe")   
int update_mapping(struct pt_regs *ctx) {
    // __u64 gfn = ctx->di >> 12, epte = ctx->si, prev_epte = 0;
    // unsigned int i = 0, gpa_key = 0, key = 0;
    // bool updated_mapping = false;
    // if (get_l1_user_addr(gfn) == 0) {
    //     return 0;
    // }

    // // Check if GPA exists in each mapping table
    // for (i = 0; i < REMAP_HISTORY_LEN; i++) {
    //     gpa_key = (i * MAPPING_TABLE_SIZE) + gfn;
    //     __u64 *existing_epte = bpf_map_lookup_elem(&history_mapping_table, &gpa_key);
        // if (existing_epte == NULL) bpf_printk("i: %d gpa: %llx, existing_epte: %llx, epte: %llx, prev_epte: %llx\n", i, gpa_key, existing_epte, epte, prev_epte);
        // if (existing_epte != NULL) bpf_printk("i: %d gpa: %llx, *existing_epte: %llx, epte: %llx, prev_epte: %llx\n", i, gpa_key, *existing_epte, epte, prev_epte);
    //     if ((existing_epte == NULL || *existing_epte == 0ULL) && (prev_epte == 0 || prev_epte != epte)) {
    //         bpf_map_update_elem(&history_mapping_table, &gpa_key, &epte, BPF_ANY);
    //         updated_mapping = true;
    //         break;
    //     }
    //     else if ((existing_epte == NULL || *existing_epte == 0ULL) && (prev_epte == epte)) {
    //         break;
    //     }
    //     if (existing_epte != NULL) prev_epte = *existing_epte;
    // }
    // bpf_map_update_elem(&mapping_table, &gpa_key, &epte, BPF_ANY);

    // key = REMAP_UPDATE_SUCCESS0 + i;
    // __u64 *counter_value = bpf_map_lookup_elem(&counter, &key);
    // if (updated_mapping && counter_value != NULL) {
        // bpf_printk("updating counter %d, updated_mapping: %d gpa: %llx\n",key, updated_mapping, gpa_key);
    //     (*counter_value)++;
    //     bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    // }
    return 0;
}

char _license[] SEC("license") = "GPL";
