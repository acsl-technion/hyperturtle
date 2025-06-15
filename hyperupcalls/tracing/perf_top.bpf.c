#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */


struct key_t {
    u32 pid;
    u64 kernel_ip;
    int user_stack_id;
    int kernel_stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, u64);
    __uint(max_entries, 10240);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} rbp_traces SEC(".maps");


#define bpf_increment_elem(MAP, KEY) ({ \
    u64 *val = bpf_map_lookup_elem(&MAP, KEY); \
    if (val) { \
        (*val)++; \
    } else { \
        u64 zero = 0; \
        bpf_map_update_elem(&MAP, KEY, &zero, BPF_ANY); \
    } \
})

__always_inline static int rbp_trace(struct pt_regs *ctx) {
    u64 vcpu_regs[NR_VCPU_REGS] = {0};
    int r = bpf_probe_kvm_vcpu(vcpu_regs, sizeof(u64) * NR_VCPU_REGS);
    if (r < 0)
        return 0;
    u64 rip = vcpu_regs[VCPU_REGS_RIP];
    bpf_printk("rbp_trace: %llx\n", rip);
    bpf_increment_elem(rbp_traces, &rip);
    return 0;
}


SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    struct key_t key = {.pid = 0};
    rbp_trace(&ctx->regs);

    if (key.kernel_stack_id >= 0) {
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        page_offset = 0;
#endif
    }
    return 0;
}

char _license[] SEC("license") = "GPL";