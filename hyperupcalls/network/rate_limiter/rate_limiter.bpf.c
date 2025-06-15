
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define VAL_PERIOD_NS 1000000000UL // 1 second
#define VAL_MAX_COUNT 1000000000000UL //

typedef struct RateLimiter_ {
    __u64 cur_count;
    __u64 last_timestamp;
    __u64 period_ns;
    __u64 max_count;
} RateLimiter;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, RateLimiter);
    __uint(max_entries, 1);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} packets SEC(".maps");


SEC("xdp")
int rate_limiter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 timestamp;
    __u64 delta;
    RateLimiter *value;
    int ret = XDP_DROP;

    value = bpf_map_lookup_elem(&packets, &key);
    if (!value) {
        return XDP_PASS;
    }

    timestamp = bpf_ktime_get_ns();
    if (timestamp - value->last_timestamp >= VAL_MAX_COUNT / VAL_PERIOD_NS) {
        delta = ((timestamp - value->last_timestamp) * VAL_MAX_COUNT) / VAL_PERIOD_NS;
        value->cur_count = value->cur_count > delta ? value->cur_count - delta : 0;
        value->last_timestamp = timestamp;
    }

    if (value->cur_count < VAL_MAX_COUNT) {
        ret = XDP_PASS;
        value->cur_count += ctx->data_end - ctx->data;
    }

    bpf_map_update_elem(&packets, &key, value, BPF_ANY);
    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
