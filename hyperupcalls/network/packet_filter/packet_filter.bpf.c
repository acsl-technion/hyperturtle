// #include "../../vmlinux_guest.h"
#include "../packet.h"
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define MAP_SIZE 1024
#define HASH_SEED 0xdeadbeef

/**
 * This progra
*/

typedef struct rule_t {
    __u32 ip;
    __u16 port;
    __u8 protocol;
    __u8 action;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAP_SIZE);
    __type(key, __u32);
    __type(value, rule);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} rules SEC(".maps");


static __always_inline struct rule_t parse_packet(struct xdp_md *ctx)
{
    __u64 ret = 0;
    struct rule_t zero_rule = {0};
    __u32 ip_addr = 0;
    __u16 port = 0;
    __u8 protocol = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return zero_rule;
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        ip_addr = ip->saddr;
    }
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if (tcp + 1 > data_end)
            return zero_rule;
        port = tcp->dest;
        protocol = IPPROTO_TCP;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if (udp + 1 > data_end)
            return zero_rule;
        port = udp->dest;
        protocol = IPPROTO_UDP;
    } else {
        return zero_rule;
    }

    return (struct rule_t){.ip = ip_addr, .port = port, .protocol = protocol};
}

// static __always_inline hash_val *lookup_hash_array(struct xdp_md *ctx, __u64 key) {
//     for (int i = 0; i < MAP_SIZE / sizeof(hash_val); i++) {
//         __u32 hash = jhash_1word(key, HASH_SEED);
//         __u32 index = hash % MAP_SIZE;
//         hash_val *val = bpf_map_lookup_elem(&packets_to_filter, &index);
//         if (val == NULL || val->key == 0)
//             return NULL;
//         if (val->key == key)
//             return val;
//         key = index;
//     }
// }

SEC("xdp")
int packet_filter(struct xdp_md *ctx) {
    __u64 port = 0;
    __u32 key = 0;
    __u64 *p;

    struct rule_t packet_metadata = parse_packet(ctx);

    for (int i = 0; i < MAP_SIZE / sizeof(rule); i++) {
        struct rule_t *r = bpf_map_lookup_elem(&rules, &i);
        if (r == NULL || r->port == 0)
            break;
        if (r->ip == packet_metadata.ip && r->port == packet_metadata.port && r->protocol == packet_metadata.protocol)
            return r->action;
    }
    return XDP_DROP;
}