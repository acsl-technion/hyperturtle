#include "../vmlinux.h"
// #include <linux/types.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>       /* for getting kprobe arguments */
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// #include <sys/socket.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <arpa/inet.h>
// Returns the protocol byte for an IP packet, 0 for anything else
static __always_inline __u64 lookup_protocol(struct xdp_md *ctx)
{
    __u64 protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP        
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

static __always_inline __u64 lookup_port(struct xdp_md *ctx)
{
    __u64 ret = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end && iph->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
                ret = bpf_htons(tcph->dest);
        }
    }

    return ret;
}