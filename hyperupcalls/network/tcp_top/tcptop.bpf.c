// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
// #include "../../../vmlinux.h"
#include "../../packet.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcptop.h"
// #include <gadget/mntns_filter.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET 2 /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/
#define IP_MAP_SIZE 128

const volatile pid_t target_pid = 0;
const volatile int target_family = -1;

struct tcptop_elem_t {
	ip_key_t key;
	traffic_t value;
} typedef tcptop_elem_t;

enum {
	PACKETS_PROCESSED = 0,
	OUTGOING,
	INCOMING,
	IP_MAP_FULL,
	NOT_IPV4,
	NOT_ETH,
	PARSING_FAILED,
	NEW_ENTRY,
	UPDATED_ENTRY,
	NEXT_SLOT,
	N_COUNTERS
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IP_MAP_SIZE);
	__type(key, u32);
	__type(value, tcptop_elem_t);
} ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IP_MAP_SIZE);
	__type(key, ip_key_t);
	__type(value, traffic_t);
} internal_ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, N_COUNTERS);
	__type(key, u32);
	__type(value, u32);
} counter SEC(".maps");


// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, struct ip_key_t);
// 	__type(value, struct traffic_t);
// } ip_map SEC(".maps");


static __always_inline u32 inc_counter(u32 key) {
    u32 *counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value == NULL) {
        return 0;
    }
    (*counter_value)++;
    // bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    return *counter_value;
}


/*
 * ip_map_lookup - find the first available slot in the ip_map and return it
 */
static __always_inline u32 get_next_available_slot()
{
	u32 key = NEXT_SLOT, next_slot_val;
	u32 *next_slot = bpf_map_lookup_elem(&counter, &key);
	if (next_slot == NULL) {
		return -1;
	}
	next_slot_val = *next_slot;
	(*next_slot)++;
	bpf_map_update_elem(&counter, &key, next_slot, BPF_ANY);
	return next_slot_val;
}

static __always_inline u16 get_family(void* data, void* data_end) {
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	// Check that it's an IP packet
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
		return AF_INET;
	return 0;

}

static __always_inline int get_ip_and_ports(void* data, void* data_end, u16 family, u32 *saddr, u32 *daddr, u16 *lport, u16 *dport, bool outgoing) {
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct iphdr *iph;
	
	if (family == AF_INET) {
		iph = data + sizeof(struct ethhdr);
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return -1;
		*saddr = iph->saddr;
		*daddr = iph->daddr;
		if (iph->protocol == IPPROTO_TCP) {
			tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
				return -1;
			*lport = bpf_ntohs(tcp->source);
			*dport = bpf_ntohs(tcp->dest);
		} else if (iph->protocol == IPPROTO_UDP) {
			udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
				return -1;
			*lport = bpf_ntohs(udp->source);
			*dport = bpf_ntohs(udp->dest);
		}
	}
	if (!outgoing) {
		u32 tmp = *saddr;
		*saddr = *daddr;
		*daddr = tmp;
		u16 tmp2 = *lport;
		*lport = *dport;
		*dport = tmp2;
	}
	return 0;
}

static int probe_ip(void *data, void *data_end, bool outgoing)
{
	ip_key_t ip_key = {0};
	traffic_t *trafficp;
	tcptop_elem_t tcptop_elem = {0};
	// void *data = (void *)(long)ctx->data;
    // void *data_end = (void *)(long)ctx->data_end;
	u64 mntns_id = 0;
	u16 family;
	bool found_entry = false;
	u32 pid = 0; // doesn't do anything here
	u32 size = data_end - data;
	u32 ipmap_index;

	family = get_family(data, data_end);
	if (family != AF_INET) {
		inc_counter(NOT_ETH);
		return 0;
	}

	// mntns_id = gadget_get_mntns_id();

	// if (gadget_should_discard_mntns_id(mntns_id))
	// 	return 0;

	// ip_key.pid = pid;
	// bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
	if (get_ip_and_ports(data, data_end, family, &ip_key.saddr, &ip_key.daddr, &ip_key.lport, &ip_key.dport, outgoing) < 0) {
		inc_counter(PARSING_FAILED);
		return 0;
	}
	ip_key.family = family;
	// ip_key.mntnsid = mntns_id;

	trafficp = bpf_map_lookup_elem(&internal_ip_map, &ip_key);
	if (trafficp != NULL) {
		tcptop_elem.key = ip_key;
		
		if (!outgoing)
			trafficp->received += size;
		else
			trafficp->sent += size;

		tcptop_elem.value = *trafficp;
		ipmap_index = trafficp->index;
		bpf_map_update_elem(&internal_ip_map, &ip_key, trafficp, BPF_ANY);
		bpf_map_update_elem(&ip_map, &ipmap_index, &tcptop_elem, BPF_ANY);
		inc_counter(UPDATED_ENTRY);	
	} else if ((ipmap_index = get_next_available_slot()) >= 0 && ipmap_index < IP_MAP_SIZE) {
		traffic_t zero = {.sent = 0, .received = 0, .index = ipmap_index};
		if (!outgoing) {
			zero.sent = 0;
			zero.received = size;
		} else {
			zero.sent = size;
			zero.received = 0;
		}
		tcptop_elem.key = ip_key;
		// memcpy(&tcptop_elem.key, &ip_key, sizeof(ip_key_t));
		// tcptop_elem.value = zero;
		tcptop_elem.value = (traffic_t){.index = ipmap_index, .sent = 0, .received = (u32)size};
		bpf_map_update_elem(&internal_ip_map, &ip_key, &zero, BPF_ANY);
		bpf_map_update_elem(&ip_map, &ipmap_index, &tcptop_elem, BPF_ANY);
		inc_counter(NEW_ENTRY);
	}
	else {
		inc_counter(IP_MAP_FULL);
		return 0;
	}
	inc_counter(PACKETS_PROCESSED);
	return 0;
}

SEC("tc")
int tcptop_int(struct __sk_buff *ctx) {
	probe_ip((void*)(long)ctx->data, (void*)(long)ctx->data_end, false);
	inc_counter(INCOMING);
	return 0;
}


SEC("xdp")
int tcptop_br(struct xdp_md *ctx) {
	probe_ip((void*)(long)ctx->data, (void*)(long)ctx->data_end, true);
	inc_counter(OUTGOING);
	return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
