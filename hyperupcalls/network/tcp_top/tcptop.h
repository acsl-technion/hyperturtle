/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPTOP_H
#define __TCPTOP_H

#define TASK_COMM_LEN 16
#define IPV6_LEN 16

#include "../../../vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */


struct ip_key_t {
	__u32 saddr;
	__u32 daddr;
	// __u64 mntnsid;
	__u16 lport;
	__u16 dport;
	__u16 family;
} typedef ip_key_t;

struct traffic_t {
	size_t sent;
	size_t received;
	u32 index;
} typedef traffic_t;

#endif /* __TCPTOP_H */
