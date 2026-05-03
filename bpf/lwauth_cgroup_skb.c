// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 LightweightAuth Contributors
//
// lwauth_cgroup_skb.c — eBPF cgroup/skb program for egress filtering.
//
// This program attaches to cgroup/skb/egress and enforces IP-level
// network policies before traffic leaves the pod. It's a defence-in-depth
// layer that blocks traffic even if application-level policy is bypassed.
//
// Use case: deny egress to known-bad CIDR ranges, enforce tenant
// isolation at the network level in multi-tenant clusters.
//
// Kernel requirements: >= 5.10, CO-RE (BTF enabled).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Deny list: CIDRs that should be blocked on egress.
// Key = network prefix (masked IP), Value = prefix length.
struct cidr_entry {
    __u32 network;   // network address (host byte order)
    __u8  prefix_len;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);        // index
    __type(value, struct cidr_entry);
} deny_cidrs SEC(".maps");

// Stats.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} cgroup_stats SEC(".maps");

enum cgroup_stat_key {
    CGROUP_STAT_TOTAL   = 0,
    CGROUP_STAT_ALLOWED = 1,
    CGROUP_STAT_DENIED  = 2,
};

static __always_inline void bump_cgroup_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&cgroup_stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int match_cidr(__u32 addr, struct cidr_entry *cidr) {
    __u32 mask = 0xFFFFFFFF;
    if (cidr->prefix_len < 32)
        mask <<= (32 - cidr->prefix_len);
    return (addr & mask) == (cidr->network & mask);
}

SEC("cgroup_skb/egress")
int lwauth_cgroup_egress(struct __sk_buff *skb) {
    bump_cgroup_stat(CGROUP_STAT_TOTAL);

    // Only process IPv4 for now.
    if (skb->protocol != bpf_htons(0x0800)) {
        bump_cgroup_stat(CGROUP_STAT_ALLOWED);
        return 1; // allow non-IPv4
    }

    // Extract destination IP from the IP header.
    __u32 dst_ip = 0;
    bpf_skb_load_bytes(skb, 16, &dst_ip, 4); // offset 16 = dst IP in IPv4 header

    // Check against deny list.
    for (__u32 i = 0; i < 4096; i++) {
        struct cidr_entry *entry = bpf_map_lookup_elem(&deny_cidrs, &i);
        if (!entry || entry->prefix_len == 0)
            break;
        if (match_cidr(bpf_ntohl(dst_ip), entry)) {
            bump_cgroup_stat(CGROUP_STAT_DENIED);
            return 0; // drop
        }
    }

    bump_cgroup_stat(CGROUP_STAT_ALLOWED);
    return 1; // allow
}

char _license[] SEC("license") = "Apache-2.0";
