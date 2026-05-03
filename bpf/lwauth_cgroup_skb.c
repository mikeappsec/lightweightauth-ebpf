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
// Supports both IPv4 and IPv6 egress deny rules.
//
// Kernel requirements: >= 5.10, CO-RE (BTF enabled).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// LPM trie key for IPv4 CIDR matching (O(32) per lookup).
struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

// LPM trie key for IPv6 CIDR matching (O(128) per lookup).
struct lpm_key_v6 {
    __u32 prefixlen;
    __u32 addr[4];
};

// IPv4 deny CIDRs — LPM trie for efficient prefix matching.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
} deny_cidrs SEC(".maps");

// IPv6 deny CIDRs — LPM trie for efficient prefix matching.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
} deny_cidrs6 SEC(".maps");

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

SEC("cgroup_skb/egress")
int lwauth_cgroup_egress(struct __sk_buff *skb) {
    bump_cgroup_stat(CGROUP_STAT_TOTAL);

    if (skb->protocol == bpf_htons(0x0800)) {
        // IPv4: extract destination IP and check LPM trie.
        __u32 dst_ip = 0;
        bpf_skb_load_bytes(skb, 16, &dst_ip, 4);

        struct lpm_key_v4 key = {
            .prefixlen = 32,
            .addr = dst_ip,
        };
        if (bpf_map_lookup_elem(&deny_cidrs, &key)) {
            bump_cgroup_stat(CGROUP_STAT_DENIED);
            return 0; // drop
        }

        bump_cgroup_stat(CGROUP_STAT_ALLOWED);
        return 1;
    }

    if (skb->protocol == bpf_htons(0x86DD)) {
        // IPv6: extract destination (offset 24, 16 bytes) and check LPM trie.
        struct lpm_key_v6 key = { .prefixlen = 128 };
        bpf_skb_load_bytes(skb, 24, &key.addr, 16);

        if (bpf_map_lookup_elem(&deny_cidrs6, &key)) {
            bump_cgroup_stat(CGROUP_STAT_DENIED);
            return 0; // drop
        }

        bump_cgroup_stat(CGROUP_STAT_ALLOWED);
        return 1;
    }

    // Allow non-IP protocols (ARP, etc.)
    bump_cgroup_stat(CGROUP_STAT_ALLOWED);
    return 1;
}

char _license[] SEC("license") = "Apache-2.0";
