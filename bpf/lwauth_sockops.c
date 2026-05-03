// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 LightweightAuth Contributors
//
// lwauth_sockops.c — eBPF sockops program that intercepts TCP
// connection establishment and redirects selected connections to the
// lwauth userspace agent for an allow/deny decision.
//
// This program attaches to cgroup/sockops and captures:
//   - BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  (client-initiated connect)
//   - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB (server-side accept)
//
// On match, it stores the socket in a sockhash map so the sk_msg
// program can intercept and redirect data to the lwauth Unix socket.
//
// Kernel requirements: >= 5.10, CO-RE (BTF enabled).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum number of tracked sockets.
#define MAX_SOCKETS 65536

// Port range to intercept (configurable via userspace map update).
struct port_range {
    __u16 lo;
    __u16 hi;
};

// Key for the sockhash map — 4-tuple.
struct sock_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  family; // AF_INET=2, AF_INET6=10
    __u8  pad[3];
};

// Sockhash map: stores sockets for sk_msg redirection.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_hash SEC(".maps");

// Config map: userspace writes intercepted port ranges here.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct port_range);
} intercept_ports SEC(".maps");

// Stats map: counters for observability.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum stat_key {
    STAT_INTERCEPTED = 0,
    STAT_ALLOWED     = 1,
    STAT_DENIED      = 2,
    STAT_ERRORS      = 3,
};

static __always_inline void bump_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Check if a port is in the intercepted range.
static __always_inline int should_intercept(__u16 port) {
    for (__u32 i = 0; i < 64; i++) {
        struct port_range *range = bpf_map_lookup_elem(&intercept_ports, &i);
        if (!range || (range->lo == 0 && range->hi == 0))
            break;
        if (port >= range->lo && port <= range->hi)
            return 1;
    }
    return 0;
}

static __always_inline void extract_key(struct bpf_sock_ops *skops, struct sock_key *key) {
    key->family = skops->family;
    if (skops->family == 2) { // AF_INET
        key->saddr = skops->local_ip4;
        key->daddr = skops->remote_ip4;
    }
    key->sport = skops->local_port;
    key->dport = bpf_ntohl(skops->remote_port) >> 16;
}

SEC("sockops")
int lwauth_sockops(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;

    // Only process established connections.
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;

    // Check if destination port should be intercepted.
    __u16 dport = bpf_ntohl(skops->remote_port) >> 16;
    if (!should_intercept(dport))
        return 0;

    // Build socket key and insert into sockhash.
    struct sock_key key = {};
    extract_key(skops, &key);

    int ret = bpf_sock_hash_update(skops, &sock_hash, &key, BPF_ANY);
    if (ret == 0) {
        bump_stat(STAT_INTERCEPTED);
    } else {
        bump_stat(STAT_ERRORS);
    }

    return 0;
}

char _license[] SEC("license") = "Apache-2.0";
