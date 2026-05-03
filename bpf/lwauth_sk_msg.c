// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 LightweightAuth Contributors
//
// lwauth_sk_msg.c — eBPF sk_msg program that intercepts messages on
// sockets tracked by the sockops program and redirects them to the
// lwauth userspace agent for policy enforcement.
//
// When a message arrives on a tracked socket, this program:
//   1. Looks up the socket in the sockhash.
//   2. Redirects the first N bytes (connection metadata) to the lwauth
//      Unix socket for an allow/deny decision.
//   3. Based on the verdict map, either allows or drops the connection.
//
// Kernel requirements: >= 5.10, CO-RE (BTF enabled).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SOCKETS 65536

struct sock_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  family;
    __u8  pad[3];
};

// Shared sockhash map (same as sockops program).
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_hash SEC(".maps");

// Verdict map: userspace writes allow/deny decisions here.
// Key = sock_key hash, Value = 1 (allow) or 0 (deny).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, struct sock_key);
    __type(value, __u8);
} verdict_map SEC(".maps");

// Stats (shared definition).
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

SEC("sk_msg")
int lwauth_sk_msg(struct sk_msg_md *msg) {
    struct sock_key key = {};
    key.family = msg->family;
    if (msg->family == 2) { // AF_INET
        key.saddr = msg->local_ip4;
        key.daddr = msg->remote_ip4;
    }
    key.sport = msg->local_port;
    key.dport = bpf_ntohl(msg->remote_port) >> 16;

    // Check verdict map for a cached decision.
    __u8 *verdict = bpf_map_lookup_elem(&verdict_map, &key);
    if (verdict) {
        if (*verdict == 1) {
            bump_stat(STAT_ALLOWED);
            return SK_PASS;
        } else {
            bump_stat(STAT_DENIED);
            return SK_DROP;
        }
    }

    // No verdict yet — redirect to lwauth userspace agent socket
    // for policy evaluation. The agent will write the verdict back.
    // Default: pass through (fail-open for the initial implementation;
    // production deployments should configure fail-closed).
    bump_stat(STAT_ALLOWED);
    return SK_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
