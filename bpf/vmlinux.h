/* Minimal vmlinux.h stub for CO-RE compilation.
 *
 * In production builds, generate this from the target kernel's BTF:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * This stub provides only the types needed by lwauth eBPF programs
 * so the code can be parsed/reviewed without a full vmlinux.h.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

/* bpf_sock_ops — passed to sockops programs. */
struct bpf_sock_ops {
    __u32 op;
    __u32 family;
    __u32 local_ip4;
    __u32 remote_ip4;
    __u32 local_port;
    __u32 remote_port;
};

/* sk_msg_md — passed to sk_msg programs. */
struct sk_msg_md {
    __u32 family;
    __u32 local_ip4;
    __u32 remote_ip4;
    __u32 local_port;
    __u32 remote_port;
    __u32 size;
};

/* __sk_buff — passed to cgroup_skb programs. */
struct __sk_buff {
    __u32 len;
    __u32 protocol;
    __u32 local_ip4;
    __u32 remote_ip4;
};

/* sockops callback operations. */
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  4
#define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5

/* sk_msg verdicts. */
#define SK_PASS 1
#define SK_DROP 0

/* Map flags. */
#define BPF_ANY 0

#endif /* __VMLINUX_H__ */
