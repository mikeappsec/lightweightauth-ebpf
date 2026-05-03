# lightweightauth-ebpf

Mode-C eBPF data plane for [lightweightauth](https://github.com/mikeappsec/lightweightauth).
A privileged DaemonSet that attaches eBPF programs (`sockops` / `sk_msg` /
`cgroup_skb`) and redirects selected connections to a local `lightweightauth`
Unix socket for an allow/deny decision.

> Status: **experimental** (F9). Requires Linux ≥ 5.10, BTF-enabled kernel,
> CAP_BPF + CAP_SYS_ADMIN.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Node (DaemonSet pod)                                   │
│                                                         │
│  ┌────────────┐   sockops/sk_msg    ┌───────────────┐  │
│  │ Kernel BPF │ ◄─────────────────► │ lwauth-ebpf   │  │
│  │ programs   │   verdict map       │ (userspace)    │  │
│  └────────────┘                     └──────┬────────┘  │
│                                            │ UDS        │
│                                     ┌──────▼────────┐  │
│                                     │ lwauth        │  │
│                                     │ (control)     │  │
│                                     └───────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Build

```bash
# Compile eBPF objects + Go binary
make all

# Container image
make image
```

Requires: `clang`, `llvm`, `bpftool` (for vmlinux.h generation), Go 1.26+.

## Configuration

See [deploy/daemonset.yaml](deploy/daemonset.yaml) for the ConfigMap example.

```yaml
bpfDir: /opt/lwauth-ebpf/bpf
cgroupPath: /sys/fs/cgroup
lwauthSocket: /run/lwauth/lwauth.sock
failMode: open          # "open" or "closed"
interceptPorts:
  - lo: 80
    hi: 80
  - lo: 443
    hi: 443
denyCidrs:
  - "10.99.0.0/16"
```

## Deploy

```bash
kubectl apply -f deploy/daemonset.yaml
```

## Layout

```
lightweightauth-ebpf/
├── bpf/                     # CO-RE eBPF C sources
│   ├── vmlinux.h            # Minimal BTF stubs
│   ├── lwauth_sockops.c     # Connection interception
│   ├── lwauth_sk_msg.c      # Per-message verdict enforcement
│   └── lwauth_cgroup_skb.c  # Egress CIDR deny
├── cmd/lwauth-ebpf/         # Userspace agent
│   ├── main.go
│   ├── config.go
│   └── config_test.go
├── internal/
│   ├── loader/              # eBPF program load + attach
│   └── bridge/              # UDS bridge to lwauth
├── deploy/                  # Kubernetes DaemonSet manifests
├── Dockerfile
├── Makefile
└── go.mod
```

## License

Apache-2.0.
