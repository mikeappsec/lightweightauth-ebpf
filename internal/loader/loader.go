// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package loader handles loading, attaching, and managing eBPF programs
// for the lwauth data plane. It abstracts the cilium/ebpf library and
// provides a clean interface for the agent.
package loader

import (
	"fmt"
	"net/http"
	"sync"
)

// Options configures eBPF program loading and attachment.
type Options struct {
	// CgroupPath is the cgroup v2 path for attaching cgroup programs.
	CgroupPath string

	// InterceptPorts are port ranges for sockops interception.
	InterceptPorts []PortRange

	// DenyCIDRs are CIDR blocks to deny on egress.
	DenyCIDRs []string
}

// PortRange is an inclusive port range.
type PortRange struct {
	Lo uint16
	Hi uint16
}

// Programs holds loaded eBPF programs and their maps.
type Programs struct {
	mu         sync.Mutex
	closed     bool
	verdictMap *Map
	statsMap   *Map
}

// Map is a handle to a BPF map (abstraction over cilium/ebpf.Map).
type Map struct {
	Name string
	FD   int
}

// Load compiles (if needed) and loads eBPF programs from bpfDir.
// It attaches sockops to the cgroup, links sk_msg to the sockhash,
// and attaches cgroup_skb/egress.
//
// This is the main entry point. On success, the caller must defer Close().
func Load(bpfDir string, opts *Options) (*Programs, error) {
	if bpfDir == "" {
		return nil, fmt.Errorf("loader: bpfDir is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("loader: options are required")
	}
	if opts.CgroupPath == "" {
		return nil, fmt.Errorf("loader: cgroupPath is required")
	}

	// In a real implementation, this would:
	// 1. Open pre-compiled .o files from bpfDir
	// 2. Load programs via cilium/ebpf
	// 3. Attach sockops to cgroup
	// 4. Link sk_msg to sockhash
	// 5. Attach cgroup_skb/egress
	// 6. Populate intercept_ports map
	// 7. Populate deny_cidrs map
	//
	// For now, we return a Programs struct that represents the loaded state.
	// The actual cilium/ebpf integration requires a Linux kernel with BTF.

	progs := &Programs{
		verdictMap: &Map{Name: "verdict_map", FD: -1},
		statsMap:   &Map{Name: "stats", FD: -1},
	}

	return progs, nil
}

// VerdictMap returns the BPF verdict map for the bridge to write decisions.
func (p *Programs) VerdictMap() *Map {
	return p.verdictMap
}

// Close detaches all eBPF programs and closes map file descriptors.
func (p *Programs) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	// In production: detach programs, close FDs.
	return nil
}

// MetricsHandler returns an HTTP handler that exports BPF stats as
// Prometheus metrics.
func (p *Programs) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()

		// In production, read per-CPU array map and sum values.
		// For now, emit placeholder metrics.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintln(w, "# HELP lwauth_ebpf_connections_intercepted_total Total connections intercepted by sockops.")
		fmt.Fprintln(w, "# TYPE lwauth_ebpf_connections_intercepted_total counter")
		fmt.Fprintln(w, "lwauth_ebpf_connections_intercepted_total 0")
		fmt.Fprintln(w, "# HELP lwauth_ebpf_connections_allowed_total Total connections allowed.")
		fmt.Fprintln(w, "# TYPE lwauth_ebpf_connections_allowed_total counter")
		fmt.Fprintln(w, "lwauth_ebpf_connections_allowed_total 0")
		fmt.Fprintln(w, "# HELP lwauth_ebpf_connections_denied_total Total connections denied.")
		fmt.Fprintln(w, "# TYPE lwauth_ebpf_connections_denied_total counter")
		fmt.Fprintln(w, "lwauth_ebpf_connections_denied_total 0")
		fmt.Fprintln(w, "# HELP lwauth_ebpf_errors_total Total eBPF errors.")
		fmt.Fprintln(w, "# TYPE lwauth_ebpf_errors_total counter")
		fmt.Fprintln(w, "lwauth_ebpf_errors_total 0")
	}
}
