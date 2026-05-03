// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the lwauth-ebpf agent configuration.
type Config struct {
	// BPFDir is the directory containing compiled eBPF object files.
	BPFDir string `yaml:"bpfDir"`

	// CgroupPath is the cgroup v2 mount path for attaching cgroup programs.
	CgroupPath string `yaml:"cgroupPath"`

	// LWAuthSocket is the Unix domain socket path to the lwauth control plane.
	LWAuthSocket string `yaml:"lwauthSocket"`

	// InterceptPorts defines port ranges to intercept via sockops/sk_msg.
	InterceptPorts []PortRange `yaml:"interceptPorts"`

	// DenyCIDRs defines CIDR ranges to block on egress via cgroup_skb.
	DenyCIDRs []string `yaml:"denyCidrs"`

	// FailMode controls behavior when lwauth is unreachable.
	// "open" = allow traffic (default), "closed" = deny traffic.
	FailMode string `yaml:"failMode"`
}

// PortRange is an inclusive port range.
type PortRange struct {
	Lo uint16 `yaml:"lo"`
	Hi uint16 `yaml:"hi"`
}

// LoadConfig reads and validates the config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.BPFDir == "" {
		c.BPFDir = "/opt/lwauth-ebpf/bpf"
	}
	if c.CgroupPath == "" {
		c.CgroupPath = "/sys/fs/cgroup"
	}
	if c.LWAuthSocket == "" {
		c.LWAuthSocket = "/run/lwauth/lwauth.sock"
	}
	if c.FailMode == "" {
		c.FailMode = "open"
	}
	if c.FailMode != "open" && c.FailMode != "closed" {
		return fmt.Errorf("config: failMode must be 'open' or 'closed', got %q", c.FailMode)
	}
	for i, pr := range c.InterceptPorts {
		if pr.Lo == 0 || pr.Hi == 0 {
			return fmt.Errorf("config: interceptPorts[%d]: lo and hi must be non-zero", i)
		}
		if pr.Lo > pr.Hi {
			return fmt.Errorf("config: interceptPorts[%d]: lo (%d) > hi (%d)", i, pr.Lo, pr.Hi)
		}
	}
	return nil
}
