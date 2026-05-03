// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	data := `
bpfDir: /opt/bpf
cgroupPath: /sys/fs/cgroup
lwauthSocket: /run/lwauth/lwauth.sock
failMode: open
interceptPorts:
  - lo: 80
    hi: 80
  - lo: 443
    hi: 443
denyCidrs:
  - "10.0.0.0/8"
`
	if err := os.WriteFile(cfgFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BPFDir != "/opt/bpf" {
		t.Errorf("BPFDir = %q, want /opt/bpf", cfg.BPFDir)
	}
	if cfg.CgroupPath != "/sys/fs/cgroup" {
		t.Errorf("CgroupPath = %q, want /sys/fs/cgroup", cfg.CgroupPath)
	}
	if len(cfg.InterceptPorts) != 2 {
		t.Errorf("InterceptPorts len = %d, want 2", len(cfg.InterceptPorts))
	}
	if cfg.InterceptPorts[0].Lo != 80 || cfg.InterceptPorts[0].Hi != 80 {
		t.Errorf("InterceptPorts[0] = %+v, want {80, 80}", cfg.InterceptPorts[0])
	}
	if len(cfg.DenyCIDRs) != 1 || cfg.DenyCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("DenyCIDRs = %v, want [10.0.0.0/8]", cfg.DenyCIDRs)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	data := `{}`
	if err := os.WriteFile(cfgFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BPFDir != "/opt/lwauth-ebpf/bpf" {
		t.Errorf("BPFDir = %q, want default", cfg.BPFDir)
	}
	if cfg.CgroupPath != "/sys/fs/cgroup" {
		t.Errorf("CgroupPath = %q, want default", cfg.CgroupPath)
	}
	if cfg.LWAuthSocket != "/run/lwauth/lwauth.sock" {
		t.Errorf("LWAuthSocket = %q, want default", cfg.LWAuthSocket)
	}
	if cfg.FailMode != "open" {
		t.Errorf("FailMode = %q, want open", cfg.FailMode)
	}
}

func TestLoadConfig_InvalidFailMode(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	data := `failMode: maybe`
	if err := os.WriteFile(cfgFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgFile)
	if err == nil {
		t.Fatal("expected error for invalid failMode")
	}
}

func TestLoadConfig_InvalidPortRange(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	data := `
interceptPorts:
  - lo: 443
    hi: 80
`
	if err := os.WriteFile(cfgFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgFile)
	if err == nil {
		t.Fatal("expected error for lo > hi")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/file.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
