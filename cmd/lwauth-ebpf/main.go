// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Command lwauth-ebpf is the userspace agent for the LightweightAuth eBPF
// data plane (Mode C). It runs as a privileged DaemonSet and:
//
//  1. Loads eBPF programs (sockops, sk_msg, cgroup_skb) into the kernel.
//  2. Configures intercept port ranges and deny CIDRs via BPF maps.
//  3. Bridges intercepted connections to the lwauth control plane via
//     Unix domain socket for allow/deny decisions.
//  4. Writes verdicts back to the BPF verdict map.
//  5. Exports Prometheus metrics from BPF per-CPU stats maps.
//
// Usage:
//
//	lwauth-ebpf --config /etc/lwauth-ebpf/config.yaml
//
// Requires: Linux >= 5.10, CAP_BPF + CAP_SYS_ADMIN, BTF enabled.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mikeappsec/lightweightauth-ebpf/internal/bridge"
	"github.com/mikeappsec/lightweightauth-ebpf/internal/loader"
)

func main() {
	configPath := flag.String("config", "/etc/lwauth-ebpf/config.yaml", "path to config file")
	metricsAddr := flag.String("metrics-addr", ":9191", "Prometheus metrics listen address")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Load eBPF programs.
	ports := make([]loader.PortRange, len(cfg.InterceptPorts))
	for i, p := range cfg.InterceptPorts {
		ports[i] = loader.PortRange{Lo: p.Lo, Hi: p.Hi}
	}
	progs, err := loader.Load(cfg.BPFDir, &loader.Options{
		CgroupPath:     cfg.CgroupPath,
		InterceptPorts: ports,
		DenyCIDRs:      cfg.DenyCIDRs,
	})
	if err != nil {
		slog.Error("failed to load eBPF programs", "err", err)
		os.Exit(1)
	}
	defer progs.Close()
	slog.Info("eBPF programs loaded and attached")

	// Start the bridge to lwauth control plane.
	br, err := bridge.New(cfg.LWAuthSocket, progs.VerdictMap())
	if err != nil {
		slog.Error("failed to create bridge", "err", err)
		os.Exit(1)
	}
	go br.Run(ctx)
	slog.Info("bridge started", "socket", cfg.LWAuthSocket)

	// Metrics server.
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", progs.MetricsHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	srv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		slog.Info("metrics server starting", "addr", *metricsAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	srv.Close()
}
