// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package bridge connects the eBPF data plane to the lwauth control
// plane. When a connection is intercepted by the sockops/sk_msg programs,
// the bridge sends connection metadata to lwauth via Unix domain socket
// and writes the verdict back to the BPF verdict map.
//
// Protocol (over UDS):
//
//	Request:  JSON { "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
//	                  "src_port": 43210, "dst_port": 8080, "protocol": "tcp" }
//	Response: JSON { "allow": true }
//
// The bridge maintains a connection pool to the lwauth socket and
// handles reconnection on failure.
package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth-ebpf/internal/loader"
)

// AuthRequest is sent to lwauth for an allow/deny decision.
type AuthRequest struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// AuthResponse is received from lwauth.
type AuthResponse struct {
	Allow bool `json:"allow"`
}

// Bridge connects the eBPF verdict map to the lwauth control plane.
type Bridge struct {
	socketPath string
	verdictMap *loader.Map
	mu         sync.Mutex
	conn       net.Conn
}

// New creates a bridge to the lwauth control plane.
func New(socketPath string, verdictMap *loader.Map) (*Bridge, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("bridge: socket path is required")
	}
	return &Bridge{
		socketPath: socketPath,
		verdictMap: verdictMap,
	}, nil
}

// Run starts the bridge event loop. It reads intercepted connection
// events from a BPF ring buffer (in production) and queries lwauth.
// Blocks until ctx is cancelled.
func (b *Bridge) Run(ctx context.Context) {
	slog.Info("bridge: event loop started")

	// In production, this would:
	// 1. Open a BPF ring buffer for connection events from the sockops program
	// 2. For each event, call Authorize() to get a verdict
	// 3. Write the verdict to the BPF verdict map
	//
	// For now, we just wait for context cancellation.
	<-ctx.Done()
	slog.Info("bridge: shutting down")
	b.mu.Lock()
	if b.conn != nil {
		b.conn.Close()
	}
	b.mu.Unlock()
}

// Authorize sends a connection to lwauth and returns the verdict.
func (b *Bridge) Authorize(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	conn, err := b.getConn()
	if err != nil {
		return nil, fmt.Errorf("bridge: connect: %w", err)
	}

	// Set deadline from context.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	conn.SetDeadline(deadline)

	// Encode request.
	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		b.resetConn()
		return nil, fmt.Errorf("bridge: write: %w", err)
	}

	// Decode response.
	var resp AuthResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		b.resetConn()
		return nil, fmt.Errorf("bridge: read: %w", err)
	}

	return &resp, nil
}

func (b *Bridge) getConn() (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return b.conn, nil
	}
	conn, err := net.DialTimeout("unix", b.socketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	b.conn = conn
	return conn, nil
}

func (b *Bridge) resetConn() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
}
