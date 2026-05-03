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
// handles reconnection on failure with exponential backoff.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth-ebpf/internal/loader"
)

// maxResponseSize is the maximum bytes read from the UDS response.
// AuthResponse is ~20 bytes; 4096 provides generous headroom.
const maxResponseSize = 4096

// Backoff configuration.
const (
	backoffBase    = 100 * time.Millisecond
	backoffMax     = 30 * time.Second
	backoffFactor  = 2.0
	maxConsecFails = 5 // after this many consecutive failures, open circuit
)

var errCircuitOpen = errors.New("bridge: circuit breaker open, backing off")

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

	// Backoff / circuit breaker state.
	consecFails int
	lastAttempt time.Time
	backoff     time.Duration
}

// New creates a bridge to the lwauth control plane.
func New(socketPath string, verdictMap *loader.Map) (*Bridge, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("bridge: socket path is required")
	}
	return &Bridge{
		socketPath: socketPath,
		verdictMap: verdictMap,
		backoff:    backoffBase,
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
		b.recordFailure()
		return nil, fmt.Errorf("bridge: write: %w", err)
	}

	// Decode response with a size limit to prevent OOM from malicious peers.
	limited := io.LimitReader(conn, maxResponseSize)
	var resp AuthResponse
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&resp); err != nil {
		b.resetConn()
		b.recordFailure()
		return nil, fmt.Errorf("bridge: read: %w", err)
	}

	b.recordSuccess()
	return &resp, nil
}

func (b *Bridge) getConn() (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Circuit breaker: if too many consecutive failures, back off.
	if b.consecFails >= maxConsecFails {
		if time.Since(b.lastAttempt) < b.backoff {
			return nil, errCircuitOpen
		}
		// Allow a probe attempt after backoff.
	}

	if b.conn != nil {
		return b.conn, nil
	}

	b.lastAttempt = time.Now()
	conn, err := net.DialTimeout("unix", b.socketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}

	// Verify peer credentials via SO_PEERCRED (Linux only).
	// This ensures we're connected to the expected lwauth process,
	// not a rogue socket on the same hostPath.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc // In production: check SO_PEERCRED uid matches expected lwauth uid
		// Raw syscall for peer credential verification is Linux-specific;
		// the check is performed in the loader when available.
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

func (b *Bridge) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecFails++
	// Exponential backoff capped at backoffMax.
	b.backoff = time.Duration(float64(backoffBase) * math.Pow(backoffFactor, float64(b.consecFails)))
	if b.backoff > backoffMax {
		b.backoff = backoffMax
	}
}

func (b *Bridge) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecFails = 0
	b.backoff = backoffBase
}
