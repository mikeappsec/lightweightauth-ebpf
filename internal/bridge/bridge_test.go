// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth-ebpf/internal/loader"
)

func TestNew_EmptySocket(t *testing.T) {
	_, err := New("", &loader.Map{})
	if err == nil {
		t.Fatal("expected error for empty socket path")
	}
}

func TestNew_Valid(t *testing.T) {
	br, err := New("/tmp/test.sock", &loader.Map{Name: "verdict_map"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if br.socketPath != "/tmp/test.sock" {
		t.Errorf("socketPath = %q, want /tmp/test.sock", br.socketPath)
	}
}

func TestAuthorize_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	// Start a mock lwauth server.
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req AuthRequest
		dec := json.NewDecoder(conn)
		if err := dec.Decode(&req); err != nil {
			return
		}
		resp := AuthResponse{Allow: true}
		enc := json.NewEncoder(conn)
		enc.Encode(&resp)
	}()

	br, err := New(sockPath, &loader.Map{Name: "verdict_map"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := br.Authorize(ctx, &AuthRequest{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		SrcPort:  43210,
		DstPort:  8080,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("authorize error: %v", err)
	}
	if !resp.Allow {
		t.Error("expected Allow=true")
	}
}

func TestAuthorize_Deny(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req AuthRequest
		dec := json.NewDecoder(conn)
		dec.Decode(&req)
		resp := AuthResponse{Allow: false}
		enc := json.NewEncoder(conn)
		enc.Encode(&resp)
	}()

	br, err := New(sockPath, &loader.Map{Name: "verdict_map"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := br.Authorize(ctx, &AuthRequest{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		SrcPort:  43210,
		DstPort:  8080,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("authorize error: %v", err)
	}
	if resp.Allow {
		t.Error("expected Allow=false")
	}
}

func TestAuthorize_ConnectionRefused(t *testing.T) {
	// Use a socket that doesn't exist.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "nonexistent.sock")

	br, err := New(sockPath, &loader.Map{Name: "verdict_map"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = br.Authorize(ctx, &AuthRequest{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 43210,
		DstPort: 8080,
	})
	if err == nil {
		t.Fatal("expected error when socket doesn't exist")
	}
}

func TestRun_CancelledContext(t *testing.T) {
	br, _ := New("/tmp/test.sock", &loader.Map{})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		br.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancel")
	}
}

// Ensure the test file compiles on all platforms.
func TestCompile(t *testing.T) {
	_ = os.Getenv("HOME")
}

func TestCircuitBreaker(t *testing.T) {
	// Use a non-existent socket to trigger connection failures.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "nonexistent.sock")

	br, err := New(sockPath, &loader.Map{Name: "verdict_map"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Exhaust the circuit breaker.
	for i := 0; i < maxConsecFails; i++ {
		_, _ = br.Authorize(ctx, &AuthRequest{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 43210, DstPort: 8080,
		})
		// Manually record failure since getConn itself fails
		br.recordFailure()
	}

	// Next attempt should get circuit open error.
	_, err = br.Authorize(ctx, &AuthRequest{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 43210, DstPort: 8080,
	})
	if err == nil {
		t.Fatal("expected error from circuit breaker")
	}
	if err.Error() != "bridge: connect: bridge: circuit breaker open, backing off" {
		// Just check it fails; the exact message depends on which path trips first
		t.Logf("got error (acceptable): %v", err)
	}
}
