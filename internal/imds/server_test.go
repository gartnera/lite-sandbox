package imds

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

func TestNewServer_RandomPort(t *testing.T) {
	// Create server with port 0 (random port)
	server, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	// Verify endpoint has a valid port
	endpoint := server.Endpoint()
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Errorf("unexpected endpoint format: %s", endpoint)
	}

	// Verify port is not 0
	if strings.Contains(endpoint, ":0/") {
		t.Error("port should not be 0")
	}

	t.Logf("IMDS endpoint: %s", endpoint)
}

func TestNewServer_MultiplePorts(t *testing.T) {
	// Create multiple servers to ensure they get different ports
	server1, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server1: %v", err)
	}
	defer server1.Shutdown(context.Background())

	server2, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server2: %v", err)
	}
	defer server2.Shutdown(context.Background())

	// Verify they have different ports
	if server1.addr == server2.addr {
		t.Errorf("servers should have different addresses: %s == %s", server1.addr, server2.addr)
	}

	t.Logf("Server 1: %s", server1.Endpoint())
	t.Logf("Server 2: %s", server2.Endpoint())
}

func TestServer_SecretToken(t *testing.T) {
	// Create two servers and verify they have different secret tokens
	server1, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server1: %v", err)
	}
	defer server1.Shutdown(context.Background())

	server2, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server2: %v", err)
	}
	defer server2.Shutdown(context.Background())

	// Verify secret tokens are different
	if server1.secretToken == server2.secretToken {
		t.Error("servers should have different secret tokens")
	}

	// Verify endpoints are standard format (no secret token in path for AWS SDK compatibility)
	endpoint1 := server1.Endpoint()
	if !strings.HasPrefix(endpoint1, "http://") || !strings.HasSuffix(endpoint1, "/") {
		t.Errorf("endpoint should be http://host:port/ format, got: %s", endpoint1)
	}

	t.Logf("Token 1 length: %d", len(server1.secretToken))
	t.Logf("Token 2 length: %d", len(server2.secretToken))
}

// TestServer_SessionEviction verifies that expired session tokens drop out of
// the cache instead of accumulating forever (the previous map-based store
// never deleted entries, leaking ~100B + map overhead per /latest/api/token
// hit until process exit).
func TestServer_SessionEviction(t *testing.T) {
	server, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	// Run eviction in the background, like Start() does for the real server.
	go server.sessions.Start()

	// Set a very short TTL directly to keep the test fast.
	const shortTTL = 50 * time.Millisecond
	for i := 0; i < 200; i++ {
		server.sessions.Set("token-"+strings.Repeat("x", i), struct{}{}, shortTTL)
	}

	if got := server.sessions.Len(); got != 200 {
		t.Fatalf("expected 200 entries pre-expiry, got %d", got)
	}

	// Wait for entries to expire + the eviction loop to sweep them. ttlcache's
	// default sweep interval is short for sub-second TTLs; give it generous
	// time so this isn't flaky on slow CI.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if server.sessions.Len() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("entries did not evict; %d remain", server.sessions.Len())
}

// TestServer_DisableTouchOnHit verifies that checking a session token's
// presence does not silently extend its TTL — otherwise an attacker could
// keep a token alive past its negotiated lifetime by polling.
func TestServer_DisableTouchOnHit(t *testing.T) {
	server, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	const ttl = 100 * time.Millisecond
	server.sessions.Set("tok", struct{}{}, ttl)

	// Repeatedly check Has() during the TTL window. If touch-on-hit were
	// active, the entry's expiry would keep getting bumped forward.
	for i := 0; i < 5; i++ {
		time.Sleep(ttl / 4)
		server.sessions.Has("tok")
	}

	// After the original TTL has elapsed, the token must be gone regardless
	// of how many Has() calls happened in between.
	time.Sleep(ttl)
	if server.sessions.Get("tok", ttlcache.WithDisableTouchOnHit[string, struct{}]()) != nil {
		t.Fatal("session token outlived its negotiated TTL — touch-on-hit is leaking lifetime")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	server, err := NewServer("127.0.0.1:0", "default")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	// Verify server stopped
	select {
	case err := <-errChan:
		if err != nil && err.Error() != "http: Server closed" {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("server did not stop")
	}
}
