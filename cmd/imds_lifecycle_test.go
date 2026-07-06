package cmd

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

func TestIMDSLifecycle(t *testing.T) {
	lc := &imdsLifecycle{sandbox: bash_sandboxed.NewSandbox()}
	defer lc.stop()

	// No AWS config: nothing to run.
	if err := lc.apply(nil); err != nil {
		t.Fatalf("apply(nil) failed: %v", err)
	}
	if ep := lc.endpoint(); ep != "" {
		t.Fatalf("expected no server, got endpoint %q", ep)
	}

	// IMDS mode enabled: server starts.
	if err := lc.apply(&config.AWSConfig{ForceProfile: "dev"}); err != nil {
		t.Fatalf("apply(dev) failed: %v", err)
	}
	devEndpoint := lc.endpoint()
	if devEndpoint == "" {
		t.Fatal("expected a running server after enabling IMDS mode")
	}

	// Reapplying the same config keeps the same server.
	if err := lc.apply(&config.AWSConfig{ForceProfile: "dev"}); err != nil {
		t.Fatalf("apply(dev) again failed: %v", err)
	}
	if ep := lc.endpoint(); ep != devEndpoint {
		t.Fatalf("expected same endpoint %q after no-op reapply, got %q", devEndpoint, ep)
	}

	// Profile change restarts the server with the new profile.
	if err := lc.apply(&config.AWSConfig{ForceProfile: "prod"}); err != nil {
		t.Fatalf("apply(prod) failed: %v", err)
	}
	if lc.endpoint() == "" {
		t.Fatal("expected a running server after profile change")
	}
	if lc.profile != "prod" {
		t.Fatalf("expected profile %q, got %q", "prod", lc.profile)
	}

	// Switching to raw-credentials mode stops the server.
	rawCreds := true
	if err := lc.apply(&config.AWSConfig{AllowRawCredentials: &rawCreds}); err != nil {
		t.Fatalf("apply(raw credentials) failed: %v", err)
	}
	if ep := lc.endpoint(); ep != "" {
		t.Fatalf("expected server stopped after disabling IMDS mode, got endpoint %q", ep)
	}
}
