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
	if lc.defProfile != "prod" {
		t.Fatalf("expected default profile %q, got %q", "prod", lc.defProfile)
	}
	if _, ok := lc.servers["dev"]; ok {
		t.Fatal("expected dev server stopped after profile change")
	}

	// allowed_profiles start additional servers alongside the default; the
	// default endpoint stays the force_profile's.
	if err := lc.apply(&config.AWSConfig{ForceProfile: "prod", AllowedProfiles: []string{"dev", "staging"}}); err != nil {
		t.Fatalf("apply(prod + allowed) failed: %v", err)
	}
	for _, p := range []string{"prod", "dev", "staging"} {
		if _, ok := lc.servers[p]; !ok {
			t.Fatalf("expected a server for profile %q", p)
		}
	}
	if lc.endpoint() != lc.servers["prod"].Endpoint() {
		t.Fatal("default endpoint should be the force_profile's server")
	}

	// Dropping an allowed profile stops just that server.
	if err := lc.apply(&config.AWSConfig{ForceProfile: "prod", AllowedProfiles: []string{"dev"}}); err != nil {
		t.Fatalf("apply(prod + dev) failed: %v", err)
	}
	if _, ok := lc.servers["staging"]; ok {
		t.Fatal("expected staging server stopped after removal from allowed_profiles")
	}
	if len(lc.servers) != 2 {
		t.Fatalf("expected 2 servers (prod, dev), got %d", len(lc.servers))
	}

	// Switching to raw-credentials mode stops all servers.
	rawCreds := true
	if err := lc.apply(&config.AWSConfig{AllowRawCredentials: &rawCreds}); err != nil {
		t.Fatalf("apply(raw credentials) failed: %v", err)
	}
	if ep := lc.endpoint(); ep != "" {
		t.Fatalf("expected server stopped after disabling IMDS mode, got endpoint %q", ep)
	}
	if len(lc.servers) != 0 {
		t.Fatalf("expected all servers stopped, got %d", len(lc.servers))
	}
}
