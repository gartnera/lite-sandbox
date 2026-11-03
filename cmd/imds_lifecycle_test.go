package cmd

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// isolateAWSConfig keeps the IMDS servers these tests start (which pre-warm
// credentials) off the developer's real ~/.aws profiles of the same names.
func isolateAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
}

func TestIMDSLifecycle(t *testing.T) {
	isolateAWSConfig(t)
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

// TestIMDSLifecycle_CredentialNotes: a command that runs while a brokered
// profile cannot get credentials on the host comes back with a note naming the
// profile and the cause, instead of only the AWS client's "Unable to locate
// credentials". The profile here is missing from the (isolated) host config.
func TestIMDSLifecycle_CredentialNotes(t *testing.T) {
	isolateAWSConfig(t)
	sandbox := bash_sandboxed.NewSandbox()
	defer sandbox.Close()
	lc := &imdsLifecycle{sandbox: sandbox}
	defer lc.stop()
	if err := lc.apply(&config.AWSConfig{ForceProfile: "dev", AllowedProfiles: []string{"ro"}}); err != nil {
		t.Fatal(err)
	}

	// Each server pre-warms on start; wait for both (failing) warm fetches so
	// they land before the "command" below starts.
	deadline := time.Now().Add(10 * time.Second)
	for _, p := range []string{"dev", "ro"} {
		for lc.servers[p].CredentialErrorSince(time.Time{}) == nil {
			if time.Now().After(deadline) {
				t.Fatalf("pre-warm for %q did not finish", p)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	before := time.Now()
	notes := credentialNotes(lc.servers)
	if got := notes(before); len(got) != 0 {
		t.Fatalf("pre-warm failures predate the command, got %v", got)
	}

	// A credential request through the default profile's server, as an AWS
	// client in a command would make, fails; only that profile is reported.
	fetchVia(t, lc.servers["dev"].Endpoint())
	got := notes(before)
	if len(got) != 1 || !strings.Contains(got[0], `profile "dev"`) || !strings.Contains(got[0], "cause:") {
		t.Fatalf("notes = %v", got)
	}
	if got := notes(time.Now().Add(time.Second)); len(got) != 0 {
		t.Errorf("failure before since should not be reported, got %v", got)
	}
}

// fetchVia makes an IMDSv2 credential request against endpoint the way an AWS
// SDK does: a session token, then the role's credentials document.
func fetchVia(t *testing.T, endpoint string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, endpoint+"latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, endpoint+"latest/meta-data/iam/security-credentials/sandboxed-role", nil)
	req.Header.Set("X-aws-ec2-metadata-token", string(tok))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
