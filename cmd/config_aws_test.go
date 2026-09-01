package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what it
// wrote. The config `show` commands print via fmt to os.Stdout, so this is how
// their output is asserted.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// TestAWSShowCmd_DirectoryOnlyOverride guards the regression where `aws show`
// early-returned on a nil base aws section and hid a directory-only override —
// which `config aws force-profile --dir` creates without touching the base.
func TestAWSShowCmd_DirectoryOnlyOverride(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { awsOverrideDir = "" })

	// Create a directory override with no base aws section.
	awsOverrideDir = "/work/acme"
	if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"acme-dev"}); err != nil {
		t.Fatalf("dir force-profile: %v", err)
	}
	awsOverrideDir = ""

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AWS != nil {
		t.Fatalf("expected no base aws section, got %+v", cfg.AWS)
	}
	if findAWSOverride(cfg, "/work/acme") == nil {
		t.Fatal("expected a directory override for /work/acme")
	}

	out := captureStdout(t, func() {
		if err := awsShowCmd.RunE(awsShowCmd, nil); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	if !strings.Contains(out, "/work/acme") || !strings.Contains(out, "acme-dev") {
		t.Errorf("aws show omitted the directory override; got:\n%s", out)
	}
	if strings.Contains(out, "disabled (not configured)") {
		t.Errorf("aws show wrongly reported disabled; got:\n%s", out)
	}
}

func TestAWSAllowedProfilesCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	awsOverrideDir = ""
	t.Cleanup(func() { awsOverrideDir = "" })

	// allowed_profiles requires force_profile to be set first.
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, []string{"dev"}); err == nil {
		t.Fatal("expected error when force_profile is unset")
	}

	if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"ro"}); err != nil {
		t.Fatalf("force-profile: %v", err)
	}
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, []string{"dev", "prod"}); err != nil {
		t.Fatalf("allowed-profiles: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.AWS.AllowedProfiles, []string{"dev", "prod"}) {
		t.Fatalf("AllowedProfiles = %v, want [dev prod]", cfg.AWS.AllowedProfiles)
	}

	// Changing the force profile preserves allowed_profiles.
	if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"ro2"}); err != nil {
		t.Fatalf("force-profile change: %v", err)
	}
	cfg, _ = config.Load()
	if cfg.AWS.ForceProfile != "ro2" || !slices.Equal(cfg.AWS.AllowedProfiles, []string{"dev", "prod"}) {
		t.Fatalf("after profile change: profile=%q allowed=%v, want ro2 + [dev prod]", cfg.AWS.ForceProfile, cfg.AWS.AllowedProfiles)
	}

	// No args clears the list.
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	cfg, _ = config.Load()
	if len(cfg.AWS.AllowedProfiles) != 0 {
		t.Fatalf("expected cleared, got %v", cfg.AWS.AllowedProfiles)
	}

	// Switching to raw credentials clears allowed_profiles.
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, []string{"dev"}); err != nil {
		t.Fatalf("set allowed: %v", err)
	}
	if err := awsAllowRawCredentialsCmd.RunE(awsAllowRawCredentialsCmd, nil); err != nil {
		t.Fatalf("allow-raw: %v", err)
	}
	cfg, _ = config.Load()
	if cfg.AWS.ForceProfile != "" || len(cfg.AWS.AllowedProfiles) != 0 {
		t.Fatalf("raw mode should clear force_profile and allowed_profiles, got profile=%q allowed=%v", cfg.AWS.ForceProfile, cfg.AWS.AllowedProfiles)
	}
}

func TestAWSAllowedProfilesCmd_Dir(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { awsOverrideDir = "" })

	if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"ro"}); err != nil {
		t.Fatalf("base force-profile: %v", err)
	}

	// --dir without an existing force_profile override is rejected.
	awsOverrideDir = "/work/acme"
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, []string{"acme-dev"}); err == nil {
		t.Fatal("expected error for --dir without an existing override")
	}

	// Create the override, then set its allowed_profiles.
	if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"acme-ro"}); err != nil {
		t.Fatalf("dir force-profile: %v", err)
	}
	if err := awsAllowedProfilesCmd.RunE(awsAllowedProfilesCmd, []string{"acme-dev", "acme-prod"}); err != nil {
		t.Fatalf("dir allowed-profiles: %v", err)
	}
	awsOverrideDir = ""

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	o := findAWSOverride(cfg, "/work/acme")
	if o == nil {
		t.Fatal("expected an override for /work/acme")
	}
	if o.ForceProfile != "acme-ro" || !slices.Equal(o.AllowedProfiles, []string{"acme-dev", "acme-prod"}) {
		t.Fatalf("override = {%q, %v}, want {acme-ro, [acme-dev acme-prod]}", o.ForceProfile, o.AllowedProfiles)
	}
	// Base config is untouched.
	if len(cfg.AWS.AllowedProfiles) != 0 {
		t.Errorf("base AllowedProfiles should be empty, got %v", cfg.AWS.AllowedProfiles)
	}
}
