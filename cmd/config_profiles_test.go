package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestConfigProfiles_EnableDisableSet(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	captureStdout(t, func() {
		if err := configCmdRun(t, configProfilesEnableCmd, "go", "deno"); err != nil {
			t.Fatal(err)
		}
		if err := configCmdRun(t, configProfilesSetCmd, "deno", "allow_network", "true"); err != nil {
			t.Fatal(err)
		}
		if err := configCmdRun(t, configProfilesDisableCmd, "montypython"); err != nil {
			t.Fatal(err)
		}
		if err := configCmdRun(t, configProfilesDisableCmd, "deno"); err != nil {
			t.Fatal(err)
		}
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProfileEnabled("go") || cfg.ProfileEnabled("deno") || cfg.ProfileEnabled("montypython") {
		t.Errorf("profiles = %+v", cfg.Profiles)
	}
	if !cfg.ProfileOption("deno", "allow_network") {
		t.Error("disabling deno must keep its options")
	}
	if err := configCmdRun(t, configProfilesEnableCmd, "golang"); err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("unknown profile: %v", err)
	}
	if err := configCmdRun(t, configProfilesSetCmd, "go", "generate", "true"); err == nil {
		t.Error("go has no generate option (it is a commands entry)")
	}
}

// TestConfigRuntimes_DeprecatedAlias: the former `config runtimes <x>` commands
// still work, writing profiles and commands entries.
func TestConfigRuntimes_DeprecatedAlias(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	runtimes := findConfigSubcommand(t, "runtimes")
	rust := findSubcommand(t, runtimes, "rust")
	enable := findSubcommand(t, rust, "enable")
	if err := enable.Flags().Set("with-publish", "true"); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := configCmdRun(t, enable); err != nil {
			t.Fatal(err)
		}
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProfileEnabled("rust") || !slices.Contains(cfg.ExtraCommandList(), "cargo publish") {
		t.Errorf("config runtimes rust enable --with-publish wrote %+v", cfg)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), "runtimes") {
		t.Errorf("the alias must write the new form:\n%s", data)
	}
}
