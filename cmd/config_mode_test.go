package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestConfigModeCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	out := captureStdout(t, func() {
		if err := configModeShowCmd.RunE(configModeShowCmd, nil); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	if !strings.Contains(out, "Mode: allowlist (default") {
		t.Errorf("default show output = %q", out)
	}

	if err := configModeSetCmd.RunE(configModeSetCmd, []string{"strict"}); err == nil {
		t.Error("invalid mode should be rejected")
	}
	// Pin the preflight so the test does not depend on bubblewrap being present.
	orig := osSandboxPreflight
	osSandboxPreflight = func(context.Context) error { return errors.New("no backend") }
	t.Cleanup(func() { osSandboxPreflight = orig })
	if err := configModeSetCmd.RunE(configModeSetCmd, []string{"denylist"}); err != nil {
		t.Fatalf("set denylist: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveMode() != config.ModeDenylist {
		t.Errorf("mode after set = %q", cfg.EffectiveMode())
	}

	out = captureStdout(t, func() {
		if err := configModeShowCmd.RunE(configModeShowCmd, nil); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	if !strings.Contains(out, "Mode: denylist") || !strings.Contains(out, "Read-denied paths") || !strings.Contains(out, "os_sandbox is off") {
		t.Errorf("denylist show output = %q", out)
	}
}

// TestConfigModeCmd_ShowLiftedBuiltins checks `mode show` lists the SSH keys as
// hidden in every mode and, once a paths grant lifts them, says so with the
// grant rather than dropping them from the listing.
func TestConfigModeCmd_ShowLiftedBuiltins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "id_ed25519")
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "config"} {
		if err := os.WriteFile(filepath.Join(home, ".ssh", name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	show := func() string {
		return captureStdout(t, func() {
			if err := configModeShowCmd.RunE(configModeShowCmd, nil); err != nil {
				t.Fatalf("show: %v", err)
			}
		})
	}
	out := show()
	if !strings.Contains(out, "Always hidden under the OS sandbox") || !strings.Contains(out, key+"   (SSH private key)") {
		t.Errorf("allowlist show should list the key as always hidden:\n%s", out)
	}
	if strings.Contains(out, key+".pub") || strings.Contains(out, "Read-denied paths") {
		t.Errorf("allowlist show must list neither the public key nor the denylist-only lists:\n%s", out)
	}

	pathsAllowInternal = true
	t.Cleanup(func() { pathsAllowInternal = false })
	allowOut := captureStdout(t, func() {
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"~/.ssh"}); err != nil {
			t.Fatalf("allow: %v", err)
		}
	})
	if !strings.Contains(allowOut, "lifts built-in denial: "+key+" (SSH private key)") {
		t.Errorf("allow should report the lifted key:\n%s", allowOut)
	}
	out = show()
	if !strings.Contains(out, key+"   (NOT enforced: lifted by the paths grant on ~/.ssh; SSH private key)") {
		t.Errorf("show should report the lifted key with its grant:\n%s", out)
	}
}

func TestConfigAuditCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", "/tmp/x/audit.jsonl")

	if err := configAuditEnableCmd.RunE(configAuditEnableCmd, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load()
	if !cfg.AuditEnabled() {
		t.Error("audit should be enabled")
	}
	out := captureStdout(t, func() {
		if err := configAuditShowCmd.RunE(configAuditShowCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Audit: true") || !strings.Contains(out, "/tmp/x/audit.jsonl") {
		t.Errorf("audit show = %q", out)
	}
	if err := configAuditDisableCmd.RunE(configAuditDisableCmd, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load()
	if cfg.AuditEnabled() {
		t.Error("audit should be disabled")
	}
}

func TestConfigModeSet_OpenWithoutAuditWarns(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	out := captureStdout(t, func() {
		if err := configModeSetCmd.RunE(configModeSetCmd, []string{"open"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "warning") {
		t.Errorf("expected a warning for open mode without audit, got %q", out)
	}
}

func TestConfigModeSet_Dir(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { configDir = "" })
	orig := osSandboxPreflight
	osSandboxPreflight = func(context.Context) error { t.Fatal("preflight must not run for --dir"); return nil }
	t.Cleanup(func() { osSandboxPreflight = orig })

	configDir = "/work/untrusted"
	out := captureStdout(t, func() {
		if err := configModeSetCmd.RunE(configModeSetCmd, []string{"denylist"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "for /work/untrusted") || !strings.Contains(out, "base mode stays allowlist") {
		t.Errorf("output = %q", out)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveMode() != config.ModeAllowlist {
		t.Errorf("base mode changed: %s", cfg.EffectiveMode())
	}
	if got := cfg.ForDirectory("/work/untrusted/sub").EffectiveMode(); got != config.ModeDenylist {
		t.Errorf("override mode = %s", got)
	}
	if cfg.OSSandbox != nil {
		t.Error("--dir must not touch os_sandbox")
	}
}
