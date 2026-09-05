package cmd

import (
	"context"
	"errors"
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
	t.Cleanup(func() { modeOverrideDir = "" })
	orig := osSandboxPreflight
	osSandboxPreflight = func(context.Context) error { t.Fatal("preflight must not run for --dir"); return nil }
	t.Cleanup(func() { osSandboxPreflight = orig })

	modeOverrideDir = "/work/untrusted"
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
