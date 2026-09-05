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

func TestConfigureSandboxConfig_FirstTimeStaysStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lite-sandbox", "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	t.Cleanup(func() { installMode = "" })

	preflightCalled := false
	pf := func(context.Context) error { preflightCalled = true; return nil }
	res, err := configureSandboxConfig(context.Background(), pf)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.ModeSet || res.Mode != config.ModeAllowlist || !res.Audit || res.OSSandbox {
		t.Fatalf("first-time result = %+v", res)
	}
	if preflightCalled {
		t.Error("preflight must not run unless denylist is requested")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "" || !cfg.AuditEnabled() || cfg.OSSandbox != nil {
		t.Errorf("saved config = mode:%q audit:%v os:%v; want only audit set", cfg.Mode, cfg.AuditEnabled(), cfg.OSSandbox)
	}

	out := captureStdout(t, func() { printInstallConfig(res) })
	for _, want := range []string{"Created", "mode: allowlist", "audit: true", "strict default", "docs/adoption.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestConfigureSandboxConfig_OptOutDenylist(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { installMode = "" })

	installMode = "denylist"
	ok := func(context.Context) error { return nil }
	res, err := configureSandboxConfig(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.ModeSet || res.Mode != config.ModeDenylist || !res.Audit || !res.OSSandbox || !res.OSSandboxEnabled {
		t.Fatalf("denylist opt-out result = %+v", res)
	}
	cfg, _ := config.Load()
	if cfg.EffectiveMode() != config.ModeDenylist || !cfg.OSSandboxEnabled() || !cfg.AuditEnabled() {
		t.Errorf("saved config = mode:%s os:%v audit:%v", cfg.EffectiveMode(), cfg.OSSandboxEnabled(), cfg.AuditEnabled())
	}
	out := captureStdout(t, func() { printInstallConfig(res) })
	if !strings.Contains(out, "mode: denylist") || !strings.Contains(out, "os_sandbox: true") || strings.Contains(out, "strict default") {
		t.Errorf("output = %q", out)
	}
}

func TestConfigureSandboxConfig_DenylistWithoutBackend(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { installMode = "" })

	installMode = "denylist"
	fail := func(context.Context) error { return errors.New("bubblewrap (bwrap) is not installed") }
	res, err := configureSandboxConfig(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if res.OSSandbox || res.OSSandboxEnabled || res.OSSandboxErr == nil || res.Mode != config.ModeDenylist {
		t.Fatalf("expected denylist without os_sandbox and a preflight error, got %+v", res)
	}
	cfg, _ := config.Load()
	if cfg.OSSandbox != nil {
		t.Error("os_sandbox must stay unset when preflight fails")
	}
	out := captureStdout(t, func() { printInstallConfig(res) })
	if !strings.Contains(out, "os_sandbox: false") || !strings.Contains(out, "bwrap") || !strings.Contains(out, "os-sandbox enable") {
		t.Errorf("output should explain the missing backend:\n%s", out)
	}
}

func TestConfigureSandboxConfig_ExistingUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	t.Cleanup(func() { installMode = "" })
	if err := os.WriteFile(path, []byte("extra_commands:\n  - curl\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := configureSandboxConfig(context.Background(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.ModeSet || res.Mode != config.ModeAllowlist || res.Audit || res.OSSandbox {
		t.Fatalf("existing config should be reported as-is: %+v", res)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "extra_commands:\n  - curl\n" {
		t.Errorf("existing config was rewritten:\n%s", data)
	}
	out := captureStdout(t, func() { printInstallConfig(res) })
	if !strings.Contains(out, "Kept existing") || !strings.Contains(out, "audit enable") {
		t.Errorf("output = %q", out)
	}
}

func TestConfigureSandboxConfig_ModeFlagOnExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	t.Cleanup(func() { installMode = "" })
	if err := os.WriteFile(path, []byte("extra_commands:\n  - curl\nos_sandbox: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	installMode = "denylist"
	preflightCalled := false
	res, err := configureSandboxConfig(context.Background(), func(context.Context) error { preflightCalled = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !res.ModeSet || res.Mode != config.ModeDenylist || res.Audit {
		t.Fatalf("--mode denylist on existing config: %+v", res)
	}
	// os_sandbox was explicitly set by the user; --mode must not override it.
	if preflightCalled || res.OSSandbox || res.OSSandboxEnabled {
		t.Errorf("explicit os_sandbox: false must be respected: %+v (preflight called: %v)", res, preflightCalled)
	}
	cfg, _ := config.Load()
	if cfg.EffectiveMode() != config.ModeDenylist || len(cfg.ExtraCommands) != 1 || cfg.OSSandboxEnabled() {
		t.Errorf("config after --mode: mode=%s extra=%v os=%v", cfg.EffectiveMode(), cfg.ExtraCommands, cfg.OSSandboxEnabled())
	}

	installMode = "strict"
	if _, err := configureSandboxConfig(context.Background(), nil); err == nil {
		t.Error("invalid --mode should error")
	}
}
