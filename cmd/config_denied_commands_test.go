package cmd

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestConfigDeniedCommandsCmd: the former `denied-commands` command still
// works as a hidden alias, writing the unified `commands` form — a denial as
// allow: false, a lifted built-in as allow: true.
func TestConfigDeniedCommandsCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	out := captureStdout(t, func() {
		if err := configDeniedCommandsListCmd.RunE(configDeniedCommandsListCmd, nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "lite-sandbox config   (built-in)") {
		t.Errorf("default list should mark built-ins: %q", out)
	}

	// Adding a new entry stores it; adding a built-in is a no-op.
	out = captureStdout(t, func() {
		if err := configDeniedCommandsAddCmd.RunE(configDeniedCommandsAddCmd, []string{"sudo", "lite-sandbox  config"}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})
	if !strings.Contains(out, "sudo: deny") || !strings.Contains(out, "lite-sandbox config: deny (built-in default restored)") {
		t.Errorf("add output = %q", out)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsesDeprecatedCommandKeys() {
		t.Errorf("the alias must write the new section only: %+v", cfg)
	}
	if !slices.Equal(cfg.DeniedCommandList(), []string{"sudo"}) {
		t.Errorf("stored denials = %v", cfg.DeniedCommandList())
	}

	// Removing a user entry deletes it; removing a built-in records a lift.
	out = captureStdout(t, func() {
		if err := configDeniedCommandsRemoveCmd.RunE(configDeniedCommandsRemoveCmd, []string{"sudo", "lite-sandbox config", "wget"}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	if !strings.Contains(out, "sudo removed") || !strings.Contains(out, "lite-sandbox config lifted") ||
		!strings.Contains(out, "wget is not denied") {
		t.Errorf("remove output = %q", out)
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Commands) != 1 || !cfg.Commands[0].Allows() || cfg.Commands[0].Command != "lite-sandbox config" {
		t.Errorf("stored commands after remove = %+v", cfg.Commands)
	}
	if slices.Contains(cfg.EffectiveDeniedCommands(), "lite-sandbox config") {
		t.Errorf("lifted entry still in effect: %v", cfg.EffectiveDeniedCommands())
	}

	// Re-adding it drops the lift rather than restating the built-in.
	if err := configDeniedCommandsAddCmd.RunE(configDeniedCommandsAddCmd, []string{"lite-sandbox config"}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Commands) != 0 {
		t.Errorf("re-add should clear the lift, got %+v", cfg.Commands)
	}
	if !slices.Contains(cfg.EffectiveDeniedCommands(), "lite-sandbox config") {
		t.Errorf("built-in not restored: %v", cfg.EffectiveDeniedCommands())
	}
}

func TestConfigModeShow_ListsDeniedCommands(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	out := captureStdout(t, func() {
		if err := configModeShowCmd.RunE(configModeShowCmd, nil); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	if !strings.Contains(out, "Denied commands") || !strings.Contains(out, "lite-sandbox config") {
		t.Errorf("mode show should list denied commands: %q", out)
	}
}
