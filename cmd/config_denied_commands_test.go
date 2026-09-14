package cmd

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

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
	if !strings.Contains(out, "sudo denied") || !strings.Contains(out, "already denied") {
		t.Errorf("add output = %q", out)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.DeniedCommands, []string{"sudo"}) {
		t.Errorf("stored denied_commands = %v", cfg.DeniedCommands)
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
	if !slices.Equal(cfg.DeniedCommands, []string{"-lite-sandbox config"}) {
		t.Errorf("stored denied_commands after remove = %v", cfg.DeniedCommands)
	}
	if slices.Contains(cfg.EffectiveDeniedCommands(), "lite-sandbox config") {
		t.Errorf("lifted entry still in effect: %v", cfg.EffectiveDeniedCommands())
	}

	// Re-adding it drops the lift rather than listing the same entry twice.
	if err := configDeniedCommandsAddCmd.RunE(configDeniedCommandsAddCmd, []string{"lite-sandbox config"}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedCommands) != 0 {
		t.Errorf("re-add should clear the lift, got %v", cfg.DeniedCommands)
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
