package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// setCommandsFlags pins the flag variable the commands commands read (cobra
// would set it from argv) and restores it afterwards.
func setCommandsFlags(t *testing.T, noSandbox bool) {
	t.Helper()
	prev := commandsAllowNoSandbox
	commandsAllowNoSandbox = noSandbox
	t.Cleanup(func() { commandsAllowNoSandbox = prev })
}

func TestConfigCommandsCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	out := captureStdout(t, func() {
		setCommandsFlags(t, false)
		if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"curl", "uv  run pyright"}); err != nil {
			t.Fatalf("allow: %v", err)
		}
		setCommandsFlags(t, true)
		if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"docker"}); err != nil {
			t.Fatalf("allow --no-sandbox: %v", err)
		}
		setCommandsFlags(t, false)
		if err := configCommandsDenyCmd.RunE(configCommandsDenyCmd, []string{"sudo", "gh auth"}); err != nil {
			t.Fatalf("deny: %v", err)
		}
		if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"lite-sandbox update"}); err != nil {
			t.Fatalf("allow built-in: %v", err)
		}
	})
	for _, want := range []string{"curl: allow", "uv run pyright: allow", "docker: allow, no sandbox", "sudo: deny", "gh auth: deny",
		"lite-sandbox update: allow", "lifts built-in denial: lite-sandbox update"} {
		if !strings.Contains(out, want) {
			t.Errorf("confirmation output lacks %q:\n%s", want, out)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsesDeprecatedCommandKeys() {
		t.Error("the CLI must write the new section only")
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"curl", "uv run pyright", "lite-sandbox update"}) {
		t.Errorf("allowed = %v", got)
	}
	if got := cfg.UnsandboxedCommandList(); !slices.Equal(got, []string{"docker"}) {
		t.Errorf("unsandboxed = %v", got)
	}
	if got := cfg.DeniedCommandList(); !slices.Equal(got, []string{"sudo", "gh auth"}) {
		t.Errorf("denied = %v", got)
	}
	eff := cfg.EffectiveDeniedCommands()
	if slices.Contains(eff, "lite-sandbox update") || !slices.Contains(eff, "lite-sandbox config") || !slices.Contains(eff, "sudo") {
		t.Errorf("effective deny list = %v", eff)
	}

	// The file is the compact form: one entry per command.
	data, _ := os.ReadFile(os.Getenv("LITE_SANDBOX_CONFIG"))
	if !strings.Contains(string(data), "commands:\n") || strings.Count(string(data), "- command:") != 6 {
		t.Errorf("config file:\n%s", data)
	}

	// allow on an existing command replaces its statement (deny -> allow).
	out = captureStdout(t, func() {
		if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"sudo"}); err != nil {
			t.Fatalf("re-allow: %v", err)
		}
		// deny on a lifted built-in drops the lift rather than restating it.
		if err := configCommandsDenyCmd.RunE(configCommandsDenyCmd, []string{"lite-sandbox update"}); err != nil {
			t.Fatalf("re-deny built-in: %v", err)
		}
		if err := configCommandsRemoveCmd.RunE(configCommandsRemoveCmd, []string{"docker", "nothing", "lite-sandbox hook"}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	for _, want := range []string{"lite-sandbox update: deny (built-in default restored)", "docker removed", "nothing is not configured", "lite-sandbox hook is a built-in denial"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DeniedCommandList(); !slices.Equal(got, []string{"gh auth"}) {
		t.Errorf("denied after re-allow = %v", got)
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"curl", "uv run pyright", "sudo"}) {
		t.Errorf("allowed after edits = %v", got)
	}
	if len(cfg.UnsandboxedCommandList()) != 0 {
		t.Errorf("docker should be gone: %v", cfg.UnsandboxedCommandList())
	}
	if !slices.Contains(cfg.EffectiveDeniedCommands(), "lite-sandbox update") {
		t.Errorf("built-in should be back in force: %v", cfg.EffectiveDeniedCommands())
	}

	// list shows every entry, the built-ins, and nothing about deprecated keys.
	out = captureStdout(t, func() {
		if err := configCommandsListCmd.RunE(configCommandsListCmd, nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	for _, want := range []string{"curl", "gh auth", "deny", "lite-sandbox config", "(built-in)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "deprecated") {
		t.Errorf("list should not mention deprecated keys:\n%s", out)
	}
}

func TestConfigCommandsCmd_Dir(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"
	captureStdout(t, func() {
		setCommandsFlags(t, false)
		if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"make"}); err != nil {
			t.Fatalf("base allow: %v", err)
		}
		withConfigDir(t, dir, func() {
			if err := configCommandsAllowCmd.RunE(configCommandsAllowCmd, []string{"npm"}); err != nil {
				t.Fatalf("dir allow: %v", err)
			}
		})
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"make"}) {
		t.Errorf("base allowed = %v", got)
	}
	got := cfg.ForDirectory(filepath.Join(dir, "sub")).ExtraCommandList()
	if !slices.Equal(got, []string{"make", "npm"}) {
		t.Errorf("allowed for %s = %v", dir, got)
	}
	if len(cfg.Overrides) != 1 || len(cfg.Overrides[0].Commands) != 2 {
		t.Errorf("overrides = %+v", cfg.Overrides)
	}
}

// TestConfigCommandsCmd_DeprecatedAliasesAndMigrate: the former commands still
// work (hidden, writing the new form), list flags old-style keys, and migrate
// rewrites them.
func TestConfigCommandsCmd_DeprecatedAliasesAndMigrate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte("extra_commands: [make]\nunsandboxed_commands: [./deploy.sh]\ndenied_commands: [sudo, -lite-sandbox hook]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	extra := findConfigSubcommand(t, "extra-commands")
	if !extra.Hidden {
		t.Error("extra-commands should be hidden")
	}
	unsandboxed := findConfigSubcommand(t, "unsandboxed-commands")
	out := captureStdout(t, func() {
		if err := configCmdRun(t, findSubcommand(t, extra, "add"), "npm"); err != nil {
			t.Fatalf("extra-commands add: %v", err)
		}
		if err := configCmdRun(t, findSubcommand(t, unsandboxed, "add"), "docker"); err != nil {
			t.Fatalf("unsandboxed-commands add: %v", err)
		}
		if err := configCmdRun(t, findSubcommand(t, extra, "list")); err != nil {
			t.Fatalf("extra-commands list: %v", err)
		}
	})
	if !strings.Contains(out, "make\n") || !strings.Contains(out, "npm\n") || strings.Contains(out, "docker") {
		t.Errorf("extra-commands list = %q", out)
	}

	out = captureStdout(t, func() {
		if err := configCommandsListCmd.RunE(configCommandsListCmd, nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "(deprecated key)") || !strings.Contains(out, "commands migrate") {
		t.Errorf("list should flag deprecated keys:\n%s", out)
	}
	if !strings.Contains(out, "lite-sandbox hook") || !strings.Contains(out, "lifts a built-in denial") {
		t.Errorf("list should show the converted lift:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := configCommandsMigrateCmd.RunE(configCommandsMigrateCmd, nil); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	})
	if !strings.Contains(out, "Rewrote") {
		t.Errorf("migrate output = %q", out)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsesDeprecatedCommandKeys() {
		t.Errorf("deprecated keys remain: %+v", cfg)
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"npm", "make", "lite-sandbox hook"}) {
		t.Errorf("allowed after migrate = %v", got)
	}
	if got := cfg.UnsandboxedCommandList(); !slices.Equal(got, []string{"docker", "./deploy.sh"}) {
		t.Errorf("unsandboxed after migrate = %v", got)
	}
	eff := cfg.EffectiveDeniedCommands()
	if !slices.Contains(eff, "sudo") || slices.Contains(eff, "lite-sandbox hook") || !slices.Contains(eff, "lite-sandbox config") {
		t.Errorf("effective deny list after migrate = %v", eff)
	}
	out = captureStdout(t, func() {
		if err := configCommandsMigrateCmd.RunE(configCommandsMigrateCmd, nil); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
	})
	if !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("second migrate output = %q", out)
	}
}
