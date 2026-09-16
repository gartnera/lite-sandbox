package cmd

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

// withConfigDir runs fn with the shared --dir flag set, restoring it afterwards
// (the commands read the package-level flag variable, as cobra would set it).
func withConfigDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	prev := configDir
	configDir = dir
	t.Cleanup(func() { configDir = prev })
	fn()
	configDir = prev
}

// TestConfigDir_EveryCommand is the point of the shared flag: --dir is
// registered once on `config` and works for any setting under it, not just the
// handful that grew their own flag. Each case edits one section for a directory
// and checks the base is untouched while the directory resolves to the change.
func TestConfigDir_EveryCommand(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"

	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := configCmdRun(t, gitSetCmd, "remote_write", "true"); err != nil {
				t.Fatalf("git set: %v", err)
			}
			if err := configCmdRun(t, goRuntimeEnableCmd); err != nil {
				t.Fatalf("runtimes go enable: %v", err)
			}
			if err := configCmdRun(t, configLocalBinaryExecutionEnableCmd); err != nil {
				t.Fatalf("local-binary-execution enable: %v", err)
			}
			if err := configCmdRun(t, configRedundantCdDisableCmd); err != nil {
				t.Fatalf("redundant-cd disable: %v", err)
			}
			if err := configCmdRun(t, configAuditEnableCmd); err != nil {
				t.Fatalf("audit enable: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Nothing landed in the base config.
	if cfg.Git != nil || cfg.Runtimes != nil || cfg.LocalBinaryExecution != nil ||
		cfg.RejectRedundantCd != nil || cfg.Audit != nil {
		t.Fatalf("base config changed: %+v", cfg)
	}

	// One override carries all five sections.
	if len(cfg.Overrides) != 1 || cfg.Overrides[0].Path != dir {
		t.Fatalf("overrides = %+v, want a single entry for %s", cfg.Overrides, dir)
	}

	scoped := cfg.ForDirectory(filepath.Join(dir, "sub"))
	if !scoped.Git.GitRemoteWrite() {
		t.Error("git.remote_write should be on for the directory")
	}
	if !scoped.Runtimes.Go.GoEnabled() {
		t.Error("runtimes.go should be on for the directory")
	}
	if !scoped.LocalBinaryExecution.IsEnabled() {
		t.Error("local_binary_execution should be on for the directory")
	}
	if scoped.RejectsRedundantCd() {
		t.Error("reject_redundant_cd should be off for the directory")
	}
	if !scoped.AuditEnabled() {
		t.Error("audit should be on for the directory")
	}

	// Elsewhere the defaults still apply.
	other := cfg.ForDirectory("/work/other")
	if other.Git.GitRemoteWrite() || other.Runtimes != nil || other.AuditEnabled() {
		t.Errorf("override leaked outside %s: %+v", dir, other)
	}
}

// TestConfigDir_ListsInheritBase covers the list settings: a --dir edit starts
// from what the directory resolves to today, so `add` is additive against the
// base list instead of silently replacing it (the override stores the whole
// resulting list, since a section replaces its base counterpart).
func TestConfigDir_ListsInheritBase(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"

	extraCommands := findConfigSubcommand(t, "extra-commands")
	add := findSubcommand(t, extraCommands, "add")
	remove := findSubcommand(t, extraCommands, "remove")
	list := findSubcommand(t, extraCommands, "list")

	if err := add.RunE(add, []string{"make", "ninja"}); err != nil {
		t.Fatalf("base add: %v", err)
	}

	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := add.RunE(add, []string{"npm"}); err != nil {
				t.Fatalf("dir add: %v", err)
			}
			if err := remove.RunE(remove, []string{"ninja"}); err != nil {
				t.Fatalf("dir remove: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.ExtraCommandList(), []string{"make", "ninja"}) {
		t.Errorf("base extra_commands = %v, want [make ninja]", cfg.ExtraCommandList())
	}
	got := cfg.ForDirectory(dir).ExtraCommandList()
	if !slices.Equal(got, []string{"make", "npm"}) {
		t.Errorf("extra_commands for %s = %v, want [make npm]", dir, got)
	}

	// `list --dir` reports what that directory resolves to.
	var out string
	withConfigDir(t, dir, func() {
		out = captureStdout(t, func() {
			if err := list.RunE(list, nil); err != nil {
				t.Fatalf("dir list: %v", err)
			}
		})
	})
	if !strings.Contains(out, "npm") || strings.Contains(out, "ninja") {
		t.Errorf("list --dir = %q, want the directory's list", out)
	}
}

// TestConfigDir_UnchangedSectionsNotRecorded checks saveConfig records only what
// the command touched: a directory edit must not freeze the rest of the base
// config into the override.
func TestConfigDir_UnchangedSectionsNotRecorded(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"

	if err := gitSetCmd.RunE(gitSetCmd, []string{"remote_write", "true"}); err != nil {
		t.Fatalf("base git set: %v", err)
	}
	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := configLocalBinaryExecutionEnableCmd.RunE(configLocalBinaryExecutionEnableCmd, nil); err != nil {
				t.Fatalf("dir enable: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	o := findOverride(cfg, dir)
	if o == nil {
		t.Fatal("expected an override")
	}
	if o.Git != nil {
		t.Errorf("untouched git section was copied into the override: %+v", o.Git)
	}
	// The base's git setting still reaches the directory.
	if !cfg.ForDirectory(dir).Git.GitRemoteWrite() {
		t.Error("directory should inherit the base git setting")
	}
}

// TestConfigDir_NoChangeLeavesNoOverride guards against a stray empty override
// entry: setting a directory to the value it already resolves to writes nothing.
func TestConfigDir_NoChangeLeavesNoOverride(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	captureStdout(t, func() {
		if err := configRedundantCdEnableCmd.RunE(configRedundantCdEnableCmd, nil); err != nil {
			t.Fatalf("base enable: %v", err)
		}
	})
	withConfigDir(t, "/work/acme", func() {
		captureStdout(t, func() {
			if err := configRedundantCdEnableCmd.RunE(configRedundantCdEnableCmd, nil); err != nil {
				t.Fatalf("enable: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overrides) != 0 {
		t.Errorf("overrides = %+v, want none", cfg.Overrides)
	}
}

// TestConfigDir_DisableUnderDir pins the one case an override cannot express by
// clearing a section: `docker disable --dir` must store an explicitly disabled
// section, since an unset one would just inherit the enabled base.
func TestConfigDir_DisableUnderDir(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"

	captureStdout(t, func() {
		if err := dockerEnableCmd.RunE(dockerEnableCmd, nil); err != nil {
			t.Fatalf("base docker enable: %v", err)
		}
	})
	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := dockerDisableCmd.RunE(dockerDisableCmd, nil); err != nil {
				t.Fatalf("dir docker disable: %v", err)
			}
			if err := awsDisableCmd.RunE(awsDisableCmd, nil); err != nil {
				t.Fatalf("dir aws disable: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Docker.DockerEnabled() {
		t.Error("base docker should still be enabled")
	}
	if cfg.ForDirectory(dir).Docker.DockerEnabled() {
		t.Error("docker should be disabled for the directory")
	}
	if cfg.ForDirectory(dir).AWS.AWSEnabled() {
		t.Error("aws should be disabled for the directory")
	}
}

// TestConfigDir_RemoveOverride covers `config overrides remove`, the way back
// out of a --dir edit.
func TestConfigDir_RemoveOverride(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"

	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := configLocalBinaryExecutionEnableCmd.RunE(configLocalBinaryExecutionEnableCmd, nil); err != nil {
				t.Fatalf("enable: %v", err)
			}
		})
	})
	out := captureStdout(t, func() {
		if err := configOverridesRemoveCmd.RunE(configOverridesRemoveCmd, []string{dir}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	if !strings.Contains(out, dir) {
		t.Errorf("remove output = %q", out)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overrides) != 0 {
		t.Errorf("overrides = %+v, want none", cfg.Overrides)
	}
}

// TestConfigDir_Rejected checks the commands that have nothing to scope say so
// instead of ignoring the flag.
func TestConfigDir_Rejected(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	withConfigDir(t, "/work/acme", func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err == nil {
			t.Error("config path should reject --dir")
		}
	})
}

// TestConfigDir_FlagRegisteredOnce is the regression guard for the report that
// started this: `config extra-commands add npm --dir .` failed with "unknown
// flag". The flag is persistent on `config`, so every subcommand parses it —
// checked here by running the real command line through cobra.
func TestConfigDir_FlagRegisteredOnce(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { configDir = "" })

	captureStdout(t, func() {
		if err := runRootCmd(t, "config", "extra-commands", "add", "npm", "--dir", "/work/acme"); err != nil {
			t.Fatalf("add --dir: %v", err)
		}
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/work/acme").ExtraCommandList(); !slices.Equal(got, []string{"npm"}) {
		t.Errorf("extra_commands for the directory = %v, want [npm]", got)
	}
	if len(cfg.ExtraCommandList()) != 0 {
		t.Errorf("base extra_commands = %v, want none", cfg.ExtraCommandList())
	}

	// Every runnable command under `config` inherits the same flag.
	var missing []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.Runnable() && sub.InheritedFlags().Lookup("dir") == nil {
				missing = append(missing, sub.CommandPath())
			}
			walk(sub)
		}
	}
	walk(configCmd)
	if len(missing) > 0 {
		t.Errorf("subcommands without --dir: %v", missing)
	}
}

// runRootCmd executes the real CLI command line, so flag parsing (not just the
// RunE body) is exercised. Cobra keeps parsed flags on the command, so the
// caller resets what it set.
func runRootCmd(t *testing.T, args ...string) error {
	t.Helper()
	rootCmd.SetArgs(args)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	return rootCmd.Execute()
}

// configCmdRun runs a command's RunE with the given args, failing the test if
// the command has none.
func configCmdRun(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	if cmd.RunE == nil {
		t.Fatalf("%s has no RunE", cmd.CommandPath())
	}
	return cmd.RunE(cmd, args)
}

// findConfigSubcommand returns the `config <name>` command, which the string
// list settings build dynamically rather than exporting a variable for.
func findConfigSubcommand(t *testing.T, name string) *cobra.Command {
	t.Helper()
	return findSubcommand(t, configCmd, name)
}

func findSubcommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("%s has no %q subcommand", parent.CommandPath(), name)
	return nil
}
