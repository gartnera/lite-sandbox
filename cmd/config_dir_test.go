package cmd

import (
	"os"
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
			if err := configCmdRun(t, configProfilesEnableCmd, "go"); err != nil {
				t.Fatalf("profiles enable go: %v", err)
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
	if cfg.Git != nil || cfg.Profiles != nil || cfg.LocalBinaryExecution != nil ||
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
	if !scoped.ProfileEnabled("go") {
		t.Error("the go profile should be on for the directory")
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
	if other.Git.GitRemoteWrite() || other.ProfileEnabled("go") || other.AuditEnabled() {
		t.Errorf("override leaked outside %s: %+v", dir, other)
	}
}

// TestConfigDir_ListsInheritBase covers the list settings: a --dir edit starts
// from what the directory resolves to today, so `add` is additive against the
// base list instead of silently replacing it. The override --dir creates is
// merge: true, so it stores only the added entry, and removing an entry the
// base states is reported rather than applied (an override can restate an
// entry, not drop it).
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

	var removeOut string
	withConfigDir(t, dir, func() {
		captureStdout(t, func() {
			if err := add.RunE(add, []string{"npm"}); err != nil {
				t.Fatalf("dir add: %v", err)
			}
		})
		removeOut = captureStdout(t, func() {
			if err := remove.RunE(remove, []string{"ninja"}); err != nil {
				t.Fatalf("dir remove: %v", err)
			}
		})
	})
	if !strings.Contains(removeOut, `ninja: "allow" in the base config still applies to /work/acme`) {
		t.Errorf("remove output = %q, want the inherited entry reported", removeOut)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.ExtraCommandList(), []string{"make", "ninja"}) {
		t.Errorf("base extra_commands = %v, want [make ninja]", cfg.ExtraCommandList())
	}
	got := cfg.ForDirectory(dir).ExtraCommandList()
	if !slices.Equal(got, []string{"make", "ninja", "npm"}) {
		t.Errorf("extra_commands for %s = %v, want [make ninja npm]", dir, got)
	}
	if o := findOverride(cfg, dir); o == nil || !o.Merge || len(o.Commands) != 1 || o.Commands[0].Command != "npm" {
		t.Errorf("override = %+v, want merge: true holding only npm", o)
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
	if !strings.Contains(out, "npm") || !strings.Contains(out, "ninja") {
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

// TestConfigDir_ClearingFallsBackToReplace: a merge: true override cannot
// clear a field (unset inherits the base's), so a new override whose change
// clears one is written replace-style. Otherwise `aws disable --dir` would
// leave the base's AWS access on, and `aws force-profile --dir` would keep the
// base's raw credentials readable.
func TestConfigDir_ClearingFallsBackToReplace(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	captureStdout(t, func() {
		if err := awsAllowRawCredentialsCmd.RunE(awsAllowRawCredentialsCmd, nil); err != nil {
			t.Fatalf("base allow-raw-credentials: %v", err)
		}
	})
	withConfigDir(t, "/work/a", func() {
		captureStdout(t, func() {
			if err := awsDisableCmd.RunE(awsDisableCmd, nil); err != nil {
				t.Fatalf("dir aws disable: %v", err)
			}
		})
	})
	withConfigDir(t, "/work/b", func() {
		captureStdout(t, func() {
			if err := awsForceProfileCmd.RunE(awsForceProfileCmd, []string{"ro"}); err != nil {
				t.Fatalf("dir aws force-profile: %v", err)
			}
		})
	})
	withConfigDir(t, "/work/c", func() {
		captureStdout(t, func() {
			if err := configCmdRun(t, configLocalBinaryExecutionEnableCmd); err != nil {
				t.Fatalf("dir local-binary-execution enable: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ForDirectory("/work/a").AWS.AWSEnabled() {
		t.Error("aws should be disabled for /work/a")
	}
	b := cfg.ForDirectory("/work/b").AWS
	if b.AllowsRawCredentials() || b.IMDSProfile() != "ro" {
		t.Errorf("aws for /work/b = %+v, want force_profile ro without raw credentials", b)
	}
	for _, dir := range []string{"/work/a", "/work/b"} {
		if o := findOverride(cfg, dir); o == nil || o.Merge {
			t.Errorf("override for %s = %+v, want replace-style", dir, o)
		}
	}
	// A change that clears nothing keeps the merge: true override.
	if o := findOverride(cfg, "/work/c"); o == nil || !o.Merge {
		t.Errorf("override for /work/c = %+v, want merge: true", o)
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

// TestConfigDir_MergeOverrideKeepsDelta: on a merge: true override the keyed
// sections inherit the base entry by entry, so a --dir edit records only what
// it changed rather than freezing a copy of the base's entries.
func TestConfigDir_MergeOverrideKeepsDelta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
paths:
  - path: /base/data
    read: true
commands:
  - command: curl
    allow: true
overrides:
  - path: /work/acme
    merge: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	withConfigDir(t, "/work/acme", func() {
		captureStdout(t, func() {
			setPathsFlags(t, true, false, false, false)
			if err := configCmdRun(t, configPathsAllowCmd, "/work/acme/out"); err != nil {
				t.Fatalf("paths allow: %v", err)
			}
			if err := configCmdRun(t, configCommandsDenyCmd, "npm"); err != nil {
				t.Fatalf("commands deny: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overrides) != 1 {
		t.Fatalf("overrides = %+v, want one", cfg.Overrides)
	}
	o := cfg.Overrides[0]
	if len(o.Paths) != 1 || o.Paths[0].Path != "/work/acme/out" {
		t.Errorf("override paths = %+v, want only the added entry", o.Paths)
	}
	if len(o.Commands) != 1 || o.Commands[0].Command != "npm" {
		t.Errorf("override commands = %+v, want only the added entry", o.Commands)
	}
	// The base's entries still reach the directory through the merge.
	scoped := cfg.ForDirectory("/work/acme/sub")
	if got := scoped.ReadablePathList(); !slices.Equal(got, []string{"/base/data"}) {
		t.Errorf("readable = %v, want the base entry inherited", got)
	}
	if got := scoped.ExpandedWritablePaths(); !slices.Equal(got, []string{"/work/acme/out"}) {
		t.Errorf("writable = %v, want the added entry", got)
	}
	if got := scoped.ExtraCommandList(); !slices.Equal(got, []string{"curl"}) {
		t.Errorf("allowed commands = %v, want the base entry inherited", got)
	}
	if got := scoped.DeniedCommandList(); !slices.Equal(got, []string{"npm"}) {
		t.Errorf("denied commands = %v, want the added entry", got)
	}
}

// TestConfigDir_MergeOverrideReportsInherited: a merge: true override can
// restate a base entry but not drop one, so removing an inherited path under
// --dir says so instead of reporting a removal that did not happen.
func TestConfigDir_MergeOverrideReportsInherited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
paths:
  - path: /base/data
    read: true
overrides:
  - path: /work/acme
    merge: true
    paths:
      - path: /work/acme/out
        write: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out string
	withConfigDir(t, "/work/acme", func() {
		out = captureStdout(t, func() {
			if err := configCmdRun(t, configPathsRemoveCmd, "/base/data"); err != nil {
				t.Fatalf("paths remove: %v", err)
			}
		})
	})
	if !strings.Contains(out, `/base/data: "read" in the base config still applies to /work/acme`) {
		t.Errorf("output = %q, want the inherited entry reported", out)
	}
	if !strings.Contains(out, "lite-sandbox config paths remove /base/data") {
		t.Errorf("output = %q, want the way to drop it everywhere", out)
	}
	if strings.Contains(out, "/base/data removed") {
		t.Errorf("output = %q, must not report a removal that did not happen", out)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/work/acme").ReadablePathList(); !slices.Equal(got, []string{"/base/data"}) {
		t.Errorf("readable = %v, want the base entry still in force", got)
	}
	// The override's own entry is untouched by the attempted removal.
	if len(cfg.Overrides) != 1 || len(cfg.Overrides[0].Paths) != 1 {
		t.Errorf("overrides = %+v, want the override's own entry kept", cfg.Overrides)
	}
}

// TestConfigDir_MergeOverrideInheritsDeprecatedKeys: a merge: true override
// inherits the deprecated one-list-per-kind keys too (they are plain leaves
// it simply does not set), so a removal it cannot carry out is reported the
// same way.
func TestConfigDir_MergeOverrideInheritsDeprecatedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
extra_commands: [curl]
overrides:
  - path: /work/acme
    merge: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out string
	withConfigDir(t, "/work/acme", func() {
		out = captureStdout(t, func() {
			if err := configCmdRun(t, configCommandsRemoveCmd, "curl"); err != nil {
				t.Fatalf("commands remove: %v", err)
			}
		})
	})
	if !strings.Contains(out, `curl: "allow" in the base config still applies to /work/acme`) {
		t.Errorf("output = %q, want the inherited entry reported", out)
	}
	if strings.Contains(out, "curl removed") {
		t.Errorf("output = %q, must not report a removal that did not happen", out)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/work/acme").ExtraCommandList(); !slices.Equal(got, []string{"curl"}) {
		t.Errorf("allowed = %v, want the base entry still in force", got)
	}
}

// TestConfigDir_MergeOverrideDeniesLiftedBuiltin: when the base lifts a
// built-in denial, a merge: true override cannot drop that lift — so denying
// the command for one directory writes the explicit denial that restates it,
// rather than the "the built-in is back" shortcut that works globally.
func TestConfigDir_MergeOverrideDeniesLiftedBuiltin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
commands:
  - command: lite-sandbox update
    allow: true
overrides:
  - path: /work/acme
    merge: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	withConfigDir(t, "/work/acme", func() {
		captureStdout(t, func() {
			if err := configCmdRun(t, configCommandsDenyCmd, "lite-sandbox update"); err != nil {
				t.Fatalf("commands deny: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if o := cfg.Overrides[0]; len(o.Commands) != 1 || !o.Commands[0].Denies() {
		t.Fatalf("override commands = %+v, want an explicit denial", o.Commands)
	}
	scoped := cfg.ForDirectory("/work/acme")
	if got := scoped.LiftedDeniedCommands(); len(got) != 0 {
		t.Errorf("lifted = %v, want the denial to have replaced the base's lift", got)
	}
	if !slices.Contains(scoped.EffectiveDeniedCommands(), "lite-sandbox update") {
		t.Errorf("effective deny list = %v, want the command denied here", scoped.EffectiveDeniedCommands())
	}
	// Elsewhere the base's lift still stands.
	if got := cfg.ForDirectory("/elsewhere").LiftedDeniedCommands(); !slices.Equal(got, []string{"lite-sandbox update"}) {
		t.Errorf("base lifted = %v, want it untouched", got)
	}
}

// TestConfigDir_RemovingLastEntryIsReported: a replace-style override (one
// written by hand; --dir creates merge: true ones) cannot record an emptied
// section (an empty list is not written), so removing the last entry leaves
// the base's list applying to the directory. That is reported, not claimed as
// a removal.
func TestConfigDir_RemovingLastEntryIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
commands:
  - command: curl
    allow: true
overrides:
  - path: /work/acme
    commands:
      - command: curl
        allow: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out string
	withConfigDir(t, "/work/acme", func() {
		out = captureStdout(t, func() {
			if err := configCmdRun(t, configCommandsRemoveCmd, "curl"); err != nil {
				t.Fatalf("commands remove: %v", err)
			}
		})
	})
	if strings.Contains(out, "curl removed") {
		t.Errorf("output = %q, must not report a removal that did not happen", out)
	}
	if !strings.Contains(out, `curl: "allow" in the base config still applies to /work/acme`) {
		t.Errorf("output = %q, want the inherited entry reported", out)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/work/acme").ExtraCommandList(); !slices.Equal(got, []string{"curl"}) {
		t.Errorf("allowed = %v, want the base entry still in force", got)
	}
}

// TestConfigDir_NewOverrideMerges: an override --dir creates is merge: true
// and records only what the command changed. It deep-merges into the base, not
// into the override the directory was inheriting from a parent, so settings
// that parent override made and the command did not touch stop applying.
func TestConfigDir_NewOverrideMerges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
mode: denylist
commands:
  - command: curl
    allow: true
overrides:
  - path: /work
    mode: allowlist
`), 0o644); err != nil {
		t.Fatal(err)
	}

	withConfigDir(t, "/work/proj", func() {
		captureStdout(t, func() {
			if err := configCmdRun(t, configCommandsAllowCmd, "make"); err != nil {
				t.Fatalf("commands allow: %v", err)
			}
		})
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	o := findOverride(cfg, "/work/proj")
	if o == nil || !o.Merge {
		t.Fatalf("override = %+v, want merge: true", o)
	}
	if len(o.Commands) != 1 || o.Commands[0].Command != "make" || o.Mode != "" {
		t.Errorf("override = %+v, want only the make entry", o)
	}
	scoped := cfg.ForDirectory("/work/proj")
	if got := scoped.ExtraCommandList(); !slices.Equal(got, []string{"curl", "make"}) {
		t.Errorf("allowed commands = %v, want the base's curl and make", got)
	}
	if got := scoped.EffectiveMode(); got != config.ModeDenylist {
		t.Errorf("mode = %s, want the base's denylist", got)
	}
	// The parent's override and the rest of ~/work are untouched.
	if got := cfg.ForDirectory("/work/other").EffectiveMode(); got != config.ModeAllowlist {
		t.Errorf("/work/other mode = %s, want allowlist", got)
	}
}

// TestConfigDir_InheritedValueLeavesNoOverride: setting a directory to what it
// already resolves to through a parent's override writes nothing.
func TestConfigDir_InheritedValueLeavesNoOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", path)
	if err := os.WriteFile(path, []byte(`
overrides:
  - path: /work
    commands:
      - command: make
        allow: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfigDir(t, "/work/proj", func() {
		captureStdout(t, func() {
			if err := configCmdRun(t, configCommandsAllowCmd, "make"); err != nil {
				t.Fatalf("commands allow: %v", err)
			}
		})
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overrides) != 1 {
		t.Fatalf("overrides = %+v, want only /work's", cfg.Overrides)
	}
}
