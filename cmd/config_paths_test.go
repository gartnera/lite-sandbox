package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// setPathsFlags pins the package-level flag variables the paths commands read
// (cobra would set them from argv) and restores them afterwards.
func setPathsFlags(t *testing.T, allowWrite, allowInternal, denyRead, denyWrite bool) {
	t.Helper()
	pw, pi, dr, dw := pathsAllowWrite, pathsAllowInternal, pathsDenyRead, pathsDenyWrite
	pathsAllowWrite, pathsAllowInternal, pathsDenyRead, pathsDenyWrite = allowWrite, allowInternal, denyRead, denyWrite
	t.Cleanup(func() { pathsAllowWrite, pathsAllowInternal, pathsDenyRead, pathsDenyWrite = pw, pi, dr, dw })
}

func TestConfigPathsCmd(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	out := captureStdout(t, func() {
		setPathsFlags(t, false, false, false, false)
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/ref"}); err != nil {
			t.Fatalf("allow: %v", err)
		}
		setPathsFlags(t, true, false, false, false)
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/scratch"}); err != nil {
			t.Fatalf("allow --write: %v", err)
		}
		setPathsFlags(t, true, true, false, false)
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/cache/tool"}); err != nil {
			t.Fatalf("allow --write --internal: %v", err)
		}
		setPathsFlags(t, false, false, false, false)
		if err := configPathsDenyCmd.RunE(configPathsDenyCmd, []string{"/secrets"}); err != nil {
			t.Fatalf("deny: %v", err)
		}
		setPathsFlags(t, false, false, false, true)
		if err := configPathsDenyCmd.RunE(configPathsDenyCmd, []string{"/ro"}); err != nil {
			t.Fatalf("deny --write: %v", err)
		}
	})
	if !strings.Contains(out, "/scratch: read, write") || !strings.Contains(out, "/secrets: deny read") || !strings.Contains(out, "/ro: deny write") {
		t.Errorf("confirmation output = %q", out)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsesDeprecatedPathKeys() {
		t.Error("the CLI must write the new section only")
	}
	if got := cfg.ExpandedReadablePaths(); !slices.Equal(got, []string{"/ref"}) {
		t.Errorf("readable = %v", got)
	}
	if got := cfg.ExpandedWritablePaths(); !slices.Equal(got, []string{"/scratch"}) {
		t.Errorf("writable = %v", got)
	}
	if got := cfg.ExpandedInternalWritablePaths(); !slices.Equal(got, []string{"/cache/tool"}) {
		t.Errorf("internal writable = %v", got)
	}
	if got := cfg.DeniedReadPathList(); !slices.Equal(got, []string{"/secrets"}) {
		t.Errorf("denied read = %v", got)
	}
	if got := cfg.DeniedWritePathList(); !slices.Equal(got, []string{"/ro"}) {
		t.Errorf("denied write = %v", got)
	}

	// The file is the compact form: one entry per path.
	data, _ := os.ReadFile(os.Getenv("LITE_SANDBOX_CONFIG"))
	if !strings.Contains(string(data), "paths:\n") || strings.Count(string(data), "- path:") != 5 {
		t.Errorf("config file:\n%s", data)
	}

	// allow on an existing path replaces its statement (upgrade read -> write).
	captureStdout(t, func() {
		setPathsFlags(t, true, false, false, false)
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/ref"}); err != nil {
			t.Fatalf("allow upgrade: %v", err)
		}
	})
	cfg, _ = config.Load()
	if len(cfg.Paths) != 5 || cfg.ExpandedReadablePaths() != nil || !slices.Contains(cfg.ExpandedWritablePaths(), "/ref") {
		t.Errorf("after upgrade: %+v", cfg.Paths)
	}

	out = captureStdout(t, func() {
		if err := configPathsListCmd.RunE(configPathsListCmd, nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	for _, want := range []string{"/scratch", "read, write", "/cache/tool", "internal", "/secrets", "deny read", "/ro", "deny write"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "deprecated") {
		t.Errorf("list should not mention deprecated keys for a new-style config:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := configPathsRemoveCmd.RunE(configPathsRemoveCmd, []string{"/secrets", "/nope"}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	if !strings.Contains(out, "/secrets removed") || !strings.Contains(out, "/nope is not configured") {
		t.Errorf("remove output = %q", out)
	}
	cfg, _ = config.Load()
	if cfg.DeniedReadPathList() != nil || len(cfg.Paths) != 4 {
		t.Errorf("after remove: %+v", cfg.Paths)
	}
}

// TestConfigPathsCmd_Dir: with --dir the edit starts from what the directory
// resolves to, so allow extends the base's list in the override and the base is
// left alone.
func TestConfigPathsCmd_Dir(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	const dir = "/work/acme"
	captureStdout(t, func() {
		setPathsFlags(t, true, false, false, false)
		if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/base-scratch"}); err != nil {
			t.Fatalf("base allow: %v", err)
		}
		withConfigDir(t, dir, func() {
			if err := configPathsAllowCmd.RunE(configPathsAllowCmd, []string{"/work/acme/out"}); err != nil {
				t.Fatalf("dir allow: %v", err)
			}
		})
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExpandedWritablePaths(); !slices.Equal(got, []string{"/base-scratch"}) {
		t.Errorf("base writable = %v", got)
	}
	got := cfg.ForDirectory(filepath.Join(dir, "sub")).ExpandedWritablePaths()
	if !slices.Equal(got, []string{"/base-scratch", "/work/acme/out"}) {
		t.Errorf("writable for %s = %v", dir, got)
	}
	if len(cfg.Overrides) != 1 || len(cfg.Overrides[0].Paths) != 2 {
		t.Errorf("overrides = %+v", cfg.Overrides)
	}
}

// TestConfigPathsCmd_DeprecatedAliasesAndMigrate: the six former commands still
// work (hidden, writing the new form), list flags old-style keys, and migrate
// rewrites them.
func TestConfigPathsCmd_DeprecatedAliasesAndMigrate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte("readable_paths: [/old]\ndenied_write_paths: [/old-ro]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := configPathsListCmd.RunE(configPathsListCmd, nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "/old") || !strings.Contains(out, "(deprecated key)") || !strings.Contains(out, "paths migrate") {
		t.Errorf("list with old keys = %q", out)
	}

	for _, name := range []string{"readable-paths", "writable-paths", "internal-readable-paths", "internal-writable-paths", "denied-read-paths", "denied-write-paths"} {
		c := findConfigSubcommand(t, name)
		if !c.Hidden {
			t.Errorf("%s should be hidden", name)
		}
		for _, sub := range c.Commands() {
			if sub.Deprecated == "" {
				t.Errorf("%s %s should carry a deprecation notice", name, sub.Name())
			}
		}
	}
	writable := findConfigSubcommand(t, "writable-paths")
	add := findSubcommand(t, writable, "add")
	captureStdout(t, func() {
		if err := add.RunE(add, []string{"/via-alias"}); err != nil {
			t.Fatalf("alias add: %v", err)
		}
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExpandedWritablePaths(); !slices.Equal(got, []string{"/via-alias"}) {
		t.Errorf("alias add wrote %v", got)
	}
	if cfg.WritablePaths != nil {
		t.Error("alias should write a paths entry, not the old key")
	}
	list := findSubcommand(t, findConfigSubcommand(t, "readable-paths"), "list")
	out = captureStdout(t, func() {
		if err := list.RunE(list, nil); err != nil {
			t.Fatalf("alias list: %v", err)
		}
	})
	if strings.TrimSpace(out) != "/old" {
		t.Errorf("alias list = %q, want the old readable entry only", out)
	}

	out = captureStdout(t, func() {
		if err := configPathsMigrateCmd.RunE(configPathsMigrateCmd, nil); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	})
	if !strings.Contains(out, "Rewrote 2 path entries") {
		t.Errorf("migrate output = %q", out)
	}
	cfg, _ = config.Load()
	if cfg.UsesDeprecatedPathKeys() {
		t.Error("old keys remain after migrate")
	}
	if got := cfg.ExpandedReadablePaths(); !slices.Equal(got, []string{"/old"}) {
		t.Errorf("readable after migrate = %v", got)
	}
	if got := cfg.DeniedWritePathList(); !slices.Equal(got, []string{"/old-ro"}) {
		t.Errorf("denied write after migrate = %v", got)
	}
	out = captureStdout(t, func() {
		if err := configPathsMigrateCmd.RunE(configPathsMigrateCmd, nil); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
	})
	if !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("second migrate output = %q", out)
	}
	withConfigDir(t, "/x", func() {
		if err := configPathsMigrateCmd.RunE(configPathsMigrateCmd, nil); err == nil {
			t.Error("migrate should reject --dir")
		}
	})
}
