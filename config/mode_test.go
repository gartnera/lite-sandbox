package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	for _, m := range Modes {
		got, err := ParseMode(string(m))
		if err != nil || got != m {
			t.Errorf("ParseMode(%q) = %q, %v", m, got, err)
		}
	}
	if _, err := ParseMode("strict"); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestEffectiveMode_Default(t *testing.T) {
	var nilCfg *Config
	if got := nilCfg.EffectiveMode(); got != ModeAllowlist {
		t.Errorf("nil config mode = %q, want allowlist", got)
	}
	if got := (&Config{}).EffectiveMode(); got != ModeAllowlist {
		t.Errorf("empty config mode = %q, want allowlist", got)
	}
	if got := (&Config{Mode: "denylist"}).EffectiveMode(); got != ModeDenylist {
		t.Errorf("mode = %q, want denylist", got)
	}
	// An invalid value set in code (never from Load) falls back to the default.
	if got := (&Config{Mode: "bogus"}).EffectiveMode(); got != ModeAllowlist {
		t.Errorf("invalid mode = %q, want allowlist fallback", got)
	}
}

func TestAuditEnabled_Default(t *testing.T) {
	if (&Config{}).AuditEnabled() {
		t.Error("audit should default to off")
	}
	on := true
	if !(&Config{Audit: &on}).AuditEnabled() {
		t.Error("audit: true should enable")
	}
}

func TestLoad_RejectsInvalidMode(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)
	if err := os.WriteFile(configPath, []byte("mode: strict\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("expected invalid mode error, got %v", err)
	}

	// Same for an override's mode.
	if err := os.WriteFile(configPath, []byte("overrides:\n  - path: /work\n    mode: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("expected invalid override mode error, got %v", err)
	}
}

func TestLoadSave_ModeAndAudit(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)
	on := true
	if err := Save(&Config{Mode: "denylist", Audit: &on, DeniedReadPaths: []string{"~/secrets"}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveMode() != ModeDenylist || !cfg.AuditEnabled() {
		t.Errorf("round trip: mode=%q audit=%v", cfg.EffectiveMode(), cfg.AuditEnabled())
	}
	home, _ := os.UserHomeDir()
	if !slices.Contains(cfg.EffectiveDeniedReadPaths(), filepath.Join(home, "secrets")) {
		t.Errorf("denied_read_paths not expanded/merged: %v", cfg.EffectiveDeniedReadPaths())
	}
}

func TestForDirectory_ModeOverride(t *testing.T) {
	cfg := &Config{
		Mode: "allowlist",
		Overrides: []DirectoryOverride{
			{Path: "/scratch", Config: Config{Mode: "open"}},
			{Path: "/trusted", Merge: true, Config: Config{Mode: "denylist"}},
		},
	}
	if got := cfg.ForDirectory("/elsewhere").EffectiveMode(); got != ModeAllowlist {
		t.Errorf("base mode = %q", got)
	}
	if got := cfg.ForDirectory("/scratch/x").EffectiveMode(); got != ModeOpen {
		t.Errorf("replace override mode = %q, want open", got)
	}
	if got := cfg.ForDirectory("/trusted").EffectiveMode(); got != ModeDenylist {
		t.Errorf("merge override mode = %q, want denylist", got)
	}
	// An override that sets no mode inherits the base.
	cfg.Overrides = append(cfg.Overrides, DirectoryOverride{Path: "/other", Config: Config{WritablePaths: []string{"/other/out"}}})
	if got := cfg.ForDirectory("/other").EffectiveMode(); got != ModeAllowlist {
		t.Errorf("inherit mode = %q, want allowlist", got)
	}
}

func TestDefaultDeniedPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	read := deniedPathStrings(DefaultDeniedReadPaths())
	for _, want := range []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".netrc"),
	} {
		if !slices.Contains(read, want) {
			t.Errorf("read-denied defaults missing %s: %v", want, read)
		}
	}
	write := deniedPathStrings(DefaultDeniedWritePaths())
	for _, want := range []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".local", "bin"),
		configPath, // the sandbox's own config is self-protected
	} {
		if !slices.Contains(write, want) {
			t.Errorf("write-denied defaults missing %s: %v", want, write)
		}
	}
	// Nothing should be in both lists: a read-denied path is already unwritable.
	for _, p := range read {
		if slices.Contains(write, p) {
			t.Errorf("%s is in both deny lists", p)
		}
	}
	// Directory vs file kinds drive whether a missing entry is created.
	for _, e := range DefaultDeniedWritePaths() {
		switch filepath.Base(e.Path) {
		case ".ssh", "bin", "user":
			if !e.Dir {
				t.Errorf("%s should be a directory entry", e.Path)
			}
		case ".bashrc", ".gitconfig":
			if e.Dir {
				t.Errorf("%s should be a file entry", e.Path)
			}
		}
	}
}

func TestDefaultDeniedPaths_AgentEntriesOnlyWhenInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	// No agent installed: none of their paths are listed (so none get created).
	for _, p := range deniedPathStrings(append(DefaultDeniedReadPaths(), DefaultDeniedWritePaths()...)) {
		if strings.Contains(p, ".claude") || strings.Contains(p, ".codex") || strings.Contains(p, "opencode") || strings.Contains(p, "crush") {
			t.Errorf("agent path %s listed without the agent installed", p)
		}
	}

	// Claude installed: its credentials, settings, and instruction dirs appear.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	read := deniedPathStrings(DefaultDeniedReadPaths())
	write := deniedPathStrings(DefaultDeniedWritePaths())
	for _, want := range []string{filepath.Join(home, ".claude.json"), filepath.Join(home, ".claude", ".credentials.json")} {
		if !slices.Contains(read, want) {
			t.Errorf("read-denied missing %s: %v", want, read)
		}
	}
	for _, want := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude", "skills")} {
		if !slices.Contains(write, want) {
			t.Errorf("write-denied missing %s: %v", want, write)
		}
	}
}

func TestDefaultDeniedPaths_HonorAgentEnv(t *testing.T) {
	root := t.TempDir()
	cc, cx, xdg := filepath.Join(root, "cc"), filepath.Join(root, "cx"), filepath.Join(root, "xdg")
	for _, d := range []string{cc, cx, filepath.Join(xdg, "opencode"), filepath.Join(xdg, "crush")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CLAUDE_CONFIG_DIR", cc)
	t.Setenv("CODEX_HOME", cx)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	read := deniedPathStrings(DefaultDeniedReadPaths())
	for _, want := range []string{cc + "/.claude.json", cc + "/.credentials.json", cx + "/auth.json", xdg + "/gh"} {
		if !slices.Contains(read, want) {
			t.Errorf("read-denied defaults missing %s: %v", want, read)
		}
	}
	write := deniedPathStrings(DefaultDeniedWritePaths())
	for _, want := range []string{cc + "/settings.json", cx + "/config.toml", xdg + "/opencode/opencode.json", xdg + "/crush/crushrc", xdg + "/git/config"} {
		if !slices.Contains(write, want) {
			t.Errorf("write-denied defaults missing %s: %v", want, write)
		}
	}
}

func TestEffectiveDeniedEntries_UserAdditionsClassified(t *testing.T) {
	tmp := t.TempDir()
	d := filepath.Join(tmp, "secrets")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(tmp, "token")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{DeniedReadPaths: []string{d, f, filepath.Join(tmp, "missing")}}
	kinds := map[string]bool{}
	for _, e := range cfg.EffectiveDeniedReadEntries() {
		kinds[e.Path] = e.Dir
	}
	if !kinds[d] {
		t.Errorf("%s should be classified as a directory", d)
	}
	if isDir, ok := kinds[f]; !ok || isDir {
		t.Errorf("%s should be a file entry (present=%v dir=%v)", f, ok, isDir)
	}
	// A missing user path is a file entry, so the worker never creates it.
	if isDir, ok := kinds[filepath.Join(tmp, "missing")]; !ok || isDir {
		t.Errorf("missing user path should be listed as a file entry (present=%v dir=%v)", ok, isDir)
	}
}

func TestEffectiveDeniedReadPaths_RawAWSCredentials(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	aws := filepath.Join(home, ".aws")
	if !slices.Contains((&Config{}).EffectiveDeniedReadPaths(), aws) {
		t.Fatal("~/.aws should be read-denied by default")
	}
	raw := true
	cfg := &Config{AWS: &AWSConfig{AllowRawCredentials: &raw}}
	if slices.Contains(cfg.EffectiveDeniedReadPaths(), aws) {
		t.Error("~/.aws must stay readable when allow_raw_credentials is set")
	}
	// IMDS mode keeps it denied (the worker masks it anyway).
	cfg = &Config{AWS: &AWSConfig{ForceProfile: "dev"}}
	if !slices.Contains(cfg.EffectiveDeniedReadPaths(), aws) {
		t.Error("~/.aws should stay read-denied in IMDS mode")
	}
}
