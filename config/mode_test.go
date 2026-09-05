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

	read := DefaultDeniedReadPaths()
	for _, want := range []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude", ".credentials.json"),
		filepath.Join(home, ".codex", "auth.json"),
	} {
		if !slices.Contains(read, want) {
			t.Errorf("read-denied defaults missing %s: %v", want, read)
		}
	}
	write := DefaultDeniedWritePaths()
	for _, want := range []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".codex", "config.toml"),
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
}

func TestDefaultDeniedPaths_HonorAgentEnv(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "/cc")
	t.Setenv("CODEX_HOME", "/cx")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	read := DefaultDeniedReadPaths()
	for _, want := range []string{"/cc/.claude.json", "/cc/.credentials.json", "/cx/auth.json", "/xdg/gh"} {
		if !slices.Contains(read, want) {
			t.Errorf("read-denied defaults missing %s: %v", want, read)
		}
	}
	write := DefaultDeniedWritePaths()
	for _, want := range []string{"/cc/settings.json", "/cx/config.toml", "/xdg/opencode/opencode.json", "/xdg/crush/crushrc"} {
		if !slices.Contains(write, want) {
			t.Errorf("write-denied defaults missing %s: %v", want, write)
		}
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
