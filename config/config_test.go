package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPath(t *testing.T) {
	p, err := Path()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(p) != "config.yaml" {
		t.Fatalf("expected config.yaml, got %s", filepath.Base(p))
	}
	if filepath.Base(filepath.Dir(p)) != appName {
		t.Fatalf("expected parent dir %s, got %s", appName, filepath.Base(filepath.Dir(p)))
	}
}

func TestLoadSave(t *testing.T) {
	// Override the config path to a temp dir.
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	// Load should return zero-value config when file doesn't exist.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExtraCommands) != 0 {
		t.Fatalf("expected empty extra commands, got %v", cfg.ExtraCommands)
	}

	// Save and reload.
	cfg.ExtraCommands = []string{"curl", "wget"}
	cfg.UnsandboxedCommands = []string{"docker"}
	if err := Save(cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	cfg2, err := Load()
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if len(cfg2.ExtraCommands) != 2 || cfg2.ExtraCommands[0] != "curl" || cfg2.ExtraCommands[1] != "wget" {
		t.Fatalf("expected [curl wget], got %v", cfg2.ExtraCommands)
	}
	if len(cfg2.UnsandboxedCommands) != 1 || cfg2.UnsandboxedCommands[0] != "docker" {
		t.Fatalf("expected [docker], got %v", cfg2.UnsandboxedCommands)
	}
}

func TestLoadUnknownFields(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	data := []byte("extra_commands:\n  - curl\nfuture_field: value\n")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExtraCommands) != 1 || cfg.ExtraCommands[0] != "curl" {
		t.Fatalf("expected [curl], got %v", cfg.ExtraCommands)
	}
}

func TestExpandedReadablePaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	cfg := &Config{
		ReadablePaths: []string{"~/Documents", "/tmp/shared"},
	}
	got := cfg.ExpandedReadablePaths()
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(got), got)
	}
	if got[0] != filepath.Join(home, "Documents") {
		t.Fatalf("expected %s, got %s", filepath.Join(home, "Documents"), got[0])
	}
	if got[1] != "/tmp/shared" {
		t.Fatalf("expected /tmp/shared, got %s", got[1])
	}
}

func TestExpandedWritablePaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	cfg := &Config{
		WritablePaths: []string{"~", "~/Projects"},
	}
	got := cfg.ExpandedWritablePaths()
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(got), got)
	}
	if got[0] != home {
		t.Fatalf("expected %s, got %s", home, got[0])
	}
	if got[1] != filepath.Join(home, "Projects") {
		t.Fatalf("expected %s, got %s", filepath.Join(home, "Projects"), got[1])
	}
}

func TestExpandedPaths_Empty(t *testing.T) {
	cfg := &Config{}
	if got := cfg.ExpandedReadablePaths(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := cfg.ExpandedWritablePaths(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestWatch(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changed := make(chan *Config, 1)
	go func() {
		_ = Watch(ctx, func(cfg *Config) {
			changed <- cfg
		})
	}()

	// Give the watcher time to start.
	time.Sleep(100 * time.Millisecond)

	// Write a config file to trigger the watcher.
	cfg := &Config{ExtraCommands: []string{"python3"}}
	if err := Save(cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	// fsnotify may deliver the Create event before the file content is
	// written, producing a notification with an empty config first. Wait for
	// the notification that carries the saved config rather than asserting on
	// the first one.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-changed:
			if len(got.ExtraCommands) == 1 && got.ExtraCommands[0] == "python3" {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for config change notification with saved content")
		}
	}
}

func TestGitConfig_AllowsWorktreeParent(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	tests := []struct {
		name string
		cfg  *GitConfig
		want bool
	}{
		{"nil config", nil, false},
		{"unset", &GitConfig{}, false},
		{"true", &GitConfig{AllowWorktreeParent: bp(true)}, true},
		{"false", &GitConfig{AllowWorktreeParent: bp(false)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.AllowsWorktreeParent(); got != tt.want {
				t.Errorf("AllowsWorktreeParent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSConfig_ForDirectory(t *testing.T) {
	bp := func(b bool) *bool { return &b }

	cfg := &AWSConfig{
		ForceProfile: "default",
		Overrides: []AWSDirectoryOverride{
			{Path: "/work/projects", ForceProfile: "team"},
			{Path: "/work/projects/secure", ForceProfile: "secure"},
			{Path: "/work/raw", AllowRawCredentials: bp(true)},
		},
	}

	tests := []struct {
		name         string
		dir          string
		wantProfile  string
		wantUsesIMDS bool
		wantRaw      bool
	}{
		{"no match uses base", "/other/place", "default", true, false},
		{"exact match", "/work/projects", "team", true, false},
		{"subdir inherits override", "/work/projects/app", "team", true, false},
		{"most specific override wins", "/work/projects/secure/db", "secure", true, false},
		{"override switches to raw mode", "/work/raw/svc", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cfg.ForDirectory(tt.dir)
			if got.IMDSProfile() != tt.wantProfile {
				t.Errorf("IMDSProfile() = %q, want %q", got.IMDSProfile(), tt.wantProfile)
			}
			if got.UsesIMDS() != tt.wantUsesIMDS {
				t.Errorf("UsesIMDS() = %v, want %v", got.UsesIMDS(), tt.wantUsesIMDS)
			}
			if got.AllowsRawCredentials() != tt.wantRaw {
				t.Errorf("AllowsRawCredentials() = %v, want %v", got.AllowsRawCredentials(), tt.wantRaw)
			}
			// The resolved config must not carry overrides itself.
			if len(got.Overrides) != 0 {
				t.Errorf("resolved config carried %d overrides, want 0", len(got.Overrides))
			}
		})
	}
}

func TestAWSConfig_ForDirectory_Nil(t *testing.T) {
	var cfg *AWSConfig
	if got := cfg.ForDirectory("/anywhere"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestAWSConfig_ForDirectory_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}
	cfg := &AWSConfig{
		ForceProfile: "default",
		Overrides:    []AWSDirectoryOverride{{Path: "~/work", ForceProfile: "home-work"}},
	}
	got := cfg.ForDirectory(filepath.Join(home, "work", "sub"))
	if got.IMDSProfile() != "home-work" {
		t.Fatalf("IMDSProfile() = %q, want home-work", got.IMDSProfile())
	}
}

func TestLocalBinaryExecutionConfig_IsEnabled(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name string
		cfg  *LocalBinaryExecutionConfig
		want bool
	}{
		{"nil config", nil, false},
		{"nil enabled field", &LocalBinaryExecutionConfig{}, false},
		{"enabled true", &LocalBinaryExecutionConfig{Enabled: boolPtr(true)}, true},
		{"enabled false", &LocalBinaryExecutionConfig{Enabled: boolPtr(false)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
