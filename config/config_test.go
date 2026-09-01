package config

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

func TestExpandedInternalPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	cfg := &Config{
		InternalReadablePaths: []string{"~/.config/some-tool", "/opt/data"},
		InternalWritablePaths: []string{"~/.cache"},
	}
	gotRead := cfg.ExpandedInternalReadablePaths()
	if len(gotRead) != 2 || gotRead[0] != filepath.Join(home, ".config/some-tool") || gotRead[1] != "/opt/data" {
		t.Fatalf("unexpected internal readable paths: %v", gotRead)
	}
	gotWrite := cfg.ExpandedInternalWritablePaths()
	if len(gotWrite) != 1 || gotWrite[0] != filepath.Join(home, ".cache") {
		t.Fatalf("unexpected internal writable paths: %v", gotWrite)
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
	if got := cfg.ExpandedInternalReadablePaths(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := cfg.ExpandedInternalWritablePaths(); got != nil {
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

func TestConfig_ForDirectory_AWS(t *testing.T) {
	bp := func(b bool) *bool { return &b }

	cfg := &Config{
		AWS: &AWSConfig{ForceProfile: "default"},
		Overrides: []DirectoryOverride{
			{Path: "/work/projects", Config: Config{AWS: &AWSConfig{ForceProfile: "team"}}},
			{Path: "/work/projects/secure", Config: Config{AWS: &AWSConfig{ForceProfile: "secure"}}},
			{Path: "/work/raw", Config: Config{AWS: &AWSConfig{AllowRawCredentials: bp(true)}}},
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
			got := cfg.ForDirectory(tt.dir).AWS
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
			if len(cfg.ForDirectory(tt.dir).Overrides) != 0 {
				t.Errorf("resolved config carried overrides, want 0")
			}
		})
	}
}

func TestConfig_ForDirectory_Nil(t *testing.T) {
	var cfg *Config
	if got := cfg.ForDirectory("/anywhere"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestConfig_ForDirectory_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}
	cfg := &Config{
		AWS:       &AWSConfig{ForceProfile: "default"},
		Overrides: []DirectoryOverride{{Path: "~/work", Config: Config{AWS: &AWSConfig{ForceProfile: "home-work"}}}},
	}
	got := cfg.ForDirectory(filepath.Join(home, "work", "sub")).AWS
	if got.IMDSProfile() != "home-work" {
		t.Fatalf("IMDSProfile() = %q, want home-work", got.IMDSProfile())
	}
}

// TestConfig_ForDirectory_AnySection verifies the override mechanism is generic:
// sections other than AWS (here writable_paths and os_sandbox) are overridden
// per directory too, and only the sections an override sets are replaced while
// the rest are inherited from the base.
func TestConfig_ForDirectory_AnySection(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	cfg := &Config{
		WritablePaths: []string{"/base"},
		OSSandbox:     bp(false),
		AWS:           &AWSConfig{ForceProfile: "default"},
		Overrides: []DirectoryOverride{
			{Path: "/work", Config: Config{
				WritablePaths: []string{"/work/out"},
				OSSandbox:     bp(true),
			}},
		},
	}

	// Outside the override: base everywhere.
	base := cfg.ForDirectory("/elsewhere")
	if !slices.Equal(base.WritablePaths, []string{"/base"}) || base.OSSandboxEnabled() {
		t.Fatalf("base dir = {writable:%v os_sandbox:%v}, want {[/base] false}", base.WritablePaths, base.OSSandboxEnabled())
	}

	// Inside the override: the set sections are replaced, AWS is inherited.
	over := cfg.ForDirectory("/work/svc")
	if !slices.Equal(over.WritablePaths, []string{"/work/out"}) {
		t.Errorf("override WritablePaths = %v, want [/work/out]", over.WritablePaths)
	}
	if !over.OSSandboxEnabled() {
		t.Error("override should enable os_sandbox")
	}
	if over.AWS.IMDSProfile() != "default" {
		t.Errorf("override AWS = %q, want inherited default", over.AWS.IMDSProfile())
	}
}

func TestAWSConfig_IMDSProfiles(t *testing.T) {
	// Off when IMDS mode is off.
	off := &AWSConfig{}
	if got := off.IMDSProfiles(); got != nil {
		t.Errorf("IMDSProfiles() with no force_profile = %v, want nil", got)
	}

	// Default first, then allowed, de-duplicated (default and a repeat dropped).
	cfg := &AWSConfig{ForceProfile: "default", AllowedProfiles: []string{"dev", "default", "prod", "dev"}}
	got := cfg.IMDSProfiles()
	want := []string{"default", "dev", "prod"}
	if !slices.Equal(got, want) {
		t.Errorf("IMDSProfiles() = %v, want %v", got, want)
	}
}

func TestConfig_ForDirectory_AllowedProfiles(t *testing.T) {
	cfg := &Config{
		AWS: &AWSConfig{
			ForceProfile:    "default",
			AllowedProfiles: []string{"dev"},
		},
		Overrides: []DirectoryOverride{
			{Path: "/work/multi", Config: Config{AWS: &AWSConfig{ForceProfile: "team", AllowedProfiles: []string{"team-dev", "team-prod"}}}},
		},
	}

	// Base carries its allowed_profiles.
	if got := cfg.ForDirectory("/elsewhere").AWS.AllowedProfiles; !slices.Equal(got, []string{"dev"}) {
		t.Errorf("base AllowedProfiles = %v, want [dev]", got)
	}
	// Override replaces (does not merge) the allowed set.
	got := cfg.ForDirectory("/work/multi/app").AWS
	if got.IMDSProfile() != "team" {
		t.Errorf("override IMDSProfile() = %q, want team", got.IMDSProfile())
	}
	if !slices.Equal(got.AllowedProfiles, []string{"team-dev", "team-prod"}) {
		t.Errorf("override AllowedProfiles = %v, want [team-dev team-prod]", got.AllowedProfiles)
	}
	// Override replaces rather than merges, so the base 'dev' profile is gone and
	// only the override's profiles feed IMDSProfiles.
	if slices.Contains(got.AllowedProfiles, "dev") {
		t.Error("override should not inherit base allowed profile 'dev'")
	}
	if want := []string{"team", "team-dev", "team-prod"}; !slices.Equal(got.IMDSProfiles(), want) {
		t.Errorf("override IMDSProfiles() = %v, want %v", got.IMDSProfiles(), want)
	}
}

func TestConfig_ForDirectory_DeepMerge(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	cfg := &Config{
		Docker: &DockerConfig{Enabled: bp(true), SocketPath: "/base.sock"},
		AWS:    &AWSConfig{ForceProfile: "default", AllowedProfiles: []string{"dev"}},
		Overrides: []DirectoryOverride{
			{Path: "/replace", Config: Config{
				// Replace mode: whole docker section replaced, so Enabled is lost.
				Docker: &DockerConfig{AllowPrivileged: bp(true)},
			}},
			{Path: "/merge", Merge: true, Config: Config{
				// Deep merge: only allow_privileged changes; enabled/socket kept.
				Docker: &DockerConfig{AllowPrivileged: bp(true)},
			}},
		},
	}

	// Replace mode drops the base docker fields the override didn't restate.
	rep := cfg.ForDirectory("/replace/app").Docker
	if rep.DockerEnabled() {
		t.Error("replace mode should not inherit base docker.enabled")
	}
	if !rep.AllowsPrivileged() {
		t.Error("replace mode should apply override docker.allow_privileged")
	}

	// Deep merge keeps base docker fields and layers the override's field on top.
	mrg := cfg.ForDirectory("/merge/app").Docker
	if !mrg.DockerEnabled() {
		t.Error("deep merge should inherit base docker.enabled")
	}
	if mrg.UpstreamSocket() != "/base.sock" {
		t.Errorf("deep merge should inherit base docker.socket_path, got %q", mrg.UpstreamSocket())
	}
	if !mrg.AllowsPrivileged() {
		t.Error("deep merge should apply override docker.allow_privileged")
	}

	// Sections the merge override doesn't mention are inherited whole.
	if got := cfg.ForDirectory("/merge/app").AWS.IMDSProfile(); got != "default" {
		t.Errorf("deep merge should inherit base aws, got profile %q", got)
	}

	// Critical: deep merge must NOT mutate the stored base config.
	if cfg.Docker.AllowsPrivileged() {
		t.Fatal("deep merge leaked into the stored base docker config")
	}
	if !cfg.Docker.DockerEnabled() || cfg.Docker.UpstreamSocket() != "/base.sock" {
		t.Fatal("stored base docker config was altered by deep merge")
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
