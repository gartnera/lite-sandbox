package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProfileEntry_YAMLForms(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte(`
profiles:
  - go
  - name: deno
    options:
      allow_network: true
  - name: montypython
    enabled: false
`), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.validateProfiles(); err != nil {
		t.Fatal(err)
	}
	if !cfg.ProfileEnabled("go") || !cfg.ProfileEnabled("deno") || cfg.ProfileEnabled("montypython") {
		t.Errorf("enabled = go:%v deno:%v montypython:%v", cfg.ProfileEnabled("go"), cfg.ProfileEnabled("deno"), cfg.ProfileEnabled("montypython"))
	}
	if cfg.ProfileEnabled("rust") {
		t.Error("an unlisted profile must stay off")
	}
	if !cfg.ProfileOption("deno", "allow_network") || !cfg.ProfileOption("deno", "auto_sandbox") {
		t.Error("deno options: set allow_network, default auto_sandbox should both read true")
	}

	// An entry that only enables its profile is written back as the bare name.
	out, err := yaml.Marshal(&Config{Profiles: cfg.Profiles})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "- go\n") {
		t.Errorf("bare-name form not preserved:\n%s", out)
	}
	var back Config
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(back.Profiles, cfg.Profiles, func(a, b ProfileEntry) bool {
		return a.Name == b.Name && a.On() == b.On() && len(a.Options) == len(b.Options)
	}) {
		t.Errorf("round trip changed the entries: %+v -> %+v", cfg.Profiles, back.Profiles)
	}
}

func TestProfileEntry_Validation(t *testing.T) {
	for _, tc := range []struct {
		entry ProfileEntry
		want  string
	}{
		{ProfileEntry{Name: "golang"}, "unknown profile"},
		{ProfileEntry{Name: "go", Options: map[string]bool{"generate": true}}, "has no option"},
		{ProfileEntry{Name: "deno", Options: map[string]bool{"allow_net": true}}, "allow_network"},
	} {
		err := tc.entry.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate(%+v) = %v, want error containing %q", tc.entry, err, tc.want)
		}
	}
	if err := (ProfileEntry{Name: "deno", Options: map[string]bool{"allow_network": true}}).Validate(); err != nil {
		t.Errorf("valid entry rejected: %v", err)
	}
}

// TestLegacyRuntimes_Fold: a config built with the deprecated runtimes section
// reads as the equivalent profiles, options, and commands allows.
func TestLegacyRuntimes_Fold(t *testing.T) {
	yes, no := true, false
	cfg := &Config{Runtimes: &RuntimesConfig{
		Go:          &GoConfig{Enabled: &yes, Generate: &yes},
		Rust:        &RustConfig{Publish: &yes}, // publish without enabled
		Deno:        &DenoConfig{Enabled: &yes, AllowNetwork: &yes, AllowImport: &no},
		MontyPython: &MontyPythonConfig{Enabled: &no},
	}}
	if !cfg.ProfileEnabled("go") || cfg.ProfileEnabled("rust") || !cfg.ProfileEnabled("deno") || cfg.ProfileEnabled("montypython") {
		t.Error("enabled flags did not fold into profiles")
	}
	if !cfg.ProfileOption("deno", "allow_network") || cfg.ProfileOption("deno", "allow_import") || !cfg.ProfileOption("deno", "auto_sandbox") {
		t.Error("deno settings did not fold into options")
	}
	extra := cfg.ExtraCommandList()
	for _, want := range []string{"go generate", "cargo publish"} {
		if !slices.Contains(extra, want) {
			t.Errorf("ExtraCommandList() = %v, want %q", extra, want)
		}
	}
	// A profiles entry outranks the deprecated flag.
	cfg.Profiles = []ProfileEntry{{Name: "go", Enabled: &no}}
	if cfg.ProfileEnabled("go") {
		t.Error("a profiles entry should outrank runtimes.go.enabled")
	}
}

// TestEffective_OneListEach: Effective hands the sandbox one commands and one
// paths list, holding the enabled profiles' entries (marked with the profile)
// and every deprecated key.
func TestEffective_OneListEach(t *testing.T) {
	yes := true
	cfg := &Config{
		Profiles:      []ProfileEntry{{Name: "rust"}},
		ExtraCommands: []string{"curl"},
		ReadablePaths: []string{"/data"},
		Runtimes:      &RuntimesConfig{Uv: &UvConfig{Enabled: &yes, Publish: &yes}},
		Commands:      []CommandEntry{{Command: "make", Allow: &yes}},
	}
	eff := cfg.Effective()
	if eff.ExtraCommands != nil || eff.ReadablePaths != nil || eff.Runtimes != nil {
		t.Errorf("deprecated keys left on the effective config: %+v", eff)
	}
	if cfg.Runtimes == nil || len(cfg.ExtraCommands) != 1 || len(cfg.Commands) != 1 {
		t.Error("Effective modified its receiver")
	}
	whitelisted := eff.WhitelistedCommandList()
	for _, want := range []string{"cargo", "rustc", "uv", "uvx", "python", "python3"} {
		if !slices.Contains(whitelisted, want) {
			t.Errorf("WhitelistedCommandList() = %v, want %q", whitelisted, want)
		}
	}
	extra := eff.ExtraCommandList()
	for _, want := range []string{"make", "curl", "uv publish"} {
		if !slices.Contains(extra, want) {
			t.Errorf("ExtraCommandList() = %v, want %q", extra, want)
		}
	}
	for _, c := range extra {
		if slices.Contains(whitelisted, c) {
			t.Errorf("a profile command leaked into the allow list: %q", c)
		}
	}
	if !slices.Contains(eff.ReadablePathList(), "/data") {
		t.Errorf("readable_paths not folded into the paths list: %v", eff.Paths)
	}
	for _, e := range eff.Commands {
		if e.Profile != "" && !slices.Contains([]string{"rust", "uv", "montypython"}, e.Profile) {
			t.Errorf("entry from a profile that is not enabled: %+v", e)
		}
	}
	if again := eff.Effective(); again != eff {
		t.Error("Effective on an effective config should return it unchanged")
	}
}

func TestProfilePathGrantsNeverLiftBuiltinDenials(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	yes := true
	bin := filepath.Join(home, ".local", "bin")
	liftedBy := func(cfg *Config) bool {
		_, write := cfg.LiftedDeniedEntries()
		for _, d := range write {
			if d.Path == bin {
				return true
			}
		}
		return false
	}
	if !liftedBy(&Config{Paths: []PathEntry{{Path: bin, Write: &yes}}}) {
		t.Fatal("a user write grant should lift the built-in ~/.local/bin denial")
	}
	if liftedBy(&Config{Paths: []PathEntry{{Path: bin, Write: &yes, Profile: "uv"}}}) {
		t.Error("a profile's write grant must not lift a built-in denial")
	}
}

// migrated resolves dir on a copy of cfg before and after MigrateRuntimes and
// fails unless the directory's profile state is unchanged.
func checkMigrationPreserves(t *testing.T, cfg *Config, dirs ...string) *Config {
	t.Helper()
	before := make([]profileState, len(dirs))
	for i, d := range dirs {
		before[i] = stateOf(cfg.ForDirectory(d))
	}
	cfg.MigrateRuntimes()
	if cfg.UsesDeprecatedRuntimes() {
		t.Fatal("runtimes section left after migration")
	}
	// Round-trip through YAML, as the migrated file is what later loads.
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded Config
	if err := yaml.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	for i, d := range dirs {
		after := stateOf(reloaded.ForDirectory(d))
		for k, v := range before[i].enabled {
			if after.enabled[k] != v {
				t.Errorf("%s: profile %s enabled %v -> %v\n%s", d, k, v, after.enabled[k], data)
			}
		}
		for k, v := range before[i].options {
			if after.options[k] != v {
				t.Errorf("%s: option %s %v -> %v\n%s", d, k, v, after.options[k], data)
			}
		}
		for k, v := range before[i].allowed {
			if after.allowed[k] != v {
				t.Errorf("%s: %q allowed %v -> %v\n%s", d, k, v, after.allowed[k], data)
			}
		}
	}
	return &reloaded
}

func TestMigrateRuntimes_PreservesEveryDirectory(t *testing.T) {
	yes, no := true, false
	t.Run("base only", func(t *testing.T) {
		cfg := &Config{Runtimes: &RuntimesConfig{
			Go:          &GoConfig{Enabled: &yes, Generate: &yes},
			Deno:        &DenoConfig{Enabled: &yes, AutoSandbox: &no},
			MontyPython: &MontyPythonConfig{InlineOnly: &yes},
		}}
		got := checkMigrationPreserves(t, cfg, "/anywhere")
		if got.Runtimes != nil || len(got.Profiles) == 0 {
			t.Errorf("not migrated: %+v", got)
		}
	})
	t.Run("replace-mode override replaced the base's runtimes", func(t *testing.T) {
		// The override's runtimes section replaced the base's wholesale, so go
		// (and cargo publish) were off under /work even though it never says so.
		cfg := &Config{
			Runtimes: &RuntimesConfig{
				Go:   &GoConfig{Enabled: &yes},
				Rust: &RustConfig{Enabled: &yes, Publish: &yes},
			},
			Overrides: []DirectoryOverride{{
				Path:   "/work",
				Config: Config{Runtimes: &RuntimesConfig{Deno: &DenoConfig{AllowNetwork: &yes}}},
			}},
		}
		checkMigrationPreserves(t, cfg, "/work", "/elsewhere")
	})
	t.Run("replace-mode override setting commands only", func(t *testing.T) {
		// The override replaced the base's commands but inherited its runtimes,
		// so cargo publish (a runtimes flag) stayed allowed under /work.
		cfg := &Config{
			Commands: []CommandEntry{{Command: "make", Allow: &yes}},
			Runtimes: &RuntimesConfig{Rust: &RustConfig{Enabled: &yes, Publish: &yes}},
			Overrides: []DirectoryOverride{{
				Path:   "/work",
				Config: Config{Commands: []CommandEntry{{Command: "ninja", Allow: &yes}}},
			}},
		}
		checkMigrationPreserves(t, cfg, "/work", "/elsewhere")
	})
	t.Run("merge-mode override", func(t *testing.T) {
		cfg := &Config{
			Runtimes: &RuntimesConfig{Go: &GoConfig{Enabled: &yes}, Uv: &UvConfig{Enabled: &yes, Publish: &yes}},
			Overrides: []DirectoryOverride{{
				Path:  "/work",
				Merge: true,
				Config: Config{Runtimes: &RuntimesConfig{
					Go: &GoConfig{Enabled: &no},
					Uv: &UvConfig{Publish: &no},
				}},
			}},
		}
		checkMigrationPreserves(t, cfg, "/work", "/elsewhere")
	})
	t.Run("default-on profile turned off in an override", func(t *testing.T) {
		cfg := &Config{Overrides: []DirectoryOverride{{
			Path:   "/work",
			Config: Config{Runtimes: &RuntimesConfig{MontyPython: &MontyPythonConfig{Enabled: &no}}},
		}}}
		checkMigrationPreserves(t, cfg, "/work", "/elsewhere")
	})
}

// TestLoad_MigratesRuntimesOnDisk: Load rewrites a runtimes section as
// profiles in the file itself, once.
func TestLoad_MigratesRuntimesOnDisk(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte("runtimes:\n  go:\n    enabled: true\n    generate: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtimes != nil || !cfg.ProfileEnabled("go") || !slices.Contains(cfg.ExtraCommandList(), "go generate") {
		t.Fatalf("loaded config not migrated: %+v", cfg)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "runtimes") || !strings.Contains(string(data), "- go") || !strings.Contains(string(data), "go generate") {
		t.Errorf("file not rewritten in the new form:\n%s", data)
	}
	if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("file mode not kept: %v %v", info.Mode(), err)
	}
}

// TestProfileCatalog_EntriesAreConfigEntries: every profile is written in the
// config's vocabulary, so each of its entries must be one the config accepts.
func TestProfileCatalog_EntriesAreConfigEntries(t *testing.T) {
	for _, p := range Profiles() {
		if len(p.CommandNames()) == 0 {
			t.Errorf("profile %s allows no command", p.Name)
		}
		for _, e := range p.CommandEntries() {
			if err := e.Validate(); err != nil {
				t.Errorf("profile %s: %v", p.Name, err)
			}
			if e.Profile != p.Name {
				t.Errorf("profile %s: entry %q not marked with its profile", p.Name, e.Command)
			}
		}
		for _, name := range p.CommandNames() {
			if !slices.Contains(ProfilesForCommand(name), p.Name) {
				t.Errorf("ProfilesForCommand(%q) misses %s", name, p.Name)
			}
		}
	}
	// Detected paths come back as config entries too (toolchainDirs).
	yes := true
	entries := toolchainDirs(func() []string { return []string{"/opt/sdk"} })()
	want := []PathEntry{{Path: "/opt/sdk", Read: &yes}, {Path: "/opt/sdk", Write: &yes, Internal: true}}
	if len(entries) != len(want) {
		t.Fatalf("toolchainDirs = %+v", entries)
	}
	for i, e := range entries {
		if err := e.Validate(); err != nil {
			t.Error(err)
		}
		if e.GrantsAgentRead() != want[i].GrantsAgentRead() || e.GrantsInternalWrite() != want[i].GrantsInternalWrite() {
			t.Errorf("toolchainDirs entry %d = %+v, want %+v", i, e, want[i])
		}
	}
}

func TestProfileNoSandboxOption(t *testing.T) {
	xcode, _ := LookupProfile("xcode")
	off := &Config{Profiles: []ProfileEntry{{Name: "xcode"}}}
	on := &Config{Profiles: []ProfileEntry{{Name: "xcode", Options: map[string]bool{"no_sandbox": true}}}}
	for _, e := range off.ProfileCommandEntries(xcode) {
		if e.NoSandbox {
			t.Errorf("%s: no_sandbox set with the option off", e.Command)
		}
	}
	for _, e := range on.ProfileCommandEntries(xcode) {
		if !e.NoSandbox || !e.Whitelists() {
			t.Errorf("%s: want a whitelisting no_sandbox entry, got %+v", e.Command, e)
		}
	}
	var hosted []string
	for _, e := range on.Effective().Commands {
		if e.Profile == "xcode" && e.NoSandbox {
			hosted = append(hosted, e.Command)
		}
	}
	if len(hosted) != len(xcode.Commands) {
		t.Errorf("Effective no_sandbox xcode entries = %v, want all of %v", hosted, xcode.CommandNames())
	}
	// A profile without the option ignores it.
	goProfile, _ := LookupProfile("go")
	if e := (&Config{}).ProfileCommandEntries(goProfile); e[0].NoSandbox {
		t.Errorf("go entries marked no_sandbox: %+v", e)
	}
}
