package config

import (
	"slices"
	"testing"
)

func TestDefaultDeniedCommands_SelfProtection(t *testing.T) {
	got := DefaultDeniedCommands()
	for _, want := range []string{
		"lite-sandbox config",
		"lite-sandbox install",
		"lite-sandbox update",
		"lite-sandbox hook",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("built-in deny list is missing %q: %v", want, got)
		}
		if !IsDefaultDeniedCommand(want) {
			t.Errorf("IsDefaultDeniedCommand(%q) = false", want)
		}
	}
	// The read-only subcommands an agent legitimately uses stay runnable, so
	// the binary itself must never be denied outright.
	if slices.Contains(got, "lite-sandbox") {
		t.Errorf("bare lite-sandbox entry would block `version` and `config show`: %v", got)
	}
	if IsDefaultDeniedCommand("curl") {
		t.Error("IsDefaultDeniedCommand(curl) = true")
	}
}

func TestEffectiveDeniedCommands(t *testing.T) {
	cases := []struct {
		name       string
		cfg        *Config
		want       []string // entries that must be present
		wantAbsent []string
	}{
		{
			name: "defaults only",
			cfg:  &Config{},
			want: []string{"lite-sandbox config"},
		},
		{
			name: "nil config still denies the defaults",
			cfg:  nil,
			want: []string{"lite-sandbox config"},
		},
		{
			name: "user entries extend the defaults",
			cfg:  &Config{DeniedCommands: []string{"sudo", "gh auth"}},
			want: []string{"lite-sandbox config", "sudo", "gh auth"},
		},
		{
			name:       "a negated entry drops a built-in default",
			cfg:        &Config{DeniedCommands: []string{"-lite-sandbox config"}},
			want:       []string{"lite-sandbox install"},
			wantAbsent: []string{"lite-sandbox config"},
		},
		{
			name:       "negation normalizes whitespace",
			cfg:        &Config{DeniedCommands: []string{"-lite-sandbox   config"}},
			wantAbsent: []string{"lite-sandbox config"},
		},
		{
			name:       "a negation applies to a user entry too",
			cfg:        &Config{DeniedCommands: []string{"sudo", "-sudo"}},
			wantAbsent: []string{"sudo"},
		},
		{
			name: "duplicates collapse",
			cfg:  &Config{DeniedCommands: []string{"lite-sandbox config", "sudo", "sudo"}},
			want: []string{"sudo"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.cfg.EffectiveDeniedCommands()
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Errorf("missing %q in %v", w, got)
				}
			}
			for _, w := range c.wantAbsent {
				if slices.Contains(got, w) {
					t.Errorf("unexpected %q in %v", w, got)
				}
			}
			if n := len(got); n != len(slices.Compact(slices.Clone(got))) {
				t.Errorf("duplicate entries in %v", got)
			}
		})
	}
}

func TestEffectiveDeniedCommands_DirectoryOverride(t *testing.T) {
	cfg := &Config{
		DeniedCommands: []string{"sudo"},
		Overrides: []DirectoryOverride{
			{Path: "/work/repo", Config: Config{DeniedCommands: []string{"gh"}}},
		},
	}
	base := cfg.ForDirectory("/elsewhere").EffectiveDeniedCommands()
	if !slices.Contains(base, "sudo") || slices.Contains(base, "gh") {
		t.Errorf("base directory list = %v", base)
	}
	// An override replaces the section, but the built-in defaults are not part
	// of the section: they still apply under the override.
	over := cfg.ForDirectory("/work/repo").EffectiveDeniedCommands()
	if !slices.Contains(over, "gh") || slices.Contains(over, "sudo") {
		t.Errorf("override list = %v", over)
	}
	if !slices.Contains(over, "lite-sandbox config") {
		t.Errorf("override dropped the built-in defaults: %v", over)
	}
}
