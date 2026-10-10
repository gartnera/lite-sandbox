package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func deniedHas(entries []DeniedPath, p string) bool {
	for _, e := range entries {
		if e.Path == p {
			return true
		}
	}
	return false
}

// TestScopedGrant_ReachesOnlyItsScope is the point of the field: a grant
// scoped to gh is not an internal grant of the shared worker, which hides the
// path instead, while gh's own worker config has it as a plain internal grant.
func TestScopedGrant_ReachesOnlyItsScope(t *testing.T) {
	writeConfig(t, `
paths:
  - path: /creds/gh
    read: true
    internal: true
    commands: [gh]
  - path: /cache/tool
    write: true
    internal: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExpandedInternalReadablePaths(); len(got) != 0 {
		t.Errorf("shared internal readable = %v, want none", got)
	}
	if got := cfg.ExpandedInternalWritablePaths(); !slices.Equal(got, []string{"/cache/tool"}) {
		t.Errorf("shared internal writable = %v, want [/cache/tool]", got)
	}
	if !deniedHas(cfg.ScopedDeniedReadEntries(), "/creds/gh") {
		t.Errorf("shared worker does not hide /creds/gh: %v", cfg.ScopedDeniedReadEntries())
	}

	scope, ok := cfg.ScopeForCommand("gh")
	if !ok {
		t.Fatal("no scope for gh")
	}
	if scope.Key != "gh" || len(scope.Entries) != 1 {
		t.Errorf("scope = %+v", scope)
	}
	for _, name := range []string{"/usr/bin/gh", "./gh", "git"} {
		if _, ok := cfg.ScopeForCommand(name); ok {
			t.Errorf("ScopeForCommand(%q) matched; only the bare name may", name)
		}
	}

	own := cfg.ForScope(scope)
	if got := own.ExpandedInternalReadablePaths(); !slices.Equal(got, []string{"/creds/gh"}) {
		t.Errorf("scope internal readable = %v, want [/creds/gh]", got)
	}
	if got := own.ScopedDeniedReadEntries(); len(got) != 0 {
		t.Errorf("scope's own worker hides %v", got)
	}
	// ForScope copies; the config itself is unchanged.
	if !cfg.Paths[0].Scoped() {
		t.Error("ForScope modified the receiver")
	}
}

// TestScopedGrant_OtherScopesStayHidden: each worker hides every scope but
// its own.
func TestScopedGrant_OtherScopesStayHidden(t *testing.T) {
	yes := true
	cfg := &Config{Paths: []PathEntry{
		{Path: "/creds/gh", Read: &yes, Internal: true, Commands: []string{"gh"}},
		{Path: "/creds/glab", Read: &yes, Internal: true, Commands: []string{"glab"}},
	}}
	scope, _ := cfg.ScopeForCommand("gh")
	denied := cfg.ForScope(scope).ScopedDeniedReadEntries()
	if deniedHas(denied, "/creds/gh") || !deniedHas(denied, "/creds/glab") {
		t.Errorf("gh's worker hides %v, want only /creds/glab", denied)
	}
}

// TestCommandScopes_Grouping: commands naming the same entries share a scope
// (one worker); different entries make different scopes.
func TestCommandScopes_Grouping(t *testing.T) {
	yes := true
	cfg := &Config{Paths: []PathEntry{
		{Path: "/a", Read: &yes, Internal: true, Commands: []string{"hub", "gh"}},
		{Path: "/b", Write: &yes, Internal: true, Commands: []string{"gh", "hub"}},
		{Path: "/c", Read: &yes, Internal: true, Commands: []string{"glab"}},
		{Path: "/d", Read: &yes, Internal: true, Commands: []string{"glab", "tea"}},
	}}
	scopes := cfg.CommandScopes()
	var keys []string
	for _, s := range scopes {
		keys = append(keys, s.Key)
	}
	if want := []string{"gh,hub", "glab", "tea"}; !slices.Equal(keys, want) {
		t.Fatalf("scope keys = %v, want %v", keys, want)
	}
	if n := len(scopes[0].Entries); n != 2 {
		t.Errorf("gh,hub scope has %d entries, want 2", n)
	}
	if n := len(scopes[1].Entries); n != 2 {
		t.Errorf("glab scope has %d entries (/c and /d), want 2", n)
	}
	if n := len(scopes[2].Entries); n != 1 {
		t.Errorf("tea scope has %d entries (/d), want 1", n)
	}
	// tea's worker hides /c (glab's alone) but not /d, which it is granted.
	denied := cfg.ForScope(scopes[2]).ScopedDeniedReadEntries()
	if deniedHas(denied, "/d") {
		t.Errorf("tea's worker hides its own /d: %v", denied)
	}
}

// TestScopedGrant_LiftsBuiltinOnlyInItsWorker: a scoped grant on a built-in
// denylist path (~/.config/gh) leaves it masked in the shared worker and lifts
// it in its own — even when a profile wrote it.
func TestScopedGrant_LiftsBuiltinOnlyInItsWorker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	ghDir := filepath.Join(home, ".config", "gh")
	if err := os.MkdirAll(ghDir, 0o700); err != nil {
		t.Fatal(err)
	}
	yes := true
	for _, profile := range []string{"", "someprofile"} {
		cfg := &Config{Mode: string(ModeDenylist), Paths: []PathEntry{
			{Path: "~/.config/gh", Read: &yes, Internal: true, Commands: []string{"gh"}, Profile: profile},
		}}
		if !deniedHas(cfg.EffectiveDeniedReadEntries(), ghDir) {
			t.Errorf("profile %q: the shared worker's deny list lost %s", profile, ghDir)
		}
		if read, _ := cfg.LiftedDeniedEntries(); deniedHas(read, ghDir) {
			t.Errorf("profile %q: a scoped grant reported as lifting %s for every command", profile, ghDir)
		}
		scope, _ := cfg.ScopeForCommand("gh")
		if deniedHas(cfg.ForScope(scope).EffectiveDeniedReadEntries(), ghDir) {
			t.Errorf("profile %q: gh's worker still hides %s", profile, ghDir)
		}
	}
}

// TestScopedDenied_UnscopedGrantWins: a path an unscoped grant also names is
// already every command's, so no worker hides it.
func TestScopedDenied_UnscopedGrantWins(t *testing.T) {
	yes := true
	cfg := &Config{Paths: []PathEntry{
		{Path: "/creds", Read: &yes, Internal: true, Commands: []string{"gh"}},
	}, InternalReadablePaths: []string{"/creds"}}
	if got := cfg.ScopedDeniedReadEntries(); len(got) != 0 {
		t.Errorf("ScopedDeniedReadEntries = %v, want none", got)
	}
}

func TestScopedGrant_Validate(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		e    PathEntry
		want string
	}{
		{PathEntry{Path: "/x", Read: &yes, Commands: []string{"gh"}}, "internal: true"},
		{PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{"/usr/bin/gh"}}, "bare command name"},
		{PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{"gh pr"}}, "bare command name"},
		{PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{""}}, "bare command name"},
		{PathEntry{Path: "/x/*", Read: &yes, Internal: true, Commands: []string{"gh"}}, "nested-only"},
		{PathEntry{Path: "/x", Read: &no, Internal: true, Commands: []string{"gh"}}, "grants only"},
		{PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{"gh"}}, ""},
	}
	for _, c := range cases {
		err := c.e.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v: unexpected error %v", c.e, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%+v: error %v, want one mentioning %q", c.e, err, c.want)
		}
	}
}

func TestScopedGrant_Describe(t *testing.T) {
	yes := true
	e := PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{"gh", "hub"}}
	if got, want := e.Describe(), "read (internal: only for gh, hub, in its own OS sandbox worker)"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}

func TestScopeBypass(t *testing.T) {
	yes := true
	scoped := PathEntry{Path: "/x", Read: &yes, Internal: true, Commands: []string{"gh"}}
	cases := []struct {
		name     string
		commands []CommandEntry
		want     string
	}{
		{"no allow", nil, ""},
		{"restricted allow", []CommandEntry{{Command: "gh pr", Allow: &yes}}, ""},
		{"bare allow", []CommandEntry{{Command: "gh", Allow: &yes}}, "bash -c"},
		{"no_sandbox", []CommandEntry{{Command: "gh pr", Allow: &yes, NoSandbox: true}}, "on the host"},
	}
	for _, c := range cases {
		cfg := &Config{Paths: []PathEntry{scoped}, Commands: c.commands}
		got := cfg.ScopeBypass("gh")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: ScopeBypass = %q, want one containing %q", c.name, got, c.want)
		}
	}
}

// TestScopedGrant_YAML round-trips the field through the file.
func TestScopedGrant_YAML(t *testing.T) {
	writeConfig(t, `
paths:
  - path: ~/.config/gh
    read: true
    internal: true
    commands: [gh]
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Paths[0].Commands; !slices.Equal(got, []string{"gh"}) {
		t.Fatalf("commands = %v", got)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(os.Getenv("LITE_SANDBOX_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "commands:") {
		t.Errorf("saved config lost commands:\n%s", data)
	}
	writeConfig(t, `
paths:
  - path: /x
    read: true
    commands: [gh]
`)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "internal: true") {
		t.Errorf("Load of a scoped grant without internal: err = %v", err)
	}
}

// TestScopedDenied_MissingWriteGrantIsDir: a missing path a scoped write grant
// names is masked as a directory (created, then hidden), since the scope's
// worker will create it as one; a missing read grant stays a file entry.
func TestScopedDenied_MissingWriteGrantIsDir(t *testing.T) {
	dir := t.TempDir()
	yes := true
	cfg := &Config{Paths: []PathEntry{
		{Path: filepath.Join(dir, "w"), Write: &yes, Internal: true, Commands: []string{"tool"}},
		{Path: filepath.Join(dir, "r"), Read: &yes, Internal: true, Commands: []string{"tool"}},
	}}
	got := map[string]bool{}
	for _, d := range cfg.ScopedDeniedReadEntries() {
		got[d.Path] = d.Dir
	}
	if !got[filepath.Join(dir, "w")] {
		t.Error("missing write grant not masked as a directory")
	}
	if dirFlag, ok := got[filepath.Join(dir, "r")]; !ok || dirFlag {
		t.Errorf("missing read grant: present=%v dir=%v, want a file entry", ok, dirFlag)
	}
}
