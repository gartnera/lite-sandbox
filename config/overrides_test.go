package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestMatchDirectoryOverride(t *testing.T) {
	type entry struct{ dir string }
	overrides := []entry{
		{"/work"},
		{"/work/projects/secure"},
		{"/work/projects"},
		{""}, // empty path is skipped
	}
	pathOf := func(e entry) string { return e.dir }

	tests := []struct {
		name string
		dir  string
		want int // index into overrides, -1 for no match
	}{
		{"no match", "/other", -1},
		{"exact broad", "/work", 0},
		{"subdir picks broad", "/work/app", 0},
		{"subdir picks specific", "/work/projects/app", 2},
		{"most specific wins", "/work/projects/secure/db", 1},
		{"empty dir never matches", "", -1},
		{"prefix but not a path boundary", "/workshop", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchDirectoryOverride(tt.dir, overrides, pathOf); got != tt.want {
				t.Errorf("MatchDirectoryOverride(%q) = %d, want %d", tt.dir, got, tt.want)
			}
		})
	}

	// Nothing to match against.
	if got := MatchDirectoryOverride("/work", nil, pathOf); got != -1 {
		t.Errorf("empty overrides = %d, want -1", got)
	}
}

func TestDirectoryOverride_SetsAnySection(t *testing.T) {
	bp := func(b bool) *bool { return &b }

	if o := (&DirectoryOverride{Path: "/x"}); o.SetsAnySection() {
		t.Error("override with only a path should set no section")
	}
	if o := (&DirectoryOverride{Path: "/x", Config: Config{AWS: &AWSConfig{ForceProfile: "p"}}}); !o.SetsAnySection() {
		t.Error("override with an aws section should report a set section")
	}
	if o := (&DirectoryOverride{Path: "/x", Config: Config{WritablePaths: []string{"/x/out"}}}); !o.SetsAnySection() {
		t.Error("override with writable_paths should report a set section")
	}
	if o := (&DirectoryOverride{Path: "/x", Config: Config{OSSandbox: bp(false)}}); !o.SetsAnySection() {
		t.Error("override with os_sandbox set (even to false) should report a set section")
	}
}

// TestForDirectory_MergesKeyedSections is the point of the keyed sections:
// under merge: true, `paths` and `commands` combine with the base entry by
// entry, so a directory states only what it changes instead of restating the
// whole list.
func TestForDirectory_MergesKeyedSections(t *testing.T) {
	writeConfig(t, `
paths:
  - path: /base/data
    read: true
  - path: /base/out
    write: true
commands:
  - command: curl
    allow: true
  - command: npm
    allow: true
overrides:
  - path: /work
    merge: true
    paths:
      - path: /base/out     # restates the base's entry for this path
        read: true
      - path: /work/artifacts
        write: true
    commands:
      - command: curl       # restates: denied under /work
        allow: false
      - command: pnpm
        allow: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	scoped := cfg.ForDirectory("/work/app")
	// The base's untouched entry is inherited, the restated one takes the
	// override's value (so /base/out is no longer writable here), and the new
	// entry is added.
	if got := scoped.ReadablePathList(); !slices.Equal(got, []string{"/base/data", "/base/out"}) {
		t.Errorf("readable = %v, want the inherited and the restated entry", got)
	}
	if got := scoped.WritablePathList(); !slices.Equal(got, []string{"/work/artifacts"}) {
		t.Errorf("writable = %v, want only the override's new entry", got)
	}
	if got := scoped.ExtraCommandList(); !slices.Equal(got, []string{"npm", "pnpm"}) {
		t.Errorf("allowed commands = %v, want the inherited and the new entry", got)
	}
	if got := scoped.DeniedCommandList(); !slices.Equal(got, []string{"curl"}) {
		t.Errorf("denied commands = %v, want the restated entry", got)
	}

	// Elsewhere the base is untouched, and resolving never mutated it.
	base := cfg.ForDirectory("/elsewhere")
	if got := base.WritablePathList(); !slices.Equal(got, []string{"/base/out"}) {
		t.Errorf("base writable = %v, want the stored entry", got)
	}
	if got := base.ExtraCommandList(); !slices.Equal(got, []string{"curl", "npm"}) {
		t.Errorf("base allowed commands = %v, want the stored entries", got)
	}
}

// TestForDirectory_KeyedSectionsMatchBySubject: a restatement is matched by
// the subject as the sandbox matches it, not by the spelling — ~/x and its
// expanded form are one path, and extra whitespace is one command.
func TestForDirectory_KeyedSectionsMatchBySubject(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	yes, no := true, false
	cfg := &Config{
		Paths:    []PathEntry{{Path: "~/scratch", Write: &yes}},
		Commands: []CommandEntry{{Command: "uv run pyright", Allow: &yes}},
		Overrides: []DirectoryOverride{{
			Path:  "/work",
			Merge: true,
			Config: Config{
				Paths:    []PathEntry{{Path: filepath.Join(home, "scratch"), Read: &yes}},
				Commands: []CommandEntry{{Command: "uv  run   pyright", Allow: &no}},
			},
		}},
	}
	scoped := cfg.ForDirectory("/work")
	if got := scoped.ExpandedWritablePaths(); len(got) != 0 {
		t.Errorf("writable = %v, want the restated entry to have replaced the grant", got)
	}
	if got := scoped.ExpandedReadablePaths(); !slices.Equal(got, []string{filepath.Join(home, "scratch")}) {
		t.Errorf("readable = %v, want the override's entry", got)
	}
	if got := scoped.ExtraCommandList(); len(got) != 0 {
		t.Errorf("allowed commands = %v, want the restated entry to have replaced the allow", got)
	}
	if got := scoped.DeniedCommandList(); len(got) != 1 {
		t.Errorf("denied commands = %v, want the override's entry", got)
	}
}

// TestPruneRestatedEntries: a merge: true override stores the delta. An entry
// repeating the base is dropped (the merge inherits it either way), one that
// changes a base entry or names a new subject is kept.
func TestPruneRestatedEntries(t *testing.T) {
	yes := true
	base := &Config{
		Paths: []PathEntry{
			{Path: "/base/data", Read: &yes},
			{Path: "/base/out", Write: &yes},
		},
		Commands: []CommandEntry{{Command: "curl", Allow: &yes}},
	}
	o := &DirectoryOverride{Path: "/work", Merge: true, Config: Config{
		Paths: []PathEntry{
			{Path: "/base/data", Read: &yes}, // same as the base: inherited
			{Path: "/base/out", Read: &yes},  // changes the base's entry: kept
			{Path: "/work/out", Write: &yes}, // new subject: kept
		},
		Commands: []CommandEntry{{Command: "curl", Allow: &yes}}, // same as the base
	}}

	PruneRestatedEntries(o, base)

	if got := o.Paths; len(got) != 2 || got[0].Path != "/base/out" || got[1].Path != "/work/out" {
		t.Errorf("paths = %+v, want only the changed and the new entry", got)
	}
	if o.Commands != nil {
		t.Errorf("commands = %+v, want the repeated entry dropped and the section cleared", o.Commands)
	}
	if o.SetsAnySection() != true {
		t.Error("the override still sets paths")
	}
	// An override reduced to nothing is reported as setting nothing, so the
	// caller can drop it.
	empty := &DirectoryOverride{Path: "/work", Merge: true, Config: Config{
		Paths: []PathEntry{{Path: "/base/data", Read: &yes}},
	}}
	PruneRestatedEntries(empty, base)
	if empty.SetsAnySection() {
		t.Errorf("override = %+v, want nothing left after pruning", empty.Config)
	}
	// A replace-mode override is left alone: omitting an entry there drops it.
	replace := &DirectoryOverride{Path: "/work", Config: Config{Paths: []PathEntry{{Path: "/base/data", Read: &yes}}}}
	PruneRestatedEntries(replace, base)
	if len(replace.Paths) != 1 {
		t.Errorf("replace-mode override paths = %+v, want them left alone", replace.Paths)
	}
}
