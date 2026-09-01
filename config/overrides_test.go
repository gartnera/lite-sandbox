package config

import "testing"

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
