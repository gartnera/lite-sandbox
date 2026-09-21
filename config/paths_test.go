package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPaths_OneListFeedsEveryAccessor is the point of the section: a single
// `paths` list with per-entry flags resolves to the same six lists the
// sandbox, the hook, and the OS sandbox worker have always read.
func TestPaths_OneListFeedsEveryAccessor(t *testing.T) {
	writeConfig(t, `
paths:
  - path: /ref
    read: true
  - path: /scratch
    write: true
  - path: /opt/data
    read: true
    internal: true
  - path: /cache/tool
    write: true
    internal: true
  - path: /secrets
    read: false
  - path: /bin-ish
    write: false
  - path: /mixed
    read: true
    write: false
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, got, want []string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("readable", cfg.ExpandedReadablePaths(), []string{"/ref", "/mixed"})
	check("writable", cfg.ExpandedWritablePaths(), []string{"/scratch"})
	check("internal readable", cfg.ExpandedInternalReadablePaths(), []string{"/opt/data"})
	check("internal writable", cfg.ExpandedInternalWritablePaths(), []string{"/cache/tool"})
	check("denied read", cfg.DeniedReadPathList(), []string{"/secrets"})
	check("denied write", cfg.DeniedWritePathList(), []string{"/bin-ish", "/mixed"})
	if !slices.Contains(cfg.EffectiveDeniedReadPaths(), "/secrets") || !slices.Contains(cfg.EffectiveDeniedWritePaths(), "/bin-ish") {
		t.Error("user denials should be merged into the effective deny lists")
	}
}

// TestPaths_LegacyKeysStillLoadAsUnion keeps every existing config working: the
// six old keys resolve exactly as before, and a file mixing them with `paths`
// sees both.
func TestPaths_LegacyKeysStillLoadAsUnion(t *testing.T) {
	writeConfig(t, `
readable_paths: [/old-ref]
writable_paths: [/old-scratch]
internal_readable_paths: [/old-int-r]
internal_writable_paths: [/old-int-w]
denied_read_paths: [/old-deny-r]
denied_write_paths: [/old-deny-w]
paths:
  - path: /new-scratch
    write: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExpandedWritablePaths(); !slices.Equal(got, []string{"/old-scratch", "/new-scratch"}) {
		t.Errorf("writable = %v", got)
	}
	if got := cfg.ExpandedReadablePaths(); !slices.Equal(got, []string{"/old-ref"}) {
		t.Errorf("readable = %v", got)
	}
	if got := cfg.ExpandedInternalReadablePaths(); !slices.Equal(got, []string{"/old-int-r"}) {
		t.Errorf("internal readable = %v", got)
	}
	if got := cfg.ExpandedInternalWritablePaths(); !slices.Equal(got, []string{"/old-int-w"}) {
		t.Errorf("internal writable = %v", got)
	}
	if got := cfg.DeniedReadPathList(); !slices.Equal(got, []string{"/old-deny-r"}) {
		t.Errorf("denied read = %v", got)
	}
	if got := cfg.DeniedWritePathList(); !slices.Equal(got, []string{"/old-deny-w"}) {
		t.Errorf("denied write = %v", got)
	}
	if !cfg.UsesDeprecatedPathKeys() {
		t.Error("UsesDeprecatedPathKeys should report the old keys")
	}
	// The listing view shows everything in the new shape, old keys last.
	all := cfg.AllPathEntries()
	if len(all) != 7 || all[0].Path != "/new-scratch" || all[1].Path != "/old-ref" {
		t.Errorf("AllPathEntries = %+v", all)
	}
}

func TestPaths_Validation(t *testing.T) {
	cases := map[string]string{
		"no path":             "paths:\n  - read: true\n",
		"says nothing":        "paths:\n  - path: /x\n",
		"deny read but write": "paths:\n  - path: /x\n    read: false\n    write: true\n",
		"internal denial":     "paths:\n  - path: /x\n    write: false\n    internal: true\n",
		"in an override":      "overrides:\n  - path: /w\n    paths:\n      - path: /x\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			writeConfig(t, body)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "paths entry") {
				t.Fatalf("expected a paths validation error, got %v", err)
			}
		})
	}
	// Coherent combinations load.
	writeConfig(t, "paths:\n  - path: /x\n    read: true\n    write: false\n  - path: /y/*\n    write: true\n    internal: true\n")
	if _, err := Load(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestPathEntry_Describe(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		e    PathEntry
		want string
	}{
		{PathEntry{Read: &yes}, "read"},
		{PathEntry{Write: &yes}, "read, write"},
		{PathEntry{Read: &yes, Write: &yes}, "read, write"},
		{PathEntry{Write: &yes, Internal: true}, "read, write (internal: OS sandbox layer only)"},
		{PathEntry{Read: &no}, "deny read"},
		{PathEntry{Write: &no}, "deny write"},
		{PathEntry{Read: &yes, Write: &no}, "read, deny write"},
	}
	for _, c := range cases {
		if got := c.e.Describe(); got != c.want {
			t.Errorf("Describe(%+v) = %q, want %q", c.e, got, c.want)
		}
	}
}

// TestPaths_SetAndRemove: a path has one statement. Setting it replaces any
// earlier entry and lifts the path out of the deprecated lists, so the CLI
// migrates a path as soon as it touches it; removing drops every mention.
func TestPaths_SetAndRemove(t *testing.T) {
	home, _ := os.UserHomeDir()
	yes, no := true, false
	cfg := &Config{
		ReadablePaths:   []string{"~/x", "/keep"},
		DeniedReadPaths: []string{filepath.Join(home, "x")}, // same path, spelled expanded
	}
	if err := cfg.SetPath(PathEntry{Path: "~/x", Write: &yes}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.ReadablePaths, []string{"/keep"}) || cfg.DeniedReadPaths != nil {
		t.Errorf("legacy lists after SetPath: readable=%v denied=%v", cfg.ReadablePaths, cfg.DeniedReadPaths)
	}
	if len(cfg.Paths) != 1 || !cfg.Paths[0].GrantsWrite() {
		t.Fatalf("Paths = %+v", cfg.Paths)
	}
	// Setting the same path again replaces, not appends.
	if err := cfg.SetPath(PathEntry{Path: filepath.Join(home, "x"), Read: &no}); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Paths) != 1 || !cfg.Paths[0].DeniesRead() {
		t.Fatalf("Paths after replace = %+v", cfg.Paths)
	}
	if err := cfg.SetPath(PathEntry{Path: "/bad", Read: &no, Write: &yes}); err == nil {
		t.Error("SetPath should reject an incoherent entry")
	}
	if !cfg.RemovePath("~/x") || cfg.Paths != nil {
		t.Errorf("RemovePath: Paths = %+v", cfg.Paths)
	}
	if !cfg.RemovePath("/keep") || cfg.ReadablePaths != nil {
		t.Errorf("RemovePath should clear a legacy list: %v", cfg.ReadablePaths)
	}
	if cfg.RemovePath("/never") {
		t.Error("removing an unknown path should report false")
	}
}

// TestPaths_Migrate rewrites the deprecated keys as `paths` entries without
// changing what any directory resolves to — including the awkward case where
// an old-style override replaced one list and inherited the others, which a
// whole-section `paths` list cannot express without restating them.
func TestPaths_Migrate(t *testing.T) {
	writeConfig(t, `
readable_paths: [/ref]
writable_paths: [/scratch]
denied_write_paths: [/ro]
paths:
  - path: /new
    read: true
overrides:
  - path: /work/a
    writable_paths: [/work/a/out]      # replaces writable, inherits the rest
  - path: /work/b
    os_sandbox: true                   # touches no path list: keeps inheriting
  - path: /work/c
    paths:                             # already new-style: was unioned with the base's old keys
      - path: /work/c/out
        write: true
`)
	before, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	after, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	n := after.MigratePaths()
	if n == 0 {
		t.Fatal("MigratePaths reported nothing to do")
	}
	if after.UsesDeprecatedPathKeys() {
		t.Errorf("deprecated keys remain after migrate: %+v", after)
	}
	if after.MigratePaths() != 0 {
		t.Error("a second migrate should be a no-op")
	}
	// Round-trip through the file, as the CLI does, and compare every
	// directory's resolution before and after.
	if err := Save(after); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/elsewhere", "/work/a/sub", "/work/b", "/work/c"} {
		b, a := before.ForDirectory(dir), reloaded.ForDirectory(dir)
		type view struct{ r, w, ir, iw, dr, dw []string }
		mk := func(c *Config) view {
			return view{c.ExpandedReadablePaths(), c.ExpandedWritablePaths(),
				c.ExpandedInternalReadablePaths(), c.ExpandedInternalWritablePaths(),
				c.DeniedReadPathList(), c.DeniedWritePathList()}
		}
		vb, va := mk(b), mk(a)
		sortAll := func(v *view) {
			for _, l := range []*[]string{&v.r, &v.w, &v.ir, &v.iw, &v.dr, &v.dw} {
				slices.Sort(*l)
			}
		}
		sortAll(&vb)
		sortAll(&va)
		if !slices.Equal(vb.r, va.r) || !slices.Equal(vb.w, va.w) || !slices.Equal(vb.ir, va.ir) ||
			!slices.Equal(vb.iw, va.iw) || !slices.Equal(vb.dr, va.dr) || !slices.Equal(vb.dw, va.dw) {
			t.Errorf("%s resolves differently after migrate:\n before %+v\n after  %+v", dir, vb, va)
		}
	}
	// The override that set no path list still inherits rather than carrying a copy.
	for _, o := range reloaded.Overrides {
		if o.Path == "/work/b" && o.Paths != nil {
			t.Errorf("/work/b should keep inheriting, got paths %+v", o.Paths)
		}
	}
	// The file now spells everything the new way.
	data, _ := os.ReadFile(os.Getenv("LITE_SANDBOX_CONFIG"))
	if strings.Contains(string(data), "_paths:") {
		t.Errorf("migrated file still has an old key:\n%s", data)
	}
}

// TestPaths_OverrideReplacesSection: a replace-mode override's paths list
// replaces the base's for its directory, as every section does there. Only
// merge: true combines the two entry by entry
// (TestForDirectory_MergesKeyedSections).
func TestPaths_OverrideReplacesSection(t *testing.T) {
	writeConfig(t, `
paths:
  - path: /base
    write: true
overrides:
  - path: /work
    paths:
      - path: /work/out
        write: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/elsewhere").ExpandedWritablePaths(); !slices.Equal(got, []string{"/base"}) {
		t.Errorf("base writable = %v", got)
	}
	if got := cfg.ForDirectory("/work/x").ExpandedWritablePaths(); !slices.Equal(got, []string{"/work/out"}) {
		t.Errorf("override writable = %v", got)
	}
	if !(&DirectoryOverride{Path: "/x", Config: Config{Paths: []PathEntry{{Path: "/y"}}}}).SetsAnySection() {
		t.Error("an override with paths should report a set section")
	}
}

// TestPaths_MigrateMergeOverride: a merge: true override keeps only its own
// entries, since `paths` merges entry by entry there — migrate must not copy
// the base's entries into it, which would freeze them.
func TestPaths_MigrateMergeOverride(t *testing.T) {
	writeConfig(t, `
readable_paths: [/ref]
overrides:
  - path: /work
    merge: true
    writable_paths: [/work/out]
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MigratePaths() == 0 {
		t.Fatal("MigratePaths reported nothing to do")
	}
	o := cfg.Overrides[0]
	if len(o.Paths) != 1 || o.Paths[0].Path != "/work/out" || !o.Paths[0].GrantsWrite() {
		t.Errorf("override paths = %+v, want only its own entry", o.Paths)
	}
	// The directory resolves as it did: the base's readable path inherited,
	// its own writable path on top.
	scoped := cfg.ForDirectory("/work/sub")
	if got := scoped.ExpandedReadablePaths(); !slices.Equal(got, []string{"/ref"}) {
		t.Errorf("readable = %v, want the base entry inherited", got)
	}
	if got := scoped.ExpandedWritablePaths(); !slices.Equal(got, []string{"/work/out"}) {
		t.Errorf("writable = %v, want the override entry", got)
	}
}
