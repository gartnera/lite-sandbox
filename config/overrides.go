package config

import (
	"path/filepath"
	"reflect"
	"strings"
)

// DirectoryOverride replaces parts of the configuration for commands whose
// working directory is at (or under) Path. It embeds a full Config, so an
// override can set any section — aws, docker, runtimes, readable/writable paths,
// os_sandbox, and so on — not just one. Each section the override specifies fully
// replaces that section from the base config (sections it leaves unset are
// inherited), so, for example, an override's `aws:` block defines the entire AWS
// mode for its directory rather than merging field-by-field. Path supports ~
// expansion. When a directory matches more than one override the most specific
// (longest) Path wins. A nested Overrides list on an override is ignored.
type DirectoryOverride struct {
	Path   string `yaml:"path"`
	Config `yaml:",inline"`
}

// SetsAnySection reports whether the override sets at least one config section,
// i.e. whether applying it would change anything. Path alone does not count, so
// callers can drop an override that has been emptied of all its sections.
func (o *DirectoryOverride) SetsAnySection() bool {
	v := reflect.ValueOf(&o.Config).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Overrides" || !f.IsExported() {
			continue
		}
		switch fv := v.Field(i); fv.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map:
			if !fv.IsNil() {
				return true
			}
		}
	}
	return false
}

// ForDirectory returns the configuration in effect for commands whose working
// directory is dir: the base config overlaid with the single most specific
// matching directory override. Every section the override sets replaces that
// whole section from the base, while sections it leaves unset are inherited — so
// a directory can switch AWS profiles, widen writable paths, enable a runtime,
// and so on, all through one mechanism. The returned config carries no overrides
// itself, so reading any section off it reflects dir directly. A nil receiver
// returns nil.
//
// The result is a read-only resolved view: its section pointers and slices are
// shared with the receiver (and with the matched override), not deep-copied.
// Callers must treat it as immutable — read the accessors, do not mutate the
// returned Config or the values it points at, or the change would leak into the
// stored config and other directories.
func (c *Config) ForDirectory(dir string) *Config {
	if c == nil {
		return nil
	}
	resolved := *c
	resolved.Overrides = nil
	if i := MatchDirectoryOverride(dir, c.Overrides, func(o DirectoryOverride) string { return o.Path }); i >= 0 {
		overlayConfig(&resolved, &c.Overrides[i].Config)
	}
	return &resolved
}

// overlayConfig copies every set section from over onto base (mutating base). A
// section is "set" when its field is a non-nil pointer, slice, or map; unset
// sections leave base's value untouched. The Overrides field is never copied, so
// an override cannot nest further overrides. Because it walks the struct
// reflectively, it stays complete automatically as new config sections are added
// — every overridable section uses a pointer or slice type by convention, which
// is exactly what this treats as overridable.
func overlayConfig(base, over *Config) {
	bv := reflect.ValueOf(base).Elem()
	ov := reflect.ValueOf(over).Elem()
	t := bv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Overrides" || !f.IsExported() {
			continue
		}
		of := ov.Field(i)
		switch of.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map:
			if !of.IsNil() {
				bv.Field(i).Set(of)
			}
		}
	}
}

// MatchDirectoryOverride returns the index into overrides of the most specific
// entry whose configured path contains dir, or -1 when none match. It is the
// shared, config-section-agnostic resolution behind every per-directory
// override: a caller supplies its own slice of override entries and a pathOf
// accessor that yields each entry's directory, and gets back the winning index.
//
// An entry matches dir when dir equals its path or lies beneath it. When several
// entries match, the one with the longest path wins, so a nested override takes
// priority over a broader parent. Paths support ~ expansion and are resolved to
// absolute before comparison (as is dir), so relative inputs match the concrete
// directory they denote. Entries with an empty path are skipped.
func MatchDirectoryOverride[T any](dir string, overrides []T, pathOf func(T) string) int {
	if dir == "" || len(overrides) == 0 {
		return -1
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	best := -1
	bestLen := -1
	for i := range overrides {
		base := expandPath(pathOf(overrides[i]))
		if base == "" {
			continue
		}
		if abs == base || strings.HasPrefix(abs, base+string(filepath.Separator)) {
			if len(base) > bestLen {
				best = i
				bestLen = len(base)
			}
		}
	}
	return best
}
