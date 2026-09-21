package config

import (
	"path/filepath"
	"reflect"
	"strings"

	"github.com/gartnera/lite-sandbox/internal/gitworktree"
)

// DirectoryOverride changes parts of the configuration for commands whose
// working directory is at (or under) Path. It embeds a full Config, so an
// override can set any section — aws, docker, runtimes, readable/writable paths,
// os_sandbox, and so on — not just one. Path supports ~ expansion. When a
// directory matches more than one override the most specific (longest) Path wins.
// A nested Overrides list on an override is ignored.
//
// Merge selects how the override combines with the base config:
//   - false (default): each section the override sets fully REPLACES that section
//     from the base, so an override's `aws:` block defines the entire AWS mode
//     for its directory. Sections it leaves unset are inherited.
//   - true: the override is DEEP-MERGED into the base — it recurses into struct
//     sections and applies only the fields it sets, inheriting the rest. This
//     lets an override change, say, just `docker.allow_privileged` while keeping
//     the base's `docker.enabled`. The keyed list sections `paths` and
//     `commands` merge entry by entry (see keyedEntry): the base's statements
//     carry into the directory and the override restates only the paths and
//     commands it changes. Every other leaf (scalars, `*bool` flags, and the
//     deprecated one-list-per-kind keys such as writable_paths) is still taken
//     from the override when set, otherwise inherited.
type DirectoryOverride struct {
	Path   string `yaml:"path"`
	Merge  bool   `yaml:"merge,omitempty"`
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
		default:
			// By-value scalar section (none today): set means non-zero.
			if !fv.IsZero() {
				return true
			}
		}
	}
	return false
}

// ForDirectory returns the configuration in effect for commands whose working
// directory is dir: the base config combined with the single most specific
// matching directory override. How they combine depends on the override's Merge
// flag — whole-section replace by default, deep merge when Merge is true (see
// DirectoryOverride) — so a directory can switch AWS profiles, widen writable
// paths, flip a single docker flag, and so on, all through one mechanism. The
// returned config carries no overrides itself, so reading any section off it
// reflects dir directly. A nil receiver returns nil.
//
// A linked git worktree inherits the overrides of the repository it was created
// from: when nothing matches dir itself, resolution retries against the main
// worktree (see matchOverride), so a worktree parked under a container like
// ~/.superconductor/worktrees is governed by the settings written for the repo.
//
// The result is a read-only resolved view. In replace mode its section pointers
// and slices are shared with the receiver (and with the matched override); deep
// merge clones the structs and keyed lists it writes into so it never mutates
// the stored config.
// Either way, treat the result as immutable — read the accessors, do not mutate
// it or the values it points at.
func (c *Config) ForDirectory(dir string) *Config {
	if c == nil {
		return nil
	}
	resolved := *c
	resolved.Overrides = nil
	if i := matchOverride(dir, c.Overrides); i >= 0 {
		overlayConfig(&resolved, &c.Overrides[i].Config, c.Overrides[i].Merge)
	}
	return &resolved
}

// matchOverride returns the index of the override governing dir, or -1.
//
// A directory is matched directly first, so an override written for a worktree
// (or for the container it sits in) always wins. Only when nothing matches does
// resolution fall back to the main worktree of the git repository dir belongs
// to: linked worktrees live wherever `git worktree add` put them — often a
// shared container far from the checkout — and configuring each one by hand
// would be unworkable, so a worktree inherits what its repository resolves to.
// Directories that are not linked worktrees never fork git, and neither does a
// config without overrides.
func matchOverride(dir string, overrides []DirectoryOverride) int {
	pathOf := func(o DirectoryOverride) string { return o.Path }
	if i := MatchDirectoryOverride(dir, overrides, pathOf); i >= 0 {
		return i
	}
	if len(overrides) == 0 {
		return -1
	}
	main := gitworktree.MainWorktree(dir)
	if main == "" {
		return -1
	}
	if i := MatchDirectoryOverride(main, overrides, pathOf); i >= 0 {
		return i
	}
	// git reports the main worktree with symlinks resolved (/private/var/...),
	// while an override path is whatever the user wrote (/var/...). Retry with
	// both sides resolved so two spellings of one directory still match.
	return MatchDirectoryOverride(resolveSymlinks(main), overrides, func(o DirectoryOverride) string {
		return resolveSymlinks(expandPath(o.Path))
	})
}

// resolveSymlinks returns path with symlinks resolved, or path itself when it
// cannot be resolved (it may not exist yet, which is not an error here).
func resolveSymlinks(path string) string {
	if path == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// overlayConfig combines the set sections of over onto base (mutating base),
// skipping the Overrides field so an override cannot nest further overrides.
// When deep is false each set section replaces base's wholesale; when deep is
// true it recurses into struct sections and applies only the fields over sets.
// Walking the struct reflectively keeps it complete automatically as new config
// sections are added.
func overlayConfig(base, over *Config, deep bool) {
	bv := reflect.ValueOf(base).Elem()
	ov := reflect.ValueOf(over).Elem()
	t := bv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Overrides" || !f.IsExported() {
			continue
		}
		if deep {
			mergeField(bv.Field(i), ov.Field(i))
			continue
		}
		of := ov.Field(i)
		switch of.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map:
			if !of.IsNil() {
				bv.Field(i).Set(of)
			}
		default:
			// By-value scalar section (none today): set means non-zero.
			if !of.IsZero() {
				bv.Field(i).Set(of)
			}
		}
	}
}

// mergeField deep-merges the value in over into base (same type), used for
// merge:true overrides. Struct pointers recurse field-by-field into a clone of
// base's struct, so an override can set individual fields of a section while
// inheriting the rest without ever mutating the shared base struct. Every other
// kind is a leaf: over's value is taken when it is "set" (a non-nil pointer,
// slice, or map, or a non-zero scalar), otherwise base is kept. The exception
// is a keyed list section (`paths`, `commands`), which is combined entry by
// entry rather than replaced — see keyedEntry.
func mergeField(base, over reflect.Value) {
	switch over.Kind() {
	case reflect.Pointer:
		if over.IsNil() {
			return // override does not set this; keep base
		}
		if over.Elem().Kind() == reflect.Struct {
			merged := reflect.New(over.Elem().Type())
			if !base.IsNil() {
				merged.Elem().Set(base.Elem()) // start from a copy of base's struct
			}
			st := over.Elem().Type()
			for i := 0; i < st.NumField(); i++ {
				if !st.Field(i).IsExported() {
					continue
				}
				mergeField(merged.Elem().Field(i), over.Elem().Field(i))
			}
			base.Set(merged)
			return
		}
		base.Set(over) // pointer to a scalar (e.g. *bool): override wins
	case reflect.Slice:
		if over.IsNil() {
			return
		}
		if isKeyedSlice(over.Type()) {
			base.Set(mergeKeyedSlices(base, over)) // per-entry merge; see keyedEntry
			return
		}
		base.Set(over)
	case reflect.Map:
		if !over.IsNil() {
			base.Set(over)
		}
	default:
		if !over.IsZero() {
			base.Set(over)
		}
	}
}

// keyedEntry is implemented by the element type of a keyed list section: one
// whose entries are independent statements about a subject — `paths` about a
// path, `commands` about a command — rather than an ordered sequence whose
// meaning is the list as a whole. MergeKey returns the subject in the form the
// sandbox matches on, so two spellings of one path (~/x and /home/u/x) or one
// command ("uv  run" and "uv run") are the same statement.
//
// A merge: true override combines such a section with the base entry by entry
// (see mergeKeyedSlices) instead of replacing it wholesale, which is what lets
// a directory add one path grant or deny one command without restating the
// base's whole list.
type keyedEntry interface {
	MergeKey() string
}

var keyedEntryType = reflect.TypeOf((*keyedEntry)(nil)).Elem()

// isKeyedSlice reports whether t is a slice of keyedEntry, i.e. a section
// mergeKeyedSlices can combine per entry.
func isKeyedSlice(t reflect.Type) bool {
	return t.Kind() == reflect.Slice && t.Elem().Implements(keyedEntryType)
}

// mergeKeyedSlices combines a keyed list section from a merge: true override
// with the base's: the base entries whose subject the override does not
// restate, in their original order, followed by every override entry. So the
// base's statements carry into the directory, the override's statement about
// the same path or command replaces it (one statement per subject, as both
// sections require), and statements about new subjects are added.
//
// Neither input is modified: the result is a fresh slice, so a resolved view
// never aliases the stored config.
func mergeKeyedSlices(base, over reflect.Value) reflect.Value {
	restated := make(map[string]bool, over.Len())
	for i := 0; i < over.Len(); i++ {
		restated[mergeKeyOf(over.Index(i))] = true
	}
	out := reflect.MakeSlice(over.Type(), 0, base.Len()+over.Len())
	for i := 0; i < base.Len(); i++ {
		if e := base.Index(i); !restated[mergeKeyOf(e)] {
			out = reflect.Append(out, e)
		}
	}
	return reflect.AppendSlice(out, over)
}

func mergeKeyOf(entry reflect.Value) string {
	return entry.Interface().(keyedEntry).MergeKey()
}

// PruneRestatedEntries rewrites the keyed list sections (`paths`, `commands`)
// of a merge: true override as the delta against base: an entry saying exactly
// what base already says is dropped, since the merge inherits it either way.
// The override then records only what it changes, and later edits to the base
// keep flowing through to the directory instead of hitting a frozen copy. An
// override left stating nothing is reported by SetsAnySection, so the caller
// can drop it.
//
// A replace-mode override is left alone: its sections replace the base's
// outright, so every entry it holds is load-bearing.
func PruneRestatedEntries(o *DirectoryOverride, base *Config) {
	if o == nil || !o.Merge || base == nil {
		return
	}
	ov := reflect.ValueOf(&o.Config).Elem()
	bv := reflect.ValueOf(base).Elem()
	t := ov.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || !isKeyedSlice(f.Type) {
			continue
		}
		ov.Field(i).Set(pruneRestatements(ov.Field(i), bv.Field(i)))
	}
}

// pruneRestatements returns the entries of section that say something base
// does not already say verbatim — the delta a merge: true override needs to
// hold. A nil section stays nil, and one emptied by pruning becomes nil, so an
// override reduced to nothing is dropped by DirectoryOverride.SetsAnySection.
func pruneRestatements(section, base reflect.Value) reflect.Value {
	if section.IsNil() {
		return section
	}
	kept := reflect.MakeSlice(section.Type(), 0, section.Len())
	for i := 0; i < section.Len(); i++ {
		e := section.Index(i)
		if !statesTheSame(base, e) {
			kept = reflect.Append(kept, e)
		}
	}
	if kept.Len() == 0 {
		return reflect.Zero(section.Type())
	}
	return kept
}

// statesTheSame reports whether entries holds an entry equal to e.
func statesTheSame(entries, e reflect.Value) bool {
	for i := 0; i < entries.Len(); i++ {
		if reflect.DeepEqual(entries.Index(i).Interface(), e.Interface()) {
			return true
		}
	}
	return false
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
