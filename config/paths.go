package config

import (
	"fmt"
	"strings"
)

// PathEntry is one entry of the `paths` list: a path plus what sandboxed
// commands may do there. Read and Write are tri-state — unset says nothing
// about that access, true grants it, false denies it — so a single list covers
// what used to take six separate ones:
//
//	paths:
//	  - path: ~/reference-data     # readable                (was readable_paths)
//	    read: true
//	  - path: ~/scratch            # writable, implies read  (was writable_paths)
//	    write: true
//	  - path: ~/.cache/some-tool   # OS-sandbox layer only   (was internal_writable_paths)
//	    write: true
//	    internal: true
//	  - path: ~/company-secrets    # hidden entirely         (was denied_read_paths)
//	    read: false
//	  - path: ~/.local/bin         # readable, not writable  (was denied_write_paths)
//	    write: false
//
// A grant (true) widens the boundary the agent may touch, at every layer; with
// Internal it widens only the OS-sandbox layer, for programs a command spawns
// (the agent's own reads and writes there are still refused). A denial (false)
// is applied by the OS sandbox in denylist mode on top of the built-in deny
// lists (DefaultDeniedReadPaths / DefaultDeniedWritePaths): read: false hides
// the path entirely, write: false keeps it readable but not modifiable. Path
// supports ~ expansion and, for grants, the trailing /* nested-only form.
type PathEntry struct {
	Path     string `yaml:"path"`
	Read     *bool  `yaml:"read,omitempty"`
	Write    *bool  `yaml:"write,omitempty"`
	Internal bool   `yaml:"internal,omitempty"`
}

// GrantsRead reports whether the entry explicitly grants read access
// (read: true). A write grant implies read for every consumer, but is
// reported by GrantsWrite so the two stay distinct lists, as they always were.
func (e PathEntry) GrantsRead() bool { return e.Read != nil && *e.Read }

// GrantsWrite reports whether the entry grants write access (write: true).
func (e PathEntry) GrantsWrite() bool { return e.Write != nil && *e.Write }

// DeniesRead reports whether the entry hides the path (read: false).
func (e PathEntry) DeniesRead() bool { return e.Read != nil && !*e.Read }

// DeniesWrite reports whether the entry makes the path read-only (write: false).
func (e PathEntry) DeniesWrite() bool { return e.Write != nil && !*e.Write }

// Grants reports whether the entry grants any access.
func (e PathEntry) Grants() bool { return e.GrantsRead() || e.GrantsWrite() }

// Denies reports whether the entry denies any access.
func (e PathEntry) Denies() bool { return e.DeniesRead() || e.DeniesWrite() }

// Validate rejects an entry that says nothing or contradicts itself.
func (e PathEntry) Validate() error {
	if strings.TrimSpace(e.Path) == "" {
		return fmt.Errorf("paths entry without a path")
	}
	if e.Read == nil && e.Write == nil {
		return fmt.Errorf("paths entry %q sets neither read nor write", e.Path)
	}
	if e.DeniesRead() && e.GrantsWrite() {
		return fmt.Errorf("paths entry %q: read: false hides the path, so write: true cannot apply", e.Path)
	}
	if e.Internal && e.Denies() {
		return fmt.Errorf("paths entry %q: internal applies to grants only (a denial already acts at the OS sandbox layer alone)", e.Path)
	}
	return nil
}

// Describe renders the entry's access as a short phrase for listings:
// "read", "read, write", "deny read", "read, deny write", with an
// "(internal: OS sandbox layer only)" suffix for internal grants.
func (e PathEntry) Describe() string {
	var parts []string
	switch {
	case e.GrantsWrite():
		parts = append(parts, "read, write")
	case e.GrantsRead():
		parts = append(parts, "read")
	}
	if e.DeniesRead() {
		parts = append(parts, "deny read")
	}
	if e.DeniesWrite() {
		parts = append(parts, "deny write")
	}
	s := strings.Join(parts, ", ")
	if e.Internal {
		s += " (internal: OS sandbox layer only)"
	}
	return s
}

// SamePath reports whether the entry names the same path as p, comparing the
// expanded absolute forms so ~/x and /home/u/x match.
func (e PathEntry) SamePath(p string) bool {
	return expandPath(e.Path) == expandPath(p)
}

// validatePaths rejects a malformed paths entry on the base config or any
// override, so a typo cannot silently grant or deny nothing.
func (c *Config) validatePaths() error {
	if err := validatePathEntries(c.Paths); err != nil {
		return err
	}
	for _, o := range c.Overrides {
		if err := validatePathEntries(o.Paths); err != nil {
			return fmt.Errorf("override %q: %w", o.Path, err)
		}
	}
	return nil
}

func validatePathEntries(entries []PathEntry) error {
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// pathsWhere returns the deprecated list followed by the paths of the entries
// matching pred, which is how every accessor below reads both spellings at
// once: a config still using readable_paths and one using paths resolve the
// same, and a file mixing the two is the union.
func (c *Config) pathsWhere(legacy func(*Config) []string, pred func(PathEntry) bool) []string {
	if c == nil {
		return nil
	}
	out := append([]string(nil), legacy(c)...)
	for _, e := range c.Paths {
		if pred(e) {
			out = append(out, e.Path)
		}
	}
	return out
}

// ReadablePathList returns every path granted read access to the agent (not
// internal), as written: the paths entries with read: true plus the deprecated
// readable_paths list. Writable paths are readable too but are listed by
// WritablePathList, as they always were.
func (c *Config) ReadablePathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.ReadablePaths }, func(e PathEntry) bool { return e.GrantsRead() && !e.Internal })
}

// WritablePathList returns every path granted write access to the agent (not
// internal), as written.
func (c *Config) WritablePathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.WritablePaths }, func(e PathEntry) bool { return e.GrantsWrite() && !e.Internal })
}

// InternalReadablePathList returns every path granted read access at the OS
// sandbox layer only, as written.
func (c *Config) InternalReadablePathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.InternalReadablePaths }, func(e PathEntry) bool { return e.GrantsRead() && e.Internal })
}

// InternalWritablePathList returns every path granted write access at the OS
// sandbox layer only, as written.
func (c *Config) InternalWritablePathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.InternalWritablePaths }, func(e PathEntry) bool { return e.GrantsWrite() && e.Internal })
}

// DeniedReadPathList returns the user-added read-denied paths, as written
// (without the built-in defaults; see EffectiveDeniedReadEntries).
func (c *Config) DeniedReadPathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.DeniedReadPaths }, PathEntry.DeniesRead)
}

// DeniedWritePathList returns the user-added write-denied paths, as written
// (without the built-in defaults; see EffectiveDeniedWriteEntries).
func (c *Config) DeniedWritePathList() []string {
	return c.pathsWhere(func(c *Config) []string { return c.DeniedWritePaths }, PathEntry.DeniesWrite)
}

// ExpandedReadablePaths returns ReadablePathList with ~ expanded to the user's
// home directory and all paths resolved to absolute paths.
func (c *Config) ExpandedReadablePaths() []string {
	return expandPaths(c.ReadablePathList())
}

// ExpandedWritablePaths returns WritablePathList with ~ expanded to the user's
// home directory and all paths resolved to absolute paths.
func (c *Config) ExpandedWritablePaths() []string {
	return expandPaths(c.WritablePathList())
}

// ExpandedInternalReadablePaths returns InternalReadablePathList with ~
// expanded to the user's home directory and all paths resolved to absolute.
func (c *Config) ExpandedInternalReadablePaths() []string {
	return expandPaths(c.InternalReadablePathList())
}

// ExpandedInternalWritablePaths returns InternalWritablePathList with ~
// expanded to the user's home directory and all paths resolved to absolute.
func (c *Config) ExpandedInternalWritablePaths() []string {
	return expandPaths(c.InternalWritablePathList())
}

// SetPath records entry as the single statement about its path: any existing
// paths entry for the same path is dropped, and so is the path from each of
// the deprecated lists, so the CLI migrates a path to the new form the moment
// it touches it. Returns entry's validation error, if any, before changing
// anything.
func (c *Config) SetPath(entry PathEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	c.RemovePath(entry.Path)
	c.Paths = append(c.Paths, entry)
	return nil
}

// RemovePath drops every statement about p — paths entries and deprecated-list
// mentions alike — and reports whether there was one. Paths compare by their
// expanded absolute form.
func (c *Config) RemovePath(p string) bool {
	found := false
	kept := c.Paths[:0:0]
	for _, e := range c.Paths {
		if e.SamePath(p) {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) > 0 {
		c.Paths = kept
	} else {
		c.Paths = nil
	}
	for _, list := range []*[]string{
		&c.ReadablePaths, &c.WritablePaths,
		&c.InternalReadablePaths, &c.InternalWritablePaths,
		&c.DeniedReadPaths, &c.DeniedWritePaths,
	} {
		if removeStringPath(list, p) {
			found = true
		}
	}
	return found
}

func removeStringPath(list *[]string, p string) bool {
	want := expandPath(p)
	found := false
	var kept []string
	for _, v := range *list {
		if expandPath(v) == want {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	if found {
		*list = kept
	}
	return found
}

// usesLegacyPathKeys reports whether any of the six deprecated path lists is set.
func (c *Config) usesLegacyPathKeys() bool {
	return len(c.ReadablePaths) > 0 || len(c.WritablePaths) > 0 ||
		len(c.InternalReadablePaths) > 0 || len(c.InternalWritablePaths) > 0 ||
		len(c.DeniedReadPaths) > 0 || len(c.DeniedWritePaths) > 0
}

// LegacyPathEntries converts the deprecated lists into the equivalent paths
// entries — readable_paths to read: true, writable_paths to write: true, the
// internal lists likewise with internal: true, denied_read_paths to
// read: false, denied_write_paths to write: false — without changing c.
func (c *Config) LegacyPathEntries() []PathEntry {
	if c == nil {
		return nil
	}
	yes, no := true, false
	var out []PathEntry
	for _, p := range c.ReadablePaths {
		out = append(out, PathEntry{Path: p, Read: &yes})
	}
	for _, p := range c.WritablePaths {
		out = append(out, PathEntry{Path: p, Write: &yes})
	}
	for _, p := range c.InternalReadablePaths {
		out = append(out, PathEntry{Path: p, Read: &yes, Internal: true})
	}
	for _, p := range c.InternalWritablePaths {
		out = append(out, PathEntry{Path: p, Write: &yes, Internal: true})
	}
	for _, p := range c.DeniedReadPaths {
		out = append(out, PathEntry{Path: p, Read: &no})
	}
	for _, p := range c.DeniedWritePaths {
		out = append(out, PathEntry{Path: p, Write: &no})
	}
	return out
}

// AllPathEntries returns every path statement in c in the new form: the paths
// entries followed by the deprecated lists converted with LegacyPathEntries.
func (c *Config) AllPathEntries() []PathEntry {
	if c == nil {
		return nil
	}
	return append(append([]PathEntry(nil), c.Paths...), c.LegacyPathEntries()...)
}

// UsesDeprecatedPathKeys reports whether the base config or any override still
// spells a path list the old way, which MigratePaths rewrites.
func (c *Config) UsesDeprecatedPathKeys() bool {
	if c == nil {
		return false
	}
	if c.usesLegacyPathKeys() {
		return true
	}
	for _, o := range c.Overrides {
		if o.usesLegacyPathKeys() {
			return true
		}
	}
	return false
}

// MigratePaths rewrites the six deprecated path lists — on the base config and
// on every override — as paths entries and clears them, keeping what every
// directory resolves to. Returns the number of entries written.
//
// The two spellings are not one-to-one under overrides: an old-style override
// replaced only the one list it set and inherited the other five, whereas a
// paths list replaces the whole section. So an override that set any path list
// (or already had a paths list) gets the full set of entries in effect for its
// directory — the base's for every list it did not set — before its own lists
// are cleared; one that set none keeps inheriting the migrated base.
func (c *Config) MigratePaths() int {
	if c == nil {
		return 0
	}
	n := 0
	for i := range c.Overrides {
		o := &c.Overrides[i]
		if o.Paths == nil && !o.usesLegacyPathKeys() {
			continue
		}
		// The lists in effect for the override's directory: its own where set,
		// the base's otherwise, exactly as ForDirectory combined them.
		resolved := Config{
			ReadablePaths:         pickList(o.ReadablePaths, c.ReadablePaths),
			WritablePaths:         pickList(o.WritablePaths, c.WritablePaths),
			InternalReadablePaths: pickList(o.InternalReadablePaths, c.InternalReadablePaths),
			InternalWritablePaths: pickList(o.InternalWritablePaths, c.InternalWritablePaths),
			DeniedReadPaths:       pickList(o.DeniedReadPaths, c.DeniedReadPaths),
			DeniedWritePaths:      pickList(o.DeniedWritePaths, c.DeniedWritePaths),
		}
		entries := o.Paths
		if entries == nil {
			entries = c.Paths
		}
		converted := resolved.LegacyPathEntries()
		o.Paths = appendUniqueEntries(append([]PathEntry(nil), entries...), converted)
		n += len(converted)
		o.clearLegacyPathKeys()
	}
	converted := c.LegacyPathEntries()
	if len(converted) > 0 {
		c.Paths = appendUniqueEntries(c.Paths, converted)
		n += len(converted)
		c.clearLegacyPathKeys()
	}
	return n
}

func pickList(override, base []string) []string {
	if override != nil {
		return override
	}
	return base
}

func (c *Config) clearLegacyPathKeys() {
	c.ReadablePaths, c.WritablePaths = nil, nil
	c.InternalReadablePaths, c.InternalWritablePaths = nil, nil
	c.DeniedReadPaths, c.DeniedWritePaths = nil, nil
}

// appendUniqueEntries appends the entries of add that are not already in list
// (same path as written, same flags).
func appendUniqueEntries(list, add []PathEntry) []PathEntry {
	for _, e := range add {
		dup := false
		for _, have := range list {
			if have.Path == e.Path && have.Internal == e.Internal &&
				boolPtrEqual(have.Read, e.Read) && boolPtrEqual(have.Write, e.Write) {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, e)
		}
	}
	return list
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
