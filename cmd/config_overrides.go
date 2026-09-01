package cmd

import "github.com/gartnera/lite-sandbox/config"

// resolveDirArg canonicalizes a user-supplied directory to an absolute path so
// inputs like "." or "../sibling" are stored (and matched) as the concrete
// directory the user meant, not re-resolved later against the server's cwd. It
// falls back to the raw input if resolution fails.
func resolveDirArg(dir string) string {
	if resolved := config.ExpandPath(dir); resolved != "" {
		return resolved
	}
	return dir
}

// findOverride returns a pointer to the existing top-level directory override for
// dir, or nil if none is configured. dir is canonicalized to an absolute path
// first so relative inputs match the concrete directory they were stored as.
// This is shared by every section's --dir handling, not just AWS.
func findOverride(cfg *config.Config, dir string) *config.DirectoryOverride {
	if cfg == nil {
		return nil
	}
	dir = resolveDirArg(dir)
	for i := range cfg.Overrides {
		if cfg.Overrides[i].Path == dir {
			return &cfg.Overrides[i]
		}
	}
	return nil
}

// overridePtr returns a pointer to the directory override for dir, creating an
// empty one (appended) when none exists yet. Callers mutate only the section
// they are editing, so unrelated sections already stored for the same directory
// are preserved. dir is canonicalized to an absolute path so "." and other
// relative inputs are stored as the concrete directory meant.
func overridePtr(cfg *config.Config, dir string) *config.DirectoryOverride {
	dir = resolveDirArg(dir)
	if o := findOverride(cfg, dir); o != nil {
		return o
	}
	cfg.Overrides = append(cfg.Overrides, config.DirectoryOverride{Path: dir})
	return &cfg.Overrides[len(cfg.Overrides)-1]
}

// removeOverride drops the top-level directory override for dir, returning
// whether one was removed. It normalizes an emptied Overrides slice back to nil
// so a cleared config marshals without a stray empty list.
func removeOverride(cfg *config.Config, dir string) bool {
	if cfg == nil || len(cfg.Overrides) == 0 {
		return false
	}
	dir = resolveDirArg(dir)
	kept := cfg.Overrides[:0]
	removed := false
	for _, o := range cfg.Overrides {
		if o.Path == dir {
			removed = true
			continue
		}
		kept = append(kept, o)
	}
	cfg.Overrides = kept
	if len(cfg.Overrides) == 0 {
		cfg.Overrides = nil
	}
	return removed
}
