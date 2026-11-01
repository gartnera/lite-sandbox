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

// findScope returns a pointer to the existing top-level scope for
// dir, or nil if none is configured. dir is canonicalized to an absolute path
// first so relative inputs match the concrete directory they were stored as.
// This is shared by every section's --dir handling, not just AWS.
func findScope(cfg *config.Config, dir string) *config.Scope {
	if cfg == nil {
		return nil
	}
	dir = resolveDirArg(dir)
	for i := range cfg.Scopes {
		if cfg.Scopes[i].Path == dir {
			return &cfg.Scopes[i]
		}
	}
	return nil
}

// scopePtr returns a pointer to the scope for dir, creating an
// empty one (appended) when none exists yet. Callers mutate only the section
// they are editing, so unrelated sections already stored for the same directory
// are preserved. dir is canonicalized to an absolute path so "." and other
// relative inputs are stored as the concrete directory meant.
func scopePtr(cfg *config.Config, dir string) *config.Scope {
	dir = resolveDirArg(dir)
	if o := findScope(cfg, dir); o != nil {
		return o
	}
	cfg.Scopes = append(cfg.Scopes, config.Scope{Path: dir})
	return &cfg.Scopes[len(cfg.Scopes)-1]
}

// removeScope drops the top-level scope for dir, returning
// whether one was removed. It normalizes an emptied Scopes slice back to nil
// so a cleared config marshals without a stray empty list.
func removeScope(cfg *config.Config, dir string) bool {
	if cfg == nil || len(cfg.Scopes) == 0 {
		return false
	}
	dir = resolveDirArg(dir)
	kept := cfg.Scopes[:0]
	removed := false
	for _, o := range cfg.Scopes {
		if o.Path == dir {
			removed = true
			continue
		}
		kept = append(kept, o)
	}
	cfg.Scopes = kept
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = nil
	}
	return removed
}
