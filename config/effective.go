package config

import "slices"

// Effective returns the config as the sandbox consumes it: every statement
// about a path in the one Paths list and every statement about a command in
// the one Commands list, so nothing downstream has to know how they were
// spelled or where they came from. It folds in, in order:
//
//   - the deprecated one-list-per-kind path and command keys (readable_paths,
//     extra_commands, ...), as MigratePaths and MigrateCommands rewrite them;
//   - the deprecated runtimes section, as MigrateRuntimes rewrites it (into
//     Profiles and commands entries such as "cargo publish");
//   - every enabled profile's commands entries and paths entries (detected
//     now), each marked with the profile's name (CommandEntry.Profile,
//     PathEntry.Profile).
//
// Call it on a config already resolved for its directory (ForDirectory):
// overrides are dropped, not applied. LoadForDirectory does both. The result is
// a new config (the receiver is not modified) and calling Effective on it again
// returns it unchanged. It is never saved: the CLI edits the config as
// written, and the entries Effective adds would otherwise be persisted.
func (c *Config) Effective() *Config {
	if c == nil {
		c = &Config{}
	}
	if c.effective {
		return c
	}
	e := *c
	e.Overrides = nil
	e.Paths = slices.Clone(c.Paths)
	e.Commands = slices.Clone(c.Commands)
	e.Profiles = slices.Clone(c.Profiles)
	e.MigratePaths()
	e.MigrateCommands()
	e.MigrateRuntimes()
	for _, p := range e.EnabledProfiles() {
		e.Commands = append(e.Commands, p.CommandEntries()...)
		e.Paths = append(e.Paths, p.PathEntries()...)
	}
	e.effective = true
	return &e
}
