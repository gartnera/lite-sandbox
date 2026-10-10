package config

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

// CommandScope is a set of commands that share the same scoped grants: the
// paths entries with internal: true and a commands list naming each of them.
// The sandbox runs those commands in an OS sandbox worker of their own, built
// from ForScope, so the grants reach them and nothing else: the shared worker
// every other command runs in hides the paths (ScopedDeniedReadEntries), in
// every mode. A program the agent writes therefore cannot read a credential
// granted to gh, and a gh it launches itself runs in the shared worker,
// without it.
//
// Commands that name exactly the same entries share one scope (one worker):
// two entries both scoped to [gh, hub] make one scope for both commands,
// while one scoped to [gh] and another to [hub] make two.
type CommandScope struct {
	// Key identifies the scope among the config's scopes: its commands,
	// sorted and comma-joined.
	Key string
	// Commands are the command names in the scope, sorted.
	Commands []string
	// Entries are the scoped paths entries the commands get, in config order.
	Entries []PathEntry
}

// CommandScopes returns the config's command scopes, ordered by key. A config
// without scoped grants returns nil.
func (c *Config) CommandScopes() []CommandScope {
	if c == nil {
		return nil
	}
	// Each command's entries, by index into Paths, in config order.
	perCommand := make(map[string][]int)
	for i, e := range c.Paths {
		if !e.Scoped() || !e.Grants() {
			continue
		}
		for _, name := range e.Commands {
			if idx := perCommand[name]; len(idx) == 0 || idx[len(idx)-1] != i {
				perCommand[name] = append(idx, i)
			}
		}
	}
	// Commands with the same entries share a scope.
	bySet := make(map[string]*CommandScope)
	for name, idx := range perCommand {
		set := indexKey(idx)
		s, ok := bySet[set]
		if !ok {
			s = &CommandScope{}
			for _, i := range idx {
				s.Entries = append(s.Entries, c.Paths[i])
			}
			bySet[set] = s
		}
		s.Commands = append(s.Commands, name)
	}
	out := make([]CommandScope, 0, len(bySet))
	for _, s := range bySet {
		sort.Strings(s.Commands)
		s.Key = strings.Join(s.Commands, ",")
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if len(out) == 0 {
		return nil
	}
	return out
}

func indexKey(idx []int) string { return fmt.Sprint(idx) }

// ScopeForCommand returns the scope whose worker runs the command name, if a
// scoped grant names it. name is matched exactly: the bare command name as
// invoked, never a path to a binary.
func (c *Config) ScopeForCommand(name string) (CommandScope, bool) {
	for _, s := range c.CommandScopes() {
		if slices.Contains(s.Commands, name) {
			return s, true
		}
	}
	return CommandScope{}, false
}

// ForScope returns the config the scope's worker is built from: a copy of c in
// which the scope's entries are ordinary internal grants. The worker then gets
// them the way any internal grant reaches a worker (a writable or read-only
// bind), and the built-in denial on the same path (~/.config/gh is one) is
// lifted the way a grant lifts it — but only there. Entries of other scopes
// stay scoped, so this worker hides them too.
//
// That holds for a profile's scoped grant too, although a profile's grant
// otherwise never lifts a built-in denial: that rule keeps a profile from
// exposing a path to every command, and a scoped grant exposes it only to the
// commands it names, while every other worker still hides it.
func (c *Config) ForScope(s CommandScope) *Config {
	cp := *c
	cp.Paths = slices.Clone(c.Paths)
	for i, e := range cp.Paths {
		if !e.Scoped() || !scopeHasEntry(s, e) {
			continue
		}
		e.Commands = nil
		e.Profile = ""
		cp.Paths[i] = e
	}
	return &cp
}

func scopeHasEntry(s CommandScope, e PathEntry) bool {
	for _, have := range s.Entries {
		if have.Path == e.Path && have.Internal == e.Internal &&
			boolPtrEqual(have.Read, e.Read) && boolPtrEqual(have.Write, e.Write) &&
			slices.Equal(have.Commands, e.Commands) && have.Profile == e.Profile {
			return true
		}
	}
	return false
}

// ScopedDeniedReadEntries returns the paths of the config's scoped grants as
// read denials: what a worker that is not the grants' own must hide, in every
// mode. A path an unscoped grant also names is left out, since that grant
// already gives it to every command. ~ is expanded and each entry classified
// by what exists on disk, like a user's read: false entry — except a missing
// path a write grant names, which is a directory: the scope's own worker
// creates it as one (a writable bind), so it is created and masked here too
// rather than left visible to the shared worker once the command fills it.
func (c *Config) ScopedDeniedReadEntries() []DeniedPath {
	if c == nil {
		return nil
	}
	var out []DeniedPath
	for _, e := range c.Paths {
		if !e.Scoped() || !e.Grants() {
			continue
		}
		shared := false
		for _, other := range c.AllPathEntries() {
			if !other.Scoped() && other.Grants() && other.SamePath(e.Path) {
				shared = true
				break
			}
		}
		if shared {
			continue
		}
		p := expandPath(e.Path)
		out = append(out, DeniedPath{Path: p, Dir: dirExists(p) || (e.GrantsWrite() && !pathExists(p))})
	}
	return uniqueDeniedPaths(out)
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ScopeBypass explains why a command a scoped grant names would not run in
// its scope's worker, or returns "" when it would. Two allows route around
// the worker: a bare allow runs the whole command line through `bash -c`,
// which never goes to a scoped worker (it could run anything), and no_sandbox
// runs the command on the host, outside every worker.
func (c *Config) ScopeBypass(name string) string {
	for _, cmd := range c.UnsandboxedCommandList() {
		if f := strings.Fields(cmd); len(f) > 0 && f[0] == name {
			return fmt.Sprintf("%q is allowed with no_sandbox, so it runs on the host, outside the OS sandbox, where nothing is hidden", cmd)
		}
	}
	for _, cmd := range c.ExtraCommandList() {
		if strings.TrimSpace(cmd) == name {
			return fmt.Sprintf("the bare allow of %s runs a command line starting with it through bash -c in the shared worker, without the grant; allow its subcommands instead (\"%s <subcommand>\")", name, name)
		}
	}
	return ""
}
