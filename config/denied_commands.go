package config

import (
	"os"
	"path/filepath"
	"strings"
)

// selfProtectionSubcommands are the lite-sandbox subcommands a sandboxed
// command must never reach: each one rewrites the policy that is supposed to
// be governing it.
//
//   - config:  edits the config file (mode, commands, paths, ...),
//     which the MCP server hot-reloads, so `config mode set open` disables
//     enforcement for the very next command.
//   - install: rewrites the agents' own settings — including the built-in Bash
//     deny that forces the agent through the sandbox in the first place.
//   - update:  replaces the lite-sandbox binary, i.e. the enforcer itself.
//   - hook:    the PreToolUse hook that confines the agent's built-in file
//     tools; running it by hand can emit an "allow" decision.
var selfProtectionSubcommands = []string{"config", "install", "update", "hook"}

// DefaultDeniedCommands returns the built-in command deny list: the sandbox's
// own policy-editing subcommands, for both the canonical binary name and the
// name this binary was actually installed under.
//
// The OS sandbox already makes these writes fail in denylist mode (the config
// file and the agents' settings are in DefaultDeniedWritePaths, mounted
// read-only in the worker), but it is off by default and unavailable on hosts
// without bubblewrap. This list is the validation-layer half of the same
// protection: it holds whenever the mode enforces it, OS sandbox or not.
//
// It is deliberately narrow. Denying the whole binary would block the
// read-only subcommands (`version`, `config show`, `audit report`) an agent
// legitimately uses to explain its own constraints; denying broader classes of
// program (sudo, crontab, ...) is a policy decision left to denied_commands.
func DefaultDeniedCommands() []string {
	out := make([]string, 0, 2*len(selfProtectionSubcommands))
	for _, name := range selfCommandNames() {
		for _, sub := range selfProtectionSubcommands {
			out = append(out, name+" "+sub)
		}
	}
	return out
}

// selfCommandNames returns the names this binary may be invoked as: the
// canonical one, plus the running executable's own name when it was installed
// under a different one. Test binaries are skipped so a test run does not
// inherit deny entries named after itself.
func selfCommandNames() []string {
	names := []string{appName}
	exe, err := os.Executable()
	if err != nil {
		return names
	}
	base := filepath.Base(exe)
	if base == appName || base == "" || strings.HasSuffix(base, ".test") {
		return names
	}
	return append(names, base)
}

// EffectiveDeniedCommands returns the command deny list in effect: the
// built-in defaults plus the config's denials (commands entries with
// allow: false, and the deprecated denied_commands list), minus the built-ins
// lifted by a commands entry with allow: true of the same text
// (LiftedDeniedCommands). In the deprecated list an entry prefixed by "-"
// removes a previously listed one the same way: `denied_commands:
// ["-lite-sandbox config"]`.
//
// Entries keep the extra_commands format: a bare name denies every invocation
// of that command, a name followed by tokens denies only invocations whose
// leading non-flag arguments start with them.
func (c *Config) EffectiveDeniedCommands() []string {
	extra := c.DeniedCommandList()
	out := make([]string, 0, len(DefaultDeniedCommands())+len(extra))
	seen := map[string]bool{}
	removed := map[string]bool{}
	for _, lifted := range c.LiftedDeniedCommands() {
		removed[lifted] = true
	}
	add := func(e string) {
		e = NormalizeCommandEntry(e)
		if e == "" {
			return
		}
		if neg, ok := strings.CutPrefix(e, "-"); ok {
			removed[NormalizeCommandEntry(neg)] = true
			return
		}
		if seen[e] {
			return
		}
		seen[e] = true
		out = append(out, e)
	}
	for _, e := range DefaultDeniedCommands() {
		add(e)
	}
	for _, e := range extra {
		add(e)
	}
	if len(removed) == 0 {
		return out
	}
	kept := out[:0]
	for _, e := range out {
		if !removed[e] {
			kept = append(kept, e)
		}
	}
	return kept
}

// IsDefaultDeniedCommand reports whether entry is one of the built-in deny
// entries, which `config denied-commands remove` has to negate rather than
// delete.
func IsDefaultDeniedCommand(entry string) bool {
	entry = NormalizeCommandEntry(entry)
	for _, d := range DefaultDeniedCommands() {
		if d == entry {
			return true
		}
	}
	return false
}

// NormalizeCommandEntry collapses an entry's internal whitespace so
// "lite-sandbox  config" and "lite-sandbox config" are the same entry. The CLI
// normalizes with it too, so what `denied-commands remove` is given matches
// what the deny list holds.
func NormalizeCommandEntry(e string) string {
	return strings.Join(strings.Fields(e), " ")
}
