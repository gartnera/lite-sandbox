package config

import (
	"fmt"
	"strings"
)

// CommandEntry is one entry of the `commands` list: a command plus what the
// sandbox does with it. Allow is tri-state — unset says nothing, true allows,
// false denies — so a single list covers what used to take three separate
// ones:
//
//	commands:
//	  - command: curl              # allowed past the whitelist   (was extra_commands)
//	    allow: true
//	  - command: uv run pyright    # only invocations starting with those arguments
//	    allow: true
//	  - command: docker            # allowed, and runs on the host (was unsandboxed_commands)
//	    allow: true
//	    no_sandbox: true
//	  - command: sudo              # refused however else it is allowed (was denied_commands)
//	    allow: false
//	  - command: lite-sandbox update   # an allow on a built-in denial lifts it
//	    allow: true                    # (was "-lite-sandbox update")
//
// Command is a bare name ("curl", "./scripts/deploy.sh") or a name followed by
// the leading non-flag arguments the entry is limited to ("uv run pyright",
// "git push"); internal whitespace is not significant. A bare allow admits the
// command with any arguments and, when it leads an invocation, skips bash AST
// parsing entirely (the command string runs via real bash); a restricted allow
// still goes through parsing and validation. NoSandbox, on an allow, makes
// matching invocations run directly on the host, bypassing the OS sandbox
// worker even when it is enabled. A denial is checked before every command
// gate and outranks every allow, so `git push` denied and `git` allowed refuse
// exactly the pushes. The one exception is the built-in deny list
// (DefaultDeniedCommands): an allow whose text equals a built-in entry lifts
// that entry, which is how `lite-sandbox update` is opened up.
type CommandEntry struct {
	Command   string `yaml:"command"`
	Allow     *bool  `yaml:"allow,omitempty"`
	NoSandbox bool   `yaml:"no_sandbox,omitempty"`
}

// Allows reports whether the entry allows the command (allow: true).
func (e CommandEntry) Allows() bool { return e.Allow != nil && *e.Allow }

// Denies reports whether the entry denies the command (allow: false).
func (e CommandEntry) Denies() bool { return e.Allow != nil && !*e.Allow }

// Text returns the entry's command with its whitespace normalized, which is
// the form the sandbox matches and the deny list stores.
func (e CommandEntry) Text() string { return NormalizeCommandEntry(e.Command) }

// Validate rejects an entry that says nothing or contradicts itself.
func (e CommandEntry) Validate() error {
	if e.Text() == "" {
		return fmt.Errorf("commands entry without a command")
	}
	if e.Allow == nil {
		return fmt.Errorf("commands entry %q sets neither allow: true nor allow: false", e.Command)
	}
	if e.NoSandbox && e.Denies() {
		return fmt.Errorf("commands entry %q: no_sandbox applies to an allow only (a denied command never runs)", e.Command)
	}
	if strings.HasPrefix(e.Text(), "-") {
		return fmt.Errorf("commands entry %q: a leading \"-\" is the deprecated denied_commands way to lift a built-in entry; write the entry with allow: true instead", e.Command)
	}
	return nil
}

// Describe renders the entry's effect as a short phrase for listings:
// "allow", "allow, no sandbox", or "deny".
func (e CommandEntry) Describe() string {
	switch {
	case e.Denies():
		return "deny"
	case e.NoSandbox:
		return "allow, no sandbox (runs on the host, outside the OS sandbox)"
	default:
		return "allow"
	}
}

// SameCommand reports whether the entry names the same command text as c,
// comparing the whitespace-normalized forms.
func (e CommandEntry) SameCommand(c string) bool {
	return e.Text() == NormalizeCommandEntry(c)
}

// validateCommands rejects a malformed commands entry on the base config or
// any override, so a typo cannot silently allow or deny nothing.
func (c *Config) validateCommands() error {
	if err := validateCommandEntries(c.Commands); err != nil {
		return err
	}
	for _, o := range c.Overrides {
		if err := validateCommandEntries(o.Commands); err != nil {
			return fmt.Errorf("override %q: %w", o.Path, err)
		}
	}
	return nil
}

func validateCommandEntries(entries []CommandEntry) error {
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// commandsWhere returns the deprecated list followed by the commands of the
// entries matching pred, which is how every accessor below reads both
// spellings at once: a config still using extra_commands and one using
// commands resolve the same, and a file mixing the two is the union.
func (c *Config) commandsWhere(legacy func(*Config) []string, pred func(CommandEntry) bool) []string {
	if c == nil {
		return nil
	}
	out := append([]string(nil), legacy(c)...)
	for _, e := range c.Commands {
		if pred(e) {
			out = append(out, e.Command)
		}
	}
	return out
}

// ExtraCommandList returns every command allowed inside the sandbox, as
// written: the commands entries with allow: true and no no_sandbox, plus the
// deprecated extra_commands list. Commands allowed with no_sandbox are listed
// by UnsandboxedCommandList instead, as the two lists always were distinct.
func (c *Config) ExtraCommandList() []string {
	return c.commandsWhere(func(c *Config) []string { return c.ExtraCommands }, func(e CommandEntry) bool { return e.Allows() && !e.NoSandbox })
}

// UnsandboxedCommandList returns every command allowed to run on the host,
// outside the OS sandbox, as written: the commands entries with allow: true
// and no_sandbox: true, plus the deprecated unsandboxed_commands list.
func (c *Config) UnsandboxedCommandList() []string {
	return c.commandsWhere(func(c *Config) []string { return c.UnsandboxedCommands }, func(e CommandEntry) bool { return e.Allows() && e.NoSandbox })
}

// DeniedCommandList returns the user-added deny entries, as written and
// without the built-in defaults: the commands entries with allow: false, plus
// the deprecated denied_commands list (whose "-" entries are kept for
// EffectiveDeniedCommands to apply). See EffectiveDeniedCommands for the list
// in force.
func (c *Config) DeniedCommandList() []string {
	return c.commandsWhere(func(c *Config) []string { return c.DeniedCommands }, CommandEntry.Denies)
}

// LiftedDeniedCommands returns the built-in deny entries (DefaultDeniedCommands)
// that an allow lifts: a commands entry with allow: true, or a deprecated
// denied_commands "-" entry, of the same text. Only an entry whose text equals
// the built-in's lifts it: a bare `lite-sandbox` allow leaves every
// `lite-sandbox <subcommand>` entry in force, as a bare extra_commands entry
// always did, so allowing a command never silently drops the deny list
// underneath it.
func (c *Config) LiftedDeniedCommands() []string {
	if c == nil {
		return nil
	}
	var out []string
	entries := c.AllCommandEntries()
	for _, d := range DefaultDeniedCommands() {
		for _, e := range entries {
			if e.Allows() && e.SameCommand(d) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// SetCommand records entry as the single statement about its command text:
// any existing commands entry for the same text is dropped, and so is the text
// from each of the deprecated lists (a "-" lift of it included), so the CLI
// migrates a command to the new form the moment it touches it. Returns
// entry's validation error, if any, before changing anything.
func (c *Config) SetCommand(entry CommandEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	entry.Command = entry.Text()
	c.RemoveCommand(entry.Command)
	c.Commands = append(c.Commands, entry)
	return nil
}

// RemoveCommand drops every statement about the command text — commands
// entries and deprecated-list mentions alike, a denied_commands "-" lift of it
// included — and reports whether there was one. Texts compare with their
// whitespace normalized.
func (c *Config) RemoveCommand(text string) bool {
	text = NormalizeCommandEntry(text)
	found := false
	kept := c.Commands[:0:0]
	for _, e := range c.Commands {
		if e.SameCommand(text) {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) > 0 {
		c.Commands = kept
	} else {
		c.Commands = nil
	}
	for _, list := range []*[]string{&c.ExtraCommands, &c.UnsandboxedCommands} {
		if removeCommandText(list, text) {
			found = true
		}
	}
	if removeCommandText(&c.DeniedCommands, text) {
		found = true
	}
	if removeCommandText(&c.DeniedCommands, "-"+text) {
		found = true
	}
	return found
}

func removeCommandText(list *[]string, text string) bool {
	found := false
	var kept []string
	for _, v := range *list {
		if NormalizeCommandEntry(v) == text {
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

// usesLegacyCommandKeys reports whether any of the three deprecated command
// lists is set.
func (c *Config) usesLegacyCommandKeys() bool {
	return len(c.ExtraCommands) > 0 || len(c.UnsandboxedCommands) > 0 || len(c.DeniedCommands) > 0
}

// LegacyCommandEntries converts the deprecated lists into the equivalent
// commands entries — extra_commands to allow: true, unsandboxed_commands to
// allow: true with no_sandbox: true, denied_commands to allow: false and its
// "-" entries to allow: true — without changing c.
func (c *Config) LegacyCommandEntries() []CommandEntry {
	if c == nil {
		return nil
	}
	yes, no := true, false
	var out []CommandEntry
	for _, x := range c.ExtraCommands {
		if t := NormalizeCommandEntry(x); t != "" {
			out = append(out, CommandEntry{Command: t, Allow: &yes})
		}
	}
	for _, x := range c.UnsandboxedCommands {
		if t := NormalizeCommandEntry(x); t != "" {
			out = append(out, CommandEntry{Command: t, Allow: &yes, NoSandbox: true})
		}
	}
	for _, x := range c.DeniedCommands {
		t := NormalizeCommandEntry(x)
		if t == "" {
			continue
		}
		if lifted, ok := strings.CutPrefix(t, "-"); ok {
			if lifted = NormalizeCommandEntry(lifted); lifted != "" {
				out = append(out, CommandEntry{Command: lifted, Allow: &yes})
			}
			continue
		}
		out = append(out, CommandEntry{Command: t, Allow: &no})
	}
	return out
}

// AllCommandEntries returns every command statement in c in the new form: the
// commands entries followed by the deprecated lists converted with
// LegacyCommandEntries.
func (c *Config) AllCommandEntries() []CommandEntry {
	if c == nil {
		return nil
	}
	return append(append([]CommandEntry(nil), c.Commands...), c.LegacyCommandEntries()...)
}

// UsesDeprecatedCommandKeys reports whether the base config or any override
// still spells a command list the old way, which MigrateCommands rewrites.
func (c *Config) UsesDeprecatedCommandKeys() bool {
	if c == nil {
		return false
	}
	if c.usesLegacyCommandKeys() {
		return true
	}
	for _, o := range c.Overrides {
		if o.usesLegacyCommandKeys() {
			return true
		}
	}
	return false
}

// MigrateCommands rewrites the three deprecated command lists — on the base
// config and on every override — as commands entries and clears them, keeping
// what every directory resolves to. Returns the number of entries written.
//
// The two spellings are not one-to-one under overrides: an old-style override
// replaced only the one list it set and inherited the other two, whereas a
// commands list replaces the whole section. So an override that set any
// command list (or already had a commands list) gets the full set of entries
// in effect for its directory — the base's for every list it did not set —
// before its own lists are cleared; one that set none keeps inheriting the
// migrated base.
//
// A denied_commands "-" lift becomes an allow of the same text, which lifts the
// built-in the same way. Where a config stated both, the allow is dropped and
// the denial kept: a deny outranks an allow at every gate, so the resolution is
// unchanged, and one entry per command is what the new form holds.
func (c *Config) MigrateCommands() int {
	if c == nil {
		return 0
	}
	n := 0
	for i := range c.Overrides {
		o := &c.Overrides[i]
		if o.Commands == nil && !o.usesLegacyCommandKeys() {
			continue
		}
		// The lists in effect for the override's directory: its own where set,
		// the base's otherwise, exactly as ForDirectory combined them.
		resolved := Config{
			ExtraCommands:       pickList(o.ExtraCommands, c.ExtraCommands),
			UnsandboxedCommands: pickList(o.UnsandboxedCommands, c.UnsandboxedCommands),
			DeniedCommands:      pickList(o.DeniedCommands, c.DeniedCommands),
		}
		entries := o.Commands
		if entries == nil {
			entries = c.Commands
		}
		converted := resolved.LegacyCommandEntries()
		o.Commands = mergeCommandEntries(append([]CommandEntry(nil), entries...), converted)
		n += len(converted)
		o.clearLegacyCommandKeys()
	}
	converted := c.LegacyCommandEntries()
	if len(converted) > 0 {
		c.Commands = mergeCommandEntries(c.Commands, converted)
		n += len(converted)
		c.clearLegacyCommandKeys()
	}
	return n
}

func (c *Config) clearLegacyCommandKeys() {
	c.ExtraCommands, c.UnsandboxedCommands, c.DeniedCommands = nil, nil, nil
}

// mergeCommandEntries appends the entries of add to list, keeping one entry
// per command text: a duplicate is dropped, and where an allow and a denial
// meet the denial wins (it outranks the allow at every gate, so nothing
// changes in effect). Two allows that differ only in no_sandbox keep the
// unsandboxed one, which is what the unsandboxed_commands entry meant.
func mergeCommandEntries(list, add []CommandEntry) []CommandEntry {
	for _, e := range add {
		merged := false
		for i, have := range list {
			if !have.SameCommand(e.Command) {
				continue
			}
			merged = true
			switch {
			case have.Denies():
				// keep the denial
			case e.Denies():
				list[i] = e
			case e.NoSandbox && !have.NoSandbox:
				list[i] = e
			}
			break
		}
		if !merged {
			list = append(list, e)
		}
	}
	return list
}
