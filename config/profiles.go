package config

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile is a named preset of commands and paths for one toolchain, written
// in the config's own vocabulary: its commands are CommandEntry values and its
// paths PathEntry values, so enabling it is the same as having written those
// entries into the `commands` and `paths` lists (Config.Effective does exactly
// that) — `go test` then works without hand-written entries. Profiles are
// built in (see Profiles); the config only says which are enabled and sets
// their options.
//
// Every field of an entry means what it means in the config — no_sandbox on a
// command, read/write/internal on a path, allow: false for a denial — with one
// difference, for an allow of a bare command name: a profile's allow
// whitelists the command rather than opening the escape hatch a config allow
// is. The command keeps going through validation, including the argument
// validators the sandbox registers for it (the profile's parser hooks, in
// tool/bash_sandboxed/profiles.go), so enabling go allows `go test` but still
// refuses `go run pkg@latest` and `go generate`. (An allow with arguments,
// "uv run pyright", behaves as in the config.) The one-off subcommands a
// validator refuses by default — `go generate`, `cargo publish`, ... — are
// opened with a config `commands` entry for exactly that text.
//
// A profile's paths are detected when the profile is expanded (by asking the
// toolchain, e.g. `go env GOPATH GOCACHE`), which is why they are a function.
// The toolchains' own caches are granted by toolchainDirs: readable by the
// agent, and writable at the OS sandbox layer only (internal), so a build can
// populate its cache while the agent's own writes there are still refused.
type Profile struct {
	Name        string
	Description string
	// DefaultEnabled marks a profile that is on unless the config turns it off
	// (montypython, whose interpreter is embedded in the binary).
	DefaultEnabled bool
	// Commands are the profile's commands entries.
	Commands []CommandEntry
	// Options are the profile's settings, each a boolean with a default.
	Options []ProfileOption
	// paths returns the profile's paths entries; nil when it needs none. It
	// may spawn the toolchain, so it runs only when a profile is expanded.
	paths func() []PathEntry
}

// whitelist returns allow entries for the named commands: the form a
// profile's toolchain commands take.
func whitelist(names ...string) []CommandEntry {
	yes := true
	out := make([]CommandEntry, len(names))
	for i, n := range names {
		out[i] = CommandEntry{Command: n, Allow: &yes}
	}
	return out
}

// toolchainDirs turns a directory detector into the paths entries of a
// toolchain's caches and SDKs: for every directory, a read grant (the agent
// may read a module cache or an SDK's sources) and an internal write grant
// (the toolchain may write there; the agent may not directly).
func toolchainDirs(detect func() []string) func() []PathEntry {
	return func() []PathEntry {
		yes := true
		var out []PathEntry
		for _, d := range detect() {
			out = append(out,
				PathEntry{Path: d, Read: &yes},
				PathEntry{Path: d, Write: &yes, Internal: true},
			)
		}
		return out
	}
}

// xcodePaths is the xcode profile's paths: its caches as toolchainDirs, a
// read and write grant on the simulators' data so the agent can inspect and
// seed an app's container (the path `xcrun simctl get_app_container` prints),
// plus a read grant on the active developer directory so the agent can read
// the SDKs' headers and the toolchain's man pages. Nothing writes there, so it
// gets no write grant.
func xcodePaths() []PathEntry {
	out := toolchainDirs(detectXcodeBinds)()
	yes := true
	for _, dir := range xcodeSimulatorDataFor(runtime.GOOS) {
		out = append(out, PathEntry{Path: dir, Read: &yes, Write: &yes})
	}
	if dir := detectXcodeDeveloperDir(); dir != "" {
		out = append(out, PathEntry{Path: dir, Read: &yes})
	}
	return out
}

// ProfileOption is one boolean setting of a profile.
type ProfileOption struct {
	Name        string
	Default     bool
	Description string
}

// builtinProfiles is the profile catalog. The names match the runtime
// sections they replace (runtimes.go, runtimes.pnpm, ...), which is what lets
// the deprecated `runtimes` section fold into them.
var builtinProfiles = []Profile{
	{
		Name:        "go",
		Description: "Go toolchain (go, gofmt); GOPATH and GOCACHE",
		Commands:    whitelist("go", "gofmt"),
		paths: toolchainDirs(func() []string {
			return cachedDetect("go", []string{"GOPATH", "GOCACHE", "GOENV", "HOME"}, detectGoBinds)
		}),
	},
	{
		Name:        "pnpm",
		Description: "pnpm package manager; the pnpm store and cache",
		Commands:    whitelist("pnpm"),
		paths: toolchainDirs(func() []string {
			return cachedDetect("pnpm", []string{"PNPM_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "HOME"}, detectPnpmBinds)
		}),
	},
	{
		Name:        "rust",
		Description: "Rust toolchain (cargo, rustc); CARGO_HOME and RUSTUP_HOME",
		Commands:    whitelist("cargo", "rustc"),
		paths:       toolchainDirs(detectRustBinds),
	},
	{
		Name:        "deno",
		Description: "Deno runtime; DENO_DIR and the deno install root",
		Commands:    whitelist("deno"),
		Options: []ProfileOption{
			{Name: "auto_sandbox", Default: true, Description: "inject --allow-read/--allow-write scoped to the sandbox paths"},
			{Name: "allow_network", Default: false, Description: "let deno open network sockets (otherwise --deny-net is forced)"},
			{Name: "allow_import", Default: true, Description: "let deno fetch remote modules (otherwise --deny-import, and cache/add/install are refused)"},
		},
		paths: toolchainDirs(detectDenoBinds),
	},
	{
		Name:        "flutter",
		Description: "Flutter, Dart, and fvm; the fvm and pub caches, the SDK, and their config dirs",
		Commands:    whitelist("flutter", "dart", "fvm"),
		paths:       toolchainDirs(detectFlutterBinds),
	},
	{
		Name:        "xcode",
		Description: "Xcode, Swift, and XcodeGen; DerivedData, Archives, SwiftPM's and XcodeGen's caches, the simulators' data, and the developer dir (read-only)",
		Commands:    whitelist("xcodebuild", "xcrun", "swift", "swiftc", "xcode-select", "xcodegen"),
		Options: []ProfileOption{
			{Name: "allow_devices", Default: false, Description: "let xcodebuild test and simctl run code on simulators and devices, which CoreSimulator starts outside the OS sandbox"},
			{Name: noSandboxOption, Default: false, Description: "run the commands on the host, outside the OS sandbox, where SwiftPM and Xcode can sandbox manifests and plugins themselves (builds, tests, and build scripts are then unconfined)"},
		},
		paths: xcodePaths,
	},
	{
		Name:        "uv",
		Description: "uv Python package manager (uv, uvx); the uv cache, managed Pythons, and tool envs",
		Commands:    whitelist("uv", "uvx"),
		paths: toolchainDirs(func() []string {
			return cachedDetect("uv", []string{
				"UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_TOOL_DIR",
				"XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_BIN_HOME", "HOME",
			}, detectUvBinds)
		}),
	},
	{
		Name:           "montypython",
		Description:    "python/python3 on monty, the Python interpreter embedded in lite-sandbox (on by default)",
		DefaultEnabled: true,
		Commands:       whitelist("python", "python3"),
		Options: []ProfileOption{
			{Name: "inline_only", Default: false, Description: "run only -c and stdin (heredoc/pipe) programs; refuse script files"},
		},
	},
}

// Profiles returns the profile catalog, in a fixed order.
func Profiles() []Profile { return slices.Clone(builtinProfiles) }

// ProfileNames returns the names of every profile in the catalog.
func ProfileNames() []string {
	out := make([]string, len(builtinProfiles))
	for i, p := range builtinProfiles {
		out[i] = p.Name
	}
	return out
}

// LookupProfile returns the catalog profile named name.
func LookupProfile(name string) (Profile, bool) {
	for _, p := range builtinProfiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// ProfilesForCommand returns the names of the profiles that allow the
// command cmdName, so a refusal can say which profile would.
func ProfilesForCommand(cmdName string) []string {
	var out []string
	for _, p := range builtinProfiles {
		if slices.Contains(p.CommandNames(), cmdName) {
			out = append(out, p.Name)
		}
	}
	return out
}

// CommandNames returns the names of the commands the profile allows.
func (p Profile) CommandNames() []string {
	var out []string
	for _, e := range p.Commands {
		if e.Allows() {
			if f := strings.Fields(e.Command); len(f) > 0 && !slices.Contains(out, f[0]) {
				out = append(out, f[0])
			}
		}
	}
	return out
}

// Option returns the named option's definition.
func (p Profile) Option(name string) (ProfileOption, bool) {
	for _, o := range p.Options {
		if o.Name == name {
			return o, true
		}
	}
	return ProfileOption{}, false
}

// PathEntries returns the profile's paths entries, detected now (from the
// persistent detection cache when fresh), each marked with the profile's
// name. A profile without paths returns nil.
func (p Profile) PathEntries() []PathEntry {
	if p.paths == nil {
		return nil
	}
	out := p.paths()
	for i := range out {
		out[i].Profile = p.Name
	}
	return out
}

// CommandEntries returns the profile's commands entries, each marked with the
// profile's name and its text normalized.
func (p Profile) CommandEntries() []CommandEntry {
	out := slices.Clone(p.Commands)
	for i := range out {
		out[i].Command = out[i].Text()
		out[i].Profile = p.Name
	}
	return out
}

// noSandboxOption is the profile option that runs a profile's commands on the
// host, outside the OS sandbox: it sets no_sandbox on every one of the
// profile's commands entries, as a user's commands entry would. The commands
// stay whitelisted and validated. Only a profile that declares the option has
// it.
const noSandboxOption = "no_sandbox"

// ProfileCommandEntries returns p's commands entries as this config enables
// them: CommandEntries, with no_sandbox set on each when the profile's
// no_sandbox option is on.
func (c *Config) ProfileCommandEntries(p Profile) []CommandEntry {
	out := p.CommandEntries()
	if _, ok := p.Option(noSandboxOption); ok && c.ProfileOption(p.Name, noSandboxOption) {
		for i := range out {
			out[i].NoSandbox = true
		}
	}
	return out
}

// ProfileEntry is one entry of the `profiles` list: a profile name, whether
// it is enabled, and any options that differ from the profile's defaults.
// The common case is written as the bare name:
//
//	profiles:
//	  - go                       # enabled
//	  - rust
//	  - name: deno               # enabled, with options
//	    options:
//	      allow_network: true
//	  - name: montypython        # a default-on profile, turned off
//	    enabled: false
//
// Enabled unset means enabled: naming a profile turns it on.
type ProfileEntry struct {
	Name    string          `yaml:"name"`
	Enabled *bool           `yaml:"enabled,omitempty"`
	Options map[string]bool `yaml:"options,omitempty"`
}

// profileEntryFields is ProfileEntry without its YAML methods, for decoding
// and encoding the mapping form.
type profileEntryFields ProfileEntry

// UnmarshalYAML accepts both the bare-name form ("go") and the mapping form.
func (e *ProfileEntry) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*e = ProfileEntry{Name: n.Value}
		return nil
	}
	var f profileEntryFields
	if err := n.Decode(&f); err != nil {
		return err
	}
	*e = ProfileEntry(f)
	return nil
}

// MarshalYAML writes an entry that only enables its profile as the bare name.
func (e ProfileEntry) MarshalYAML() (any, error) {
	if e.Enabled == nil && len(e.Options) == 0 {
		return e.Name, nil
	}
	return profileEntryFields(e), nil
}

// On reports whether the entry enables its profile (enabled unset or true).
func (e ProfileEntry) On() bool { return e.Enabled == nil || *e.Enabled }

// MergeKey makes the entry a keyedEntry: a merge: true override restates a
// base entry by naming the same profile.
func (e ProfileEntry) MergeKey() string { return e.Name }

// Validate rejects an entry naming no known profile, or setting an option the
// profile does not have.
func (e ProfileEntry) Validate() error {
	p, ok := LookupProfile(e.Name)
	if !ok {
		return fmt.Errorf("unknown profile %q (known: %s)", e.Name, strings.Join(ProfileNames(), ", "))
	}
	for _, name := range sortedKeys(e.Options) {
		if _, ok := p.Option(name); !ok {
			return fmt.Errorf("profile %q has no option %q%s", e.Name, name, optionList(p))
		}
	}
	return nil
}

func optionList(p Profile) string {
	if len(p.Options) == 0 {
		return " (it has no options)"
	}
	names := make([]string, len(p.Options))
	for i, o := range p.Options {
		names[i] = o.Name
	}
	return " (options: " + strings.Join(names, ", ") + ")"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateProfiles rejects a malformed profiles entry on the base config or
// any override, so a typo cannot silently enable nothing.
func (c *Config) validateProfiles() error {
	for _, e := range c.Profiles {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	for _, o := range c.Overrides {
		for _, e := range o.Profiles {
			if err := e.Validate(); err != nil {
				return fmt.Errorf("override %q: %w", o.Path, err)
			}
		}
	}
	return nil
}

// profileEntry returns the last profiles entry naming name, which is the one
// in force when a list names a profile twice.
func (c *Config) profileEntry(name string) (ProfileEntry, bool) {
	if c == nil {
		return ProfileEntry{}, false
	}
	for i := len(c.Profiles) - 1; i >= 0; i-- {
		if c.Profiles[i].Name == name {
			return c.Profiles[i], true
		}
	}
	return ProfileEntry{}, false
}

// ProfileEnabled reports whether the named profile is enabled: its entry in
// `profiles` when there is one, else the deprecated runtimes section's
// enabled flag for it, else the profile's default.
func (c *Config) ProfileEnabled(name string) bool {
	if e, ok := c.profileEntry(name); ok {
		return e.On()
	}
	if on, ok := c.legacyRuntimeEnabled(name); ok {
		return on
	}
	p, _ := LookupProfile(name)
	return p.DefaultEnabled
}

// ProfileOption returns the value of a profile option: the profile entry's
// setting when it has one, else the deprecated runtimes section's, else the
// option's default. An unknown profile or option reads as false.
func (c *Config) ProfileOption(profile, option string) bool {
	if e, ok := c.profileEntry(profile); ok {
		if v, ok := e.Options[option]; ok {
			return v
		}
	}
	if v, ok := c.legacyRuntimeOption(profile, option); ok {
		return v
	}
	p, _ := LookupProfile(profile)
	o, _ := p.Option(option)
	return o.Default
}

// EnabledProfiles returns the enabled profiles, in catalog order.
func (c *Config) EnabledProfiles() []Profile {
	var out []Profile
	for _, p := range builtinProfiles {
		if c.ProfileEnabled(p.Name) {
			out = append(out, p)
		}
	}
	return out
}

// SetProfile records entry as the single statement about its profile,
// replacing any existing entry for the same name. Returns entry's validation
// error, if any, before changing anything.
func (c *Config) SetProfile(entry ProfileEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	c.RemoveProfile(entry.Name)
	c.Profiles = append(c.Profiles, entry)
	return nil
}

// RemoveProfile drops every profiles entry naming name and reports whether
// there was one.
func (c *Config) RemoveProfile(name string) bool {
	found := false
	kept := c.Profiles[:0:0]
	for _, e := range c.Profiles {
		if e.Name == name {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) > 0 {
		c.Profiles = kept
	} else {
		c.Profiles = nil
	}
	return found
}

// --- The deprecated runtimes section ---------------------------------------

// runtimeCommandGates are the subcommands the deprecated runtimes section
// opened with a flag of its own (runtimes.go.generate, runtimes.<x>.publish).
// They are commands entries now; a flag set true reads as an allow of the
// text, which is what MigrateRuntimes writes.
var runtimeCommandGates = []struct {
	text string
	flag func(*RuntimesConfig) *bool
}{
	{"go generate", func(r *RuntimesConfig) *bool { return fieldOf(r.Go, func(g *GoConfig) *bool { return g.Generate }) }},
	{"pnpm publish", func(r *RuntimesConfig) *bool { return fieldOf(r.Pnpm, func(p *PnpmConfig) *bool { return p.Publish }) }},
	{"cargo publish", func(r *RuntimesConfig) *bool { return fieldOf(r.Rust, func(p *RustConfig) *bool { return p.Publish }) }},
	{"deno publish", func(r *RuntimesConfig) *bool { return fieldOf(r.Deno, func(p *DenoConfig) *bool { return p.Publish }) }},
	{"uv publish", func(r *RuntimesConfig) *bool { return fieldOf(r.Uv, func(p *UvConfig) *bool { return p.Publish }) }},
}

func fieldOf[T any](section *T, field func(*T) *bool) *bool {
	if section == nil {
		return nil
	}
	return field(section)
}

// legacyRuntimeEnabled returns the deprecated runtimes.<name>.enabled flag,
// and whether it is set.
func (c *Config) legacyRuntimeEnabled(name string) (bool, bool) {
	if c == nil || c.Runtimes == nil {
		return false, false
	}
	r := c.Runtimes
	var flag *bool
	switch name {
	case "go":
		flag = fieldOf(r.Go, func(g *GoConfig) *bool { return g.Enabled })
	case "pnpm":
		flag = fieldOf(r.Pnpm, func(p *PnpmConfig) *bool { return p.Enabled })
	case "rust":
		flag = fieldOf(r.Rust, func(p *RustConfig) *bool { return p.Enabled })
	case "deno":
		flag = fieldOf(r.Deno, func(p *DenoConfig) *bool { return p.Enabled })
	case "flutter":
		flag = fieldOf(r.Flutter, func(p *FlutterConfig) *bool { return p.Enabled })
	case "uv":
		flag = fieldOf(r.Uv, func(p *UvConfig) *bool { return p.Enabled })
	case "montypython":
		flag = fieldOf(r.MontyPython, func(p *MontyPythonConfig) *bool { return p.Enabled })
	}
	if flag == nil {
		return false, false
	}
	return *flag, true
}

// legacyRuntimeOption returns a profile option as the deprecated runtimes
// section spelled it, and whether it is set there.
func (c *Config) legacyRuntimeOption(profile, option string) (bool, bool) {
	if c == nil || c.Runtimes == nil {
		return false, false
	}
	var flag *bool
	switch profile + "." + option {
	case "deno.auto_sandbox":
		flag = fieldOf(c.Runtimes.Deno, func(d *DenoConfig) *bool { return d.AutoSandbox })
	case "deno.allow_network":
		flag = fieldOf(c.Runtimes.Deno, func(d *DenoConfig) *bool { return d.AllowNetwork })
	case "deno.allow_import":
		flag = fieldOf(c.Runtimes.Deno, func(d *DenoConfig) *bool { return d.AllowImport })
	case "montypython.inline_only":
		flag = fieldOf(c.Runtimes.MontyPython, func(p *MontyPythonConfig) *bool { return p.InlineOnly })
	}
	if flag == nil {
		return false, false
	}
	return *flag, true
}

// legacyRuntimeCommandEntries returns the commands entries the deprecated
// runtimes section implies: an allow for each generate/publish flag set true.
func (c *Config) legacyRuntimeCommandEntries() []CommandEntry {
	if c == nil || c.Runtimes == nil {
		return nil
	}
	yes := true
	var out []CommandEntry
	for _, g := range runtimeCommandGates {
		if f := g.flag(c.Runtimes); f != nil && *f {
			out = append(out, CommandEntry{Command: g.text, Allow: &yes})
		}
	}
	return out
}

func (c *Config) legacyRuntimeAllowedCommands() []string {
	var out []string
	for _, e := range c.legacyRuntimeCommandEntries() {
		out = append(out, e.Command)
	}
	return out
}

// UsesDeprecatedRuntimes reports whether the base config or any override still
// has a runtimes section, which MigrateRuntimes rewrites.
func (c *Config) UsesDeprecatedRuntimes() bool {
	if c == nil {
		return false
	}
	if c.Runtimes != nil {
		return true
	}
	for _, o := range c.Overrides {
		if o.Runtimes != nil {
			return true
		}
	}
	return false
}

// profileState is what the profile-related settings resolve to for one
// directory: which profiles are on, every option's value, and which of the
// runtime-gated subcommands are allowed.
type profileState struct {
	enabled map[string]bool
	options map[string]bool // "profile.option"
	allowed map[string]bool // runtimeCommandGates texts
}

func stateOf(c *Config) profileState {
	s := profileState{enabled: map[string]bool{}, options: map[string]bool{}, allowed: map[string]bool{}}
	for _, p := range builtinProfiles {
		s.enabled[p.Name] = c.ProfileEnabled(p.Name)
		for _, o := range p.Options {
			s.options[p.Name+"."+o.Name] = c.ProfileOption(p.Name, o.Name)
		}
	}
	for _, g := range runtimeCommandGates {
		s.allowed[g.text] = hasCommandAllow(c, g.text)
	}
	return s
}

func hasCommandAllow(c *Config, text string) bool {
	for _, e := range c.AllCommandEntries() {
		if e.Allows() && e.SameCommand(text) {
			return true
		}
	}
	return false
}

// MigrateRuntimes rewrites the deprecated runtimes section — on the base config
// and on every override — as profiles and commands entries and clears it,
// keeping what every directory resolves to. Returns the number of entries
// written.
//
//   - runtimes.<x>.enabled becomes a profiles entry (enabled: false where it
//     turned a default-on profile off);
//   - deno's auto_sandbox/allow_network/allow_import and montypython's
//     inline_only become options on the profile's entry;
//   - go.generate and the <x>.publish flags become commands entries allowing
//     "go generate", "cargo publish", ....
//
// The two spellings do not combine the same way under overrides: an override's
// runtimes section replaced (or, under merge: true, deep-merged into) the
// base's runtimes, whereas its profiles and commands sections combine with the
// base's profiles and commands. So rather than translating each section in
// place, the migration computes what every directory resolved to before, then
// writes into each override exactly the entries needed for it to resolve the
// same way on top of the migrated base — restating an inherited entry where a
// replace-mode override would otherwise drop it, and adding an explicit entry
// where it would otherwise inherit one it did not have.
func (c *Config) MigrateRuntimes() int {
	if !c.UsesDeprecatedRuntimes() {
		return 0
	}
	// What each directory resolves to today, before anything changes.
	baseWant := stateOf(c)
	want := make([]profileState, len(c.Overrides))
	for i := range c.Overrides {
		want[i] = stateOf(overlaid(c, &c.Overrides[i]))
	}
	c.Runtimes = nil
	n := adoptProfileState(c, nil, false, func() *Config { return c }, baseWant)
	for i := range c.Overrides {
		o := &c.Overrides[i]
		o.Runtimes = nil
		n += adoptProfileState(&o.Config, c, !o.Merge, func() *Config { return overlaid(c, o) }, want[i])
	}
	return n
}

// overlaid resolves override o on top of base, as ForDirectory would for a
// directory o governs.
func overlaid(base *Config, o *DirectoryOverride) *Config {
	r := *base
	r.Overrides = nil
	overlayConfig(&r, &o.Config, o.Merge)
	return &r
}

// adoptProfileState edits target's profiles and commands entries until
// resolve() — the config in force for target's directory — matches want, and
// returns the number of entries it wrote. base is the config a replace-mode
// target inherits sections from (nil for the base itself): before such a
// target takes a section of its own, it starts from a copy of the base's, so
// the entries it used to inherit are not dropped.
func adoptProfileState(target, base *Config, replace bool, resolve func() *Config, want profileState) int {
	n := 0
	written := slices.Clone(target.Profiles) // the entries the config already had
	// Setting the first entry of a replace-mode override's profiles list stops
	// it inheriting the base's, which can flip a profile already checked; a
	// second pass settles it.
	for pass := 0; pass < 3; pass++ {
		changed := false
		for _, p := range builtinProfiles {
			have := stateOf(resolve())
			if have.enabled[p.Name] == want.enabled[p.Name] && sameOptions(p, have, want) {
				continue
			}
			if replace && target.Profiles == nil && base != nil {
				target.Profiles = slices.Clone(base.Profiles)
			}
			entry := ProfileEntry{Name: p.Name}
			if !want.enabled[p.Name] {
				no := false
				entry.Enabled = &no
			}
			for _, o := range p.Options {
				if v := want.options[p.Name+"."+o.Name]; v != o.Default {
					if entry.Options == nil {
						entry.Options = map[string]bool{}
					}
					entry.Options[o.Name] = v
				}
			}
			_ = target.SetProfile(entry)
			n++
			changed = true
		}
		if !changed {
			break
		}
	}
	// The passes above can leave entries that no longer matter — in a
	// replace-mode override, an explicit enabled: false written before the
	// list took over from the base's. Drop every such entry the directory
	// resolves the same without; the entries the config itself had stay.
	for i := len(target.Profiles) - 1; i >= 0 && n > 0; i-- {
		if slices.ContainsFunc(written, func(e ProfileEntry) bool { return reflect.DeepEqual(e, target.Profiles[i]) }) {
			continue
		}
		kept := target.Profiles
		target.Profiles = slices.Delete(slices.Clone(kept), i, i+1)
		if len(target.Profiles) == 0 {
			target.Profiles = nil
		}
		have := stateOf(resolve())
		same := true
		for _, p := range builtinProfiles {
			if have.enabled[p.Name] != want.enabled[p.Name] || !sameOptions(p, have, want) {
				same = false
				break
			}
		}
		if !same {
			target.Profiles = kept
		}
	}
	yes, no := true, false
	for _, g := range runtimeCommandGates {
		if hasCommandAllow(resolve(), g.text) == want.allowed[g.text] {
			continue
		}
		if replace && target.Commands == nil && base != nil {
			target.Commands = slices.Clone(base.Commands)
		}
		if want.allowed[g.text] {
			_ = target.SetCommand(CommandEntry{Command: g.text, Allow: &yes})
			n++
			continue
		}
		// An allow the directory must not have: drop the target's own, and if
		// one is still inherited, deny the text, which outranks it.
		target.RemoveCommand(g.text)
		if hasCommandAllow(resolve(), g.text) {
			_ = target.SetCommand(CommandEntry{Command: g.text, Allow: &no})
			n++
		}
	}
	return n
}

func sameOptions(p Profile, a, b profileState) bool {
	for _, o := range p.Options {
		k := p.Name + "." + o.Name
		if a.options[k] != b.options[k] {
			return false
		}
	}
	return true
}
