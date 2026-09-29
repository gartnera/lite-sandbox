package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

var configProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage the toolchain profiles (go, pnpm, rust, deno, flutter, uv, montypython)",
	Long: `A profile is a built-in preset of commands and paths for one toolchain.
Enabling it adds the toolchain's commands to the whitelist and grants the
directories it keeps its caches and SDKs in (detected by asking the toolchain,
e.g. ` + "`go env GOPATH GOCACHE`" + `): readable by the agent, writable only by the
programs a command runs (at the OS sandbox layer), never by the agent directly.

A profile's commands keep their validators, so enabling go allows ` + "`go test`" + `
but still refuses ` + "`go run pkg@latest`" + `. The subcommands a validator refuses
because they reach shared state (` + "`go generate`" + `, ` + "`cargo publish`" + `, ` + "`pnpm publish`" + `,
` + "`deno publish`" + `, ` + "`uv publish`" + `) are opened with a commands entry for exactly that
text: ` + "`lite-sandbox config commands allow \"cargo publish\"`" + `.

montypython (python/python3 on the embedded interpreter) is the one profile on
by default; ` + "`disable montypython`" + ` turns it off. Some profiles take options
(` + "`set deno allow_network true`" + `); ` + "`list`" + ` shows them.

A config still using the deprecated runtimes section is migrated to profiles
the first time it is loaded, and the file rewritten in the new form.`,
}

var configProfilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the profiles, whether each is enabled, and their options",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		for _, p := range config.Profiles() {
			state := "disabled"
			if cfg.ProfileEnabled(p.Name) {
				state = "enabled"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, state, strings.Join(p.CommandNames(), ", "), p.Description)
			for _, o := range p.Options {
				fmt.Fprintf(w, "  %s\t%v\t\t%s\n", o.Name, cfg.ProfileOption(p.Name, o.Name), o.Description)
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
		return nil
	},
}

var configProfilesShowCmd = &cobra.Command{
	Use:   "show <profile>",
	Short: "Show a profile: whether it is enabled, its commands, options, and detected paths",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := lookupProfile(args[0])
		if err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", p.Name, p.Description)
		fmt.Printf("enabled:  %v\n", cfg.ProfileEnabled(p.Name))
		for _, o := range p.Options {
			fmt.Printf("option %s: %v  (default %v; %s)\n", o.Name, cfg.ProfileOption(p.Name, o.Name), o.Default, o.Description)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		fmt.Fprintln(w, "commands:")
		for _, e := range cfg.ProfileCommandEntries(p) {
			what := e.Describe()
			if e.Whitelists() {
				what = "whitelisted (validated)"
				if e.NoSandbox {
					what += ", no sandbox"
				}
			}
			fmt.Fprintf(w, "  %s\t%s\n", e.Command, what)
		}
		if entries := p.PathEntries(); len(entries) > 0 {
			fmt.Fprintln(w, "paths:")
			for _, e := range entries {
				fmt.Fprintf(w, "  %s\t%s\n", e.Path, e.Describe())
			}
		}
		return w.Flush()
	},
}

var configProfilesEnableCmd = &cobra.Command{
	Use:   "enable <profile>...",
	Short: "Enable profiles",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setProfilesEnabled(args, true)
	},
}

var configProfilesDisableCmd = &cobra.Command{
	Use:   "disable <profile>...",
	Short: "Disable profiles (their commands leave the whitelist)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setProfilesEnabled(args, false)
	},
}

// setProfilesEnabled records each profile as enabled or disabled, keeping
// the options its entry already sets. A disable is written as an explicit
// enabled: false rather than by dropping the entry: under --dir the entry may
// be all that stops the directory inheriting the base's enable (or a
// deprecated runtimes flag, or a default-on profile) of the same profile.
func setProfilesEnabled(names []string, enabled bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	for _, name := range names {
		p, err := lookupProfile(name)
		if err != nil {
			return err
		}
		entry := profileEntryOf(cfg, p.Name)
		entry.Enabled = nil
		if !enabled {
			no := false
			entry.Enabled = &no
		}
		if err := cfg.SetProfile(entry); err != nil {
			return err
		}
		state := "disabled"
		if enabled {
			state = "enabled"
		}
		fmt.Printf("%s: %s (%s)\n", p.Name, state, strings.Join(p.CommandNames(), ", "))
	}
	return saveConfig(cfg)
}

var configProfilesSetCmd = &cobra.Command{
	Use:   "set <profile> <option> <true|false>",
	Short: "Set a profile option (e.g. `set deno allow_network true`)",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := lookupProfile(args[0])
		if err != nil {
			return err
		}
		val, err := parseBool(args[2])
		if err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if err := setProfileOption(cfg, p, args[1], val); err != nil {
			return err
		}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("%s.%s set to %v\n", p.Name, args[1], val)
		return nil
	},
}

// setProfileOption records option = val on the profile's entry. An entry
// written only to hold an option keeps the profile's enabled state as it
// resolves now, so setting an option never enables or disables the profile.
func setProfileOption(cfg *config.Config, p config.Profile, option string, val bool) error {
	if _, ok := p.Option(option); !ok {
		return fmt.Errorf("profile %q has no option %q", p.Name, option)
	}
	entry := profileEntryOf(cfg, p.Name)
	if entry.Options == nil {
		entry.Options = map[string]bool{}
	}
	entry.Options[option] = val
	return cfg.SetProfile(entry)
}

// profileEntryOf returns a copy of the config's entry for the profile, or a
// new entry stating the profile's current enabled state.
func profileEntryOf(cfg *config.Config, name string) config.ProfileEntry {
	for i := len(cfg.Profiles) - 1; i >= 0; i-- {
		if e := cfg.Profiles[i]; e.Name == name {
			opts := make(map[string]bool, len(e.Options))
			for k, v := range e.Options {
				opts[k] = v
			}
			if len(opts) == 0 {
				opts = nil
			}
			e.Options = opts
			return e
		}
	}
	entry := config.ProfileEntry{Name: name}
	if !cfg.ProfileEnabled(name) {
		no := false
		entry.Enabled = &no
	}
	return entry
}

func lookupProfile(name string) (config.Profile, error) {
	p, ok := config.LookupProfile(name)
	if !ok {
		return config.Profile{}, fmt.Errorf("unknown profile %q (known: %s)", name, strings.Join(config.ProfileNames(), ", "))
	}
	return p, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("value must be 'true' or 'false', got %q", s)
}

// legacyRuntimeFlags maps the flags of the former `config runtimes <x>`
// commands to what they now set: a profile option, or the text of a commands
// allow ("cargo publish").
var legacyRuntimeFlags = map[string]map[string]struct{ option, command string }{
	"go":          {"with-generate": {command: "go generate"}},
	"pnpm":        {"with-publish": {command: "pnpm publish"}},
	"rust":        {"with-publish": {command: "cargo publish"}},
	"uv":          {"with-publish": {command: "uv publish"}},
	"montypython": {"inline-only": {option: "inline_only"}},
	"deno": {
		"with-publish":      {command: "deno publish"},
		"with-auto-sandbox": {option: "auto_sandbox"},
		"with-network":      {option: "allow_network"},
		"with-import":       {option: "allow_import"},
	},
}

// deprecatedRuntimesCommand builds the former `config runtimes` tree as a
// hidden alias of `config profiles`, so a script (or an old audit report's
// suggested fix) written for it keeps working. `enable` turns the profile on
// along with any sub-setting flag given; `disable` with sub-setting flags
// turns off only those, and without any turns the profile off.
func deprecatedRuntimesCommand() *cobra.Command {
	root := &cobra.Command{
		Use:    "runtimes",
		Short:  "Deprecated: use `lite-sandbox config profiles`",
		Hidden: true,
	}
	root.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Deprecated: use `lite-sandbox config profiles list`",
		RunE:  configProfilesListCmd.RunE,
	})
	for _, p := range config.Profiles() {
		p := p
		flags := legacyRuntimeFlags[p.Name]
		sub := &cobra.Command{
			Use:   p.Name,
			Short: "Deprecated: use `lite-sandbox config profiles`",
		}
		sub.AddCommand(&cobra.Command{
			Use:   "show",
			Short: "Deprecated: use `lite-sandbox config profiles show " + p.Name + "`",
			RunE: func(cmd *cobra.Command, args []string) error {
				return configProfilesShowCmd.RunE(cmd, []string{p.Name})
			},
		})
		for _, enable := range []bool{true, false} {
			enable := enable
			use := "disable"
			if enable {
				use = "enable"
			}
			c := &cobra.Command{
				Use:   use,
				Short: "Deprecated: use `lite-sandbox config profiles " + use + " " + p.Name + "`",
				RunE: func(cmd *cobra.Command, args []string) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					names := make([]string, 0, len(flags))
					for name := range flags {
						names = append(names, name)
					}
					sort.Strings(names)
					anySub := false
					yes := true
					for _, name := range names {
						if on, _ := cmd.Flags().GetBool(name); !on {
							continue
						}
						anySub = true
						f := flags[name]
						switch {
						case f.option != "":
							if err := setProfileOption(cfg, p, f.option, enable); err != nil {
								return err
							}
						case enable:
							if err := cfg.SetCommand(config.CommandEntry{Command: f.command, Allow: &yes}); err != nil {
								return err
							}
						default:
							cfg.RemoveCommand(f.command)
						}
					}
					if enable || !anySub {
						entry := profileEntryOf(cfg, p.Name)
						entry.Enabled = nil
						if !enable {
							no := false
							entry.Enabled = &no
						}
						if err := cfg.SetProfile(entry); err != nil {
							return err
						}
					}
					fmt.Fprintf(os.Stderr, "note: `config runtimes` is deprecated; use `lite-sandbox config profiles %s %s`\n", use, p.Name)
					return saveConfig(cfg)
				},
			}
			for name := range flags {
				c.Flags().Bool(name, false, "deprecated sub-setting flag")
			}
			sub.AddCommand(c)
		}
		root.AddCommand(sub)
	}
	return root
}

func init() {
	configProfilesCmd.AddCommand(configProfilesListCmd)
	configProfilesCmd.AddCommand(configProfilesShowCmd)
	configProfilesCmd.AddCommand(configProfilesEnableCmd)
	configProfilesCmd.AddCommand(configProfilesDisableCmd)
	configProfilesCmd.AddCommand(configProfilesSetCmd)
	configCmd.AddCommand(configProfilesCmd)
	configCmd.AddCommand(deprecatedRuntimesCommand())
}
