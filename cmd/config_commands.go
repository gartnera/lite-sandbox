package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

var configCommandsCmd = &cobra.Command{
	Use:   "commands",
	Short: "Manage the commands the sandbox allows beyond the whitelist, runs on the host, or refuses outright",
	Long: `One list of commands carries every statement about a command. Each entry is a
command plus what applies to it:

  allow: true             allowed past the command whitelist          (allow <command>)
                          a bare name ("curl") allows any arguments and, when it
                          leads an invocation, skips bash AST parsing entirely (the
                          command string runs via real bash); a name plus arguments
                          ("uv run pyright") allows only invocations whose leading
                          non-flag arguments match, and is still validated
  no_sandbox: true        the allowed command runs directly on the host, outside
                          the OS sandbox worker even when it is enabled — for a
                          command that cannot run confined  (allow ... --no-sandbox)
  allow: false            refused in denylist and allowlist mode however else it is
                          allowed: checked before every command gate, matched by
                          base name (so /usr/local/bin/lite-sandbox counts), and
                          outranking every allow                      (deny <command>)

The built-in deny entries refuse the sandbox's own policy-editing subcommands
(config, install, update, hook) — without them an agent in denylist mode can
run ` + "`lite-sandbox config mode set open`" + ` and turn enforcement off for its next
command. An allow whose text equals a built-in entry lifts it (` + "`allow \"lite-sandbox update\"`" + `);
a bare allow of the binary does not. Each command has one entry: allow and
deny replace whatever the config said about it before, including an entry in
one of the deprecated lists (extra_commands, unsandboxed_commands,
denied_commands), which still load. ` + "`migrate`" + ` rewrites those lists in bulk.
` + "`lite-sandbox config mode show`" + ` prints the deny list in effect, built-in
entries included.`,
}

var commandsAllowNoSandbox bool

var configCommandsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the configured command allows and denials (built-in denials included)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		entries := cfg.AllCommandEntries()
		legacy := len(cfg.LegacyCommandEntries())
		lifted := map[string]bool{}
		for _, l := range cfg.LiftedDeniedCommands() {
			lifted[l] = true
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		for i, e := range entries {
			note := ""
			if i >= len(entries)-legacy {
				note = "\t(deprecated key)"
			}
			if e.Allows() && lifted[e.Text()] {
				note = "\t(lifts a built-in denial)" + note
			}
			fmt.Fprintf(w, "%s\t%s%s\n", e.Command, e.Describe(), note)
		}
		for _, d := range cfg.EffectiveDeniedCommands() {
			if config.IsDefaultDeniedCommand(d) {
				fmt.Fprintf(w, "%s\tdeny\t(built-in)\n", d)
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if legacy > 0 {
			fmt.Println("\nEntries marked (deprecated key) still use the old one-list-per-kind keys; `lite-sandbox config commands migrate` rewrites them as `commands` entries.")
		}
		return nil
	},
}

var configCommandsAllowCmd = &cobra.Command{
	Use:   "allow <command>...",
	Short: "Allow commands beyond the whitelist (--no-sandbox to run them on the host, outside the OS sandbox)",
	Long: `A bare name ("curl") allows the command with any arguments and, when it leads
an invocation, skips bash AST parsing entirely — the whole command string runs
via real bash (inside the OS sandbox when that is enabled). Quote a name plus
arguments ("uv run pyright") to allow only invocations whose leading non-flag
arguments match; those still go through normal parsing and validation.

--no-sandbox makes matching invocations run directly on the host, bypassing the
OS sandbox worker (and the docker filtering proxy) even when it is enabled. It
is a trust-based escape hatch for a command that cannot run confined.

Allowing the exact text of a built-in denial ("lite-sandbox update") lifts it;
the deny list otherwise outranks every allow.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		yes := true
		for _, c := range args {
			e := config.CommandEntry{Command: c, Allow: &yes, NoSandbox: commandsAllowNoSandbox}
			if err := cfg.SetCommand(e); err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", e.Text(), e.Describe())
			if config.IsDefaultDeniedCommand(e.Text()) {
				fmt.Printf("  lifts built-in denial: %s\n", e.Text())
			}
		}
		return saveConfig(cfg)
	},
}

var configCommandsDenyCmd = &cobra.Command{
	Use:   "deny <command>...",
	Short: "Refuse commands in denylist and allowlist mode, however else they are allowed",
	Long: `Denials extend the built-in deny list (the sandbox's own config, install, update
and hook subcommands; ` + "`lite-sandbox config mode show`" + ` prints it). A bare name
("sudo") denies the command whatever its arguments; a name plus arguments
("gh auth") denies only invocations starting with them. Matching is by base
name, so an entry also covers the same binary invoked by path. In open mode,
like every rule, a match is only recorded to the audit log.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		no := false
		for _, c := range args {
			e := config.CommandEntry{Command: c, Allow: &no}
			if config.IsDefaultDeniedCommand(e.Text()) {
				// A built-in is in force unless lifted, so dropping the lift
				// is the whole change and keeps the file from restating it —
				// as long as that leaves the directory saying nothing about
				// the command. Where it inherits a lift it cannot drop (a
				// merge: true override over a base that lifts it), the
				// explicit denial below is what restates it.
				cfg.RemoveCommand(c)
				if !stillStatesCommand(cfg, e.Text()) {
					fmt.Printf("%s: deny (built-in default restored)\n", e.Text())
					continue
				}
			}
			if err := cfg.SetCommand(e); err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", e.Text(), e.Describe())
		}
		return saveConfig(cfg)
	},
}

var configCommandsRemoveCmd = &cobra.Command{
	Use:   "remove <command>...",
	Short: "Remove every allow or denial recorded for commands (a built-in denial comes back into force)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, c := range args {
			text := config.NormalizeCommandEntry(c)
			switch removed := cfg.RemoveCommand(text); {
			case stillStatesCommand(cfg, text):
				// A --dir edit the directory will go on inheriting: saveConfig
				// says what stays in force and how to drop it, so claiming a
				// removal here would contradict it.
			case removed:
				fmt.Printf("%s removed\n", text)
			case config.IsDefaultDeniedCommand(text):
				fmt.Printf("%s is a built-in denial; `lite-sandbox config commands allow %q` lifts it\n", text, text)
			default:
				fmt.Printf("%s is not configured; nothing to remove\n", text)
			}
		}
		return saveConfig(cfg)
	},
}

var configCommandsMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Rewrite the deprecated one-list-per-kind command keys as `commands` entries, in the base config and every override",
	Long: `The deprecated keys (extra_commands, unsandboxed_commands, denied_commands) keep
loading, so this is optional. It rewrites them once, everywhere in the file,
keeping what every directory resolves to: an old-style override replaced only
the list it set and inherited the rest, whereas a commands list replaces the
whole section, so an override that set any command list receives the full set
of entries in effect for its directory. A denied_commands "-" entry becomes an
allow of the same text, which lifts the built-in the same way.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		n := cfg.MigrateCommands()
		if n == 0 {
			fmt.Println("Nothing to migrate: no deprecated command keys in the config")
			return nil
		}
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Printf("Rewrote %d command entries as `commands`\n", n)
		return nil
	},
}

// deprecatedCommandListCommand builds one of the former command-list commands
// (`extra-commands`, `unsandboxed-commands`) as a hidden alias of `commands`,
// so a script written for it keeps working while its help points at the new
// command. list prints the entries of that kind, add records the equivalent
// commands entry, and remove drops every statement about the command.
func deprecatedCommandListCommand(use, replacement string, kind func(*config.Config) []string, entry func(text string) config.CommandEntry) *cobra.Command {
	root := &cobra.Command{
		Use:    use,
		Short:  "Deprecated: use `lite-sandbox config commands " + replacement + "`",
		Hidden: true,
	}
	deprecated := "use `lite-sandbox config commands " + replacement + "` instead"
	root.AddCommand(&cobra.Command{
		Use:        "list",
		Short:      "List these commands",
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, c := range kind(cfg) {
				fmt.Println(c)
			}
			return nil
		},
	})
	root.AddCommand(&cobra.Command{
		Use:        "add <command>...",
		Short:      "Add commands",
		Args:       cobra.MinimumNArgs(1),
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, c := range args {
				if err := cfg.SetCommand(entry(c)); err != nil {
					return err
				}
			}
			return saveConfig(cfg)
		},
	})
	root.AddCommand(&cobra.Command{
		Use:        "remove <command>...",
		Short:      "Remove commands",
		Args:       cobra.MinimumNArgs(1),
		Deprecated: "use `lite-sandbox config commands remove` instead",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, c := range args {
				cfg.RemoveCommand(c)
			}
			return saveConfig(cfg)
		},
	})
	return root
}

func init() {
	configCmd.AddCommand(configCommandsCmd)
	configCommandsCmd.AddCommand(configCommandsListCmd)
	configCommandsCmd.AddCommand(configCommandsAllowCmd)
	configCommandsCmd.AddCommand(configCommandsDenyCmd)
	configCommandsCmd.AddCommand(configCommandsRemoveCmd)
	configCommandsCmd.AddCommand(configCommandsMigrateCmd)

	configCommandsAllowCmd.Flags().BoolVar(&commandsAllowNoSandbox, "no-sandbox", false, "run matching invocations directly on the host, bypassing the OS sandbox worker even when it is enabled")

	yes := true
	configCmd.AddCommand(deprecatedCommandListCommand("extra-commands", "allow",
		(*config.Config).ExtraCommandList,
		func(c string) config.CommandEntry { return config.CommandEntry{Command: c, Allow: &yes} }))
	configCmd.AddCommand(deprecatedCommandListCommand("unsandboxed-commands", "allow --no-sandbox",
		(*config.Config).UnsandboxedCommandList,
		func(c string) config.CommandEntry {
			return config.CommandEntry{Command: c, Allow: &yes, NoSandbox: true}
		}))
}
