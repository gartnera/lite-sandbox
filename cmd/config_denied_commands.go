package cmd

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

var configDeniedCommandsCmd = &cobra.Command{
	Use:   "denied-commands",
	Short: "Manage commands the sandbox refuses to run (on top of the built-in defaults)",
	Long: `Commands listed here are refused in denylist and allowlist mode, whatever else
allows them: the deny list is checked before the command whitelist and outranks
extra_commands and unsandboxed_commands, so it is the one gate those escape
hatches do not lift. In open mode, like every other rule, a match is only
recorded to the audit log.

Entries use the extra_commands format:

  lite-sandbox config     deny only invocations starting with that subcommand
  curl                    deny the command outright, whatever its arguments

Matching is by the command's base name, so an entry also covers the same binary
invoked by path (/usr/local/bin/lite-sandbox, ./lite-sandbox).

The built-in defaults deny the sandbox's own policy-editing subcommands
(config, install, update, hook) — without them an agent in denylist mode can
run ` + "`lite-sandbox config mode set open`" + ` and turn enforcement off for the next
command. ` + "`remove`" + ` lifts a built-in default by recording a "-" entry in the
config; the OS sandbox's own protection of those files (denylist mode) is
unaffected either way.`,
}

var configDeniedCommandsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the denied commands in effect",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, e := range cfg.EffectiveDeniedCommands() {
			if config.IsDefaultDeniedCommand(e) {
				fmt.Printf("%s   (built-in)\n", e)
				continue
			}
			fmt.Println(e)
		}
		return nil
	},
}

var configDeniedCommandsAddCmd = &cobra.Command{
	Use:   "add <command>...",
	Short: "Add commands to the deny list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		values := cfg.DeniedCommands
		for _, raw := range args {
			entry := config.NormalizeCommandEntry(raw)
			if entry == "" {
				continue
			}
			// Adding back a default that was previously lifted just drops the
			// "-" entry, rather than listing it twice.
			if i := slices.Index(values, "-"+entry); i >= 0 {
				values = slices.Delete(values, i, i+1)
				fmt.Printf("%s denied again (built-in default restored)\n", entry)
				continue
			}
			if slices.Contains(values, entry) || config.IsDefaultDeniedCommand(entry) {
				fmt.Printf("%s is already denied\n", entry)
				continue
			}
			values = append(values, entry)
			fmt.Printf("%s denied\n", entry)
		}
		cfg.DeniedCommands = values
		return saveConfig(cfg)
	},
}

var configDeniedCommandsRemoveCmd = &cobra.Command{
	Use:   "remove <command>...",
	Short: "Remove commands from the deny list (a built-in default is recorded as lifted)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		values := cfg.DeniedCommands
		for _, raw := range args {
			entry := config.NormalizeCommandEntry(raw)
			if entry == "" {
				continue
			}
			if i := slices.Index(values, entry); i >= 0 {
				values = slices.Delete(values, i, i+1)
				fmt.Printf("%s removed from the deny list\n", entry)
				continue
			}
			// A built-in entry is not in the config to delete, so lift it with
			// a "-" entry that EffectiveDeniedCommands subtracts.
			if config.IsDefaultDeniedCommand(entry) {
				if !slices.Contains(values, "-"+entry) {
					values = append(values, "-"+entry)
				}
				fmt.Printf("%s lifted (built-in default no longer applies)\n", entry)
				continue
			}
			fmt.Printf("%s is not denied; nothing to remove\n", entry)
		}
		cfg.DeniedCommands = values
		return saveConfig(cfg)
	},
}

func init() {
	configCmd.AddCommand(configDeniedCommandsCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsListCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsAddCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsRemoveCmd)
}

// deniedCommandsSummary renders the effective deny list for `config mode show`,
// marking the built-in entries.
func deniedCommandsSummary(cfg *config.Config) string {
	var b strings.Builder
	for _, e := range cfg.EffectiveDeniedCommands() {
		b.WriteString("  " + e)
		if config.IsDefaultDeniedCommand(e) {
			b.WriteString("   (built-in)")
		}
		b.WriteString("\n")
	}
	return b.String()
}
