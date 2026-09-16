package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

// The former `denied-commands` command, kept as a hidden alias of `commands`
// so a script written for it keeps working: add records a denial, remove drops
// a user denial or lifts a built-in one (as an allow of the same text, the
// form `commands allow` writes), list prints the deny list in effect.

var configDeniedCommandsCmd = &cobra.Command{
	Use:    "denied-commands",
	Short:  "Deprecated: use `lite-sandbox config commands deny|allow|list`",
	Hidden: true,
}

var configDeniedCommandsListCmd = &cobra.Command{
	Use:        "list",
	Short:      "List the denied commands in effect",
	Deprecated: "use `lite-sandbox config commands list` instead",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Print(deniedCommandsSummary(cfg, ""))
		return nil
	},
}

var configDeniedCommandsAddCmd = &cobra.Command{
	Use:        "add <command>...",
	Short:      "Add commands to the deny list",
	Args:       cobra.MinimumNArgs(1),
	Deprecated: "use `lite-sandbox config commands deny` instead",
	RunE:       configCommandsDenyCmd.RunE,
}

var configDeniedCommandsRemoveCmd = &cobra.Command{
	Use:        "remove <command>...",
	Short:      "Remove commands from the deny list (a built-in default is lifted)",
	Args:       cobra.MinimumNArgs(1),
	Deprecated: "use `lite-sandbox config commands remove` (or `commands allow` for a built-in entry) instead",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		yes := true
		for _, raw := range args {
			text := config.NormalizeCommandEntry(raw)
			if text == "" {
				continue
			}
			if config.IsDefaultDeniedCommand(text) {
				// A built-in entry is not in the config to delete, so lift it
				// with the allow entry EffectiveDeniedCommands subtracts.
				if err := cfg.SetCommand(config.CommandEntry{Command: text, Allow: &yes}); err != nil {
					return err
				}
				fmt.Printf("%s lifted (built-in default no longer applies)\n", text)
				continue
			}
			if cfg.RemoveCommand(text) {
				fmt.Printf("%s removed from the deny list\n", text)
				continue
			}
			fmt.Printf("%s is not denied; nothing to remove\n", text)
		}
		return saveConfig(cfg)
	},
}

func init() {
	configCmd.AddCommand(configDeniedCommandsCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsListCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsAddCmd)
	configDeniedCommandsCmd.AddCommand(configDeniedCommandsRemoveCmd)
}

// deniedCommandsSummary renders the effective deny list, one entry per line
// with the given indent, marking the built-in entries; the built-ins an allow
// has lifted follow, marked as not enforced. `config mode show` and the
// deprecated `denied-commands list` print it.
func deniedCommandsSummary(cfg *config.Config, indent string) string {
	var b strings.Builder
	for _, e := range cfg.EffectiveDeniedCommands() {
		b.WriteString(indent + e)
		if config.IsDefaultDeniedCommand(e) {
			b.WriteString("   (built-in)")
		}
		b.WriteString("\n")
	}
	for _, e := range cfg.LiftedDeniedCommands() {
		fmt.Fprintf(&b, "%s%s   (built-in; NOT enforced: lifted by the allow on %q)\n", indent, e, e)
	}
	return b.String()
}
