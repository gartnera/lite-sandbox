package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var unsandboxedCommandsCmd = &cobra.Command{
	Use:   "unsandboxed-commands",
	Short: "Manage commands that run on the host, bypassing the OS sandbox",
	Long: `Manage unsandboxed commands.

Entries behave like extra-commands (they bypass validation and, when bare, bash
AST parsing) except that they always execute directly on the host — bypassing
the OS sandbox worker (bwrap/sandbox-exec) even when it is enabled. This is a
trust-based escape hatch for commands that cannot run confined.`,
}

var unsandboxedCommandsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List unsandboxed commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, c := range cfg.UnsandboxedCommands {
			fmt.Println(c)
		}
		return nil
	},
}

var unsandboxedCommandsAddCmd = &cobra.Command{
	Use:   "add <command>...",
	Short: "Add commands to the unsandboxed list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		existing := make(map[string]bool, len(cfg.UnsandboxedCommands))
		for _, c := range cfg.UnsandboxedCommands {
			existing[c] = true
		}
		for _, c := range args {
			if !existing[c] {
				cfg.UnsandboxedCommands = append(cfg.UnsandboxedCommands, c)
				existing[c] = true
			}
		}
		return saveConfig(cfg)
	},
}

var unsandboxedCommandsRemoveCmd = &cobra.Command{
	Use:   "remove <command>...",
	Short: "Remove commands from the unsandboxed list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		toRemove := make(map[string]bool, len(args))
		for _, c := range args {
			toRemove[c] = true
		}
		filtered := cfg.UnsandboxedCommands[:0]
		for _, c := range cfg.UnsandboxedCommands {
			if !toRemove[c] {
				filtered = append(filtered, c)
			}
		}
		cfg.UnsandboxedCommands = filtered
		return saveConfig(cfg)
	},
}

func init() {
	unsandboxedCommandsCmd.AddCommand(unsandboxedCommandsListCmd)
	unsandboxedCommandsCmd.AddCommand(unsandboxedCommandsAddCmd)
	unsandboxedCommandsCmd.AddCommand(unsandboxedCommandsRemoveCmd)
	configCmd.AddCommand(unsandboxedCommandsCmd)
}
