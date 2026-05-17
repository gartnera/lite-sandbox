package cmd

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var gitCmd = &cobra.Command{
	Use:   "git",
	Short: "Manage git permission settings",
}

var gitShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current git permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		g := cfg.Git
		fmt.Printf("local_read:            %v\n", g.GitLocalRead())
		fmt.Printf("local_write:           %v\n", g.GitLocalWrite())
		fmt.Printf("remote_read:           %v\n", g.GitRemoteRead())
		fmt.Printf("remote_write:          %v\n", g.GitRemoteWrite())
		fmt.Printf("allow_worktree_parent: %v\n", g.AllowsWorktreeParent())
		return nil
	},
}

var gitSetCmd = &cobra.Command{
	Use:   "set <key> <true|false>",
	Short: "Set a git permission (local_read, local_write, remote_read, remote_write, allow_worktree_parent)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		valStr := strings.ToLower(args[1])
		var val bool
		switch valStr {
		case "true":
			val = true
		case "false":
			val = false
		default:
			return fmt.Errorf("value must be 'true' or 'false', got %q", args[1])
		}

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Git == nil {
			cfg.Git = &config.GitConfig{}
		}

		switch key {
		case "local_read":
			cfg.Git.LocalRead = &val
		case "local_write":
			cfg.Git.LocalWrite = &val
		case "remote_read":
			cfg.Git.RemoteRead = &val
		case "remote_write":
			cfg.Git.RemoteWrite = &val
		case "allow_worktree_parent":
			cfg.Git.AllowWorktreeParent = &val
		default:
			return fmt.Errorf("unknown git permission key %q; valid keys: local_read, local_write, remote_read, remote_write, allow_worktree_parent", key)
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("git.%s set to %v\n", key, val)
		return nil
	},
}

func init() {
	gitCmd.AddCommand(gitShowCmd)
	gitCmd.AddCommand(gitSetCmd)
	configCmd.AddCommand(gitCmd)
}
