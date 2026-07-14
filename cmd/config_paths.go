package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

// newPathListCommand builds a `lite-sandbox config <use>` command with
// list/add/remove subcommands managing one path list in the config. get
// returns the current list from a loaded config; set stores the updated list
// back before saving.
func newPathListCommand(use, short string, get func(*config.Config) []string, set func(*config.Config, []string)) *cobra.Command {
	root := &cobra.Command{
		Use:   use,
		Short: short,
	}

	root.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List " + use,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, p := range get(cfg) {
				fmt.Println(p)
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "add <path>...",
		Short: "Add paths to the " + use + " list",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			paths := get(cfg)
			existing := make(map[string]bool, len(paths))
			for _, p := range paths {
				existing[p] = true
			}
			for _, p := range args {
				if !existing[p] {
					paths = append(paths, p)
					existing[p] = true
				}
			}
			set(cfg, paths)
			return saveConfig(cfg)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "remove <path>...",
		Short: "Remove paths from the " + use + " list",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			toRemove := make(map[string]bool, len(args))
			for _, p := range args {
				toRemove[p] = true
			}
			paths := get(cfg)
			filtered := paths[:0]
			for _, p := range paths {
				if !toRemove[p] {
					filtered = append(filtered, p)
				}
			}
			set(cfg, filtered)
			return saveConfig(cfg)
		},
	})

	return root
}

func init() {
	configCmd.AddCommand(newPathListCommand(
		"readable-paths", "Manage additional readable paths",
		func(c *config.Config) []string { return c.ReadablePaths },
		func(c *config.Config, p []string) { c.ReadablePaths = p },
	))
	configCmd.AddCommand(newPathListCommand(
		"writable-paths", "Manage additional writable paths",
		func(c *config.Config) []string { return c.WritablePaths },
		func(c *config.Config, p []string) { c.WritablePaths = p },
	))
	configCmd.AddCommand(newPathListCommand(
		"internal-readable-paths", "Manage OS-sandbox-only readable paths (denied at the validation layer)",
		func(c *config.Config) []string { return c.InternalReadablePaths },
		func(c *config.Config, p []string) { c.InternalReadablePaths = p },
	))
	configCmd.AddCommand(newPathListCommand(
		"internal-writable-paths", "Manage OS-sandbox-only writable paths (denied at the validation layer)",
		func(c *config.Config) []string { return c.InternalWritablePaths },
		func(c *config.Config, p []string) { c.InternalWritablePaths = p },
	))
}
