package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

// stringListSpec describes one `lite-sandbox config <use>` command managing a
// single string list in the config. get returns the current list from a loaded
// config; set stores the updated list back before saving.
type stringListSpec struct {
	use   string
	short string
	long  string // optional Long text for the parent command

	// noun is the singular item name in the add/remove usage lines
	// ("add <path>..."). items names the collection in the list subcommand's
	// description ("List <items>") and listLabel names it in the add/remove
	// descriptions ("Add <noun>s to the <listLabel> list"); both default to use.
	noun      string
	items     string
	listLabel string

	get func(*config.Config) []string
	set func(*config.Config, []string)
}

// newStringListCommand builds a `lite-sandbox config <use>` command with
// list/add/remove subcommands managing the string list described by spec.
func newStringListCommand(spec stringListSpec) *cobra.Command {
	items := spec.items
	if items == "" {
		items = spec.use
	}
	listLabel := spec.listLabel
	if listLabel == "" {
		listLabel = spec.use
	}

	root := &cobra.Command{
		Use:   spec.use,
		Short: spec.short,
		Long:  spec.long,
	}

	root.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List " + items,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, p := range spec.get(cfg) {
				fmt.Println(p)
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "add <" + spec.noun + ">...",
		Short: "Add " + spec.noun + "s to the " + listLabel + " list",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			values := spec.get(cfg)
			existing := make(map[string]bool, len(values))
			for _, p := range values {
				existing[p] = true
			}
			for _, p := range args {
				if !existing[p] {
					values = append(values, p)
					existing[p] = true
				}
			}
			spec.set(cfg, values)
			return saveConfig(cfg)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "remove <" + spec.noun + ">...",
		Short: "Remove " + spec.noun + "s from the " + listLabel + " list",
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
			values := spec.get(cfg)
			filtered := values[:0]
			for _, p := range values {
				if !toRemove[p] {
					filtered = append(filtered, p)
				}
			}
			spec.set(cfg, filtered)
			return saveConfig(cfg)
		},
	})

	return root
}

func init() {
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "readable-paths",
		short: "Manage additional readable paths",
		noun:  "path",
		get:   func(c *config.Config) []string { return c.ReadablePaths },
		set:   func(c *config.Config, p []string) { c.ReadablePaths = p },
	}))
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "writable-paths",
		short: "Manage additional writable paths",
		noun:  "path",
		get:   func(c *config.Config) []string { return c.WritablePaths },
		set:   func(c *config.Config, p []string) { c.WritablePaths = p },
	}))
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "internal-readable-paths",
		short: "Manage OS-sandbox-only readable paths (denied at the validation layer)",
		noun:  "path",
		get:   func(c *config.Config) []string { return c.InternalReadablePaths },
		set:   func(c *config.Config, p []string) { c.InternalReadablePaths = p },
	}))
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "internal-writable-paths",
		short: "Manage OS-sandbox-only writable paths (denied at the validation layer)",
		noun:  "path",
		get:   func(c *config.Config) []string { return c.InternalWritablePaths },
		set:   func(c *config.Config, p []string) { c.InternalWritablePaths = p },
	}))
}
