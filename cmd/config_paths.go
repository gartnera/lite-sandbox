package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

var configPathsCmd = &cobra.Command{
	Use:   "paths",
	Short: "Manage the paths commands may read or write, and the paths the OS sandbox hides or keeps read-only",
	Long: `One list of paths carries every statement about a path: a grant widens the
boundary the agent may touch beyond the working directory, a denial is applied
by the OS sandbox in denylist mode on top of the built-in deny lists. Each
entry is a path plus what applies there:

  read: true              readable                            (allow <path>)
  write: true             writable, which implies readable    (allow <path> --write)
  internal: true          the grant holds only at the OS sandbox layer, for
                          programs a command spawns; the agent's own reads and
                          writes there are still refused      (allow ... --internal)
  read: false             hidden entirely, in denylist mode   (deny <path>)
  write: false            readable but not writable, in denylist mode (deny <path> --write)

Paths support ~ expansion; a grant with a trailing /* covers only paths nested
below the directory, not the directory itself. Each path has one entry: allow
and deny replace whatever the config said about it before, including an entry
in one of the deprecated lists (readable_paths, writable_paths,
internal_readable_paths, internal_writable_paths, denied_read_paths,
denied_write_paths), which still load. ` + "`migrate`" + ` rewrites those lists in bulk.
` + "`lite-sandbox config mode show`" + ` prints the deny lists in effect, built-in
entries included.`,
}

var (
	pathsAllowWrite    bool
	pathsAllowInternal bool
	pathsDenyRead      bool
	pathsDenyWrite     bool
)

var configPathsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the configured path grants and denials",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		entries := cfg.AllPathEntries()
		if len(entries) == 0 {
			fmt.Println("No paths configured (the working directory is always readable and writable)")
			return nil
		}
		legacy := len(cfg.LegacyPathEntries())
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		for i, e := range entries {
			note := ""
			if i >= len(entries)-legacy {
				note = "\t(deprecated key)"
			}
			fmt.Fprintf(w, "%s\t%s%s\n", e.Path, e.Describe(), note)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if legacy > 0 {
			fmt.Println("\nEntries marked (deprecated key) still use the old one-list-per-kind keys; `lite-sandbox config paths migrate` rewrites them as `paths` entries.")
		}
		return nil
	},
}

var configPathsAllowCmd = &cobra.Command{
	Use:   "allow <path>...",
	Short: "Grant read access to paths (--write for read and write; --internal for the OS sandbox layer only)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		yes := true
		for _, p := range args {
			e := config.PathEntry{Path: p, Internal: pathsAllowInternal}
			if pathsAllowWrite {
				e.Write = &yes
			} else {
				e.Read = &yes
			}
			if err := cfg.SetPath(e); err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", p, e.Describe())
		}
		return saveConfig(cfg)
	},
}

var configPathsDenyCmd = &cobra.Command{
	Use:   "deny <path>...",
	Short: "Deny paths under the OS sandbox in denylist mode: hidden entirely (default, --read), or readable but not writable (--write)",
	Long: `Denials extend the built-in deny lists the OS sandbox applies in denylist mode
(credential stores hidden, shell startup files and the agents' settings kept
read-only; ` + "`lite-sandbox config mode show`" + ` prints them). ~ is expanded and a
missing path is skipped until it exists. Without the OS sandbox there is
nothing to apply them to, and in allowlist mode the sandbox keeps its
cwd-confined layout and the lists are unused.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		no := false
		for _, p := range args {
			e := config.PathEntry{Path: p}
			// A read denial hides the path, writes included, so it wins when
			// both flags are given.
			if pathsDenyWrite && !pathsDenyRead {
				e.Write = &no
			} else {
				e.Read = &no
			}
			if err := cfg.SetPath(e); err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", p, e.Describe())
		}
		return saveConfig(cfg)
	},
}

var configPathsRemoveCmd = &cobra.Command{
	Use:   "remove <path>...",
	Short: "Remove every grant or denial recorded for paths",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, p := range args {
			if cfg.RemovePath(p) {
				fmt.Printf("%s removed\n", p)
			} else {
				fmt.Printf("%s is not configured; nothing to remove\n", p)
			}
		}
		return saveConfig(cfg)
	},
}

var configPathsMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Rewrite the deprecated one-list-per-kind path keys as `paths` entries, in the base config and every override",
	Long: `The deprecated keys (readable_paths, writable_paths, internal_readable_paths,
internal_writable_paths, denied_read_paths, denied_write_paths) keep loading,
so this is optional. It rewrites them once, everywhere in the file, keeping
what every directory resolves to: an old-style override replaced only the list
it set and inherited the rest, whereas a paths list replaces the whole section,
so an override that set any path list receives the full set of entries in
effect for its directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		n := cfg.MigratePaths()
		if n == 0 {
			fmt.Println("Nothing to migrate: no deprecated path keys in the config")
			return nil
		}
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Printf("Rewrote %d path entries as `paths`\n", n)
		return nil
	},
}

// deprecatedPathListCommand builds one of the six former path-list commands
// (`readable-paths`, `denied-write-paths`, ...) as a hidden alias of `paths`,
// so a script written for it keeps working while its help points at the new
// command. list prints the entries of that kind, add records the equivalent
// paths entry, and remove drops every statement about the path.
func deprecatedPathListCommand(use, replacement string, kind func(config.PathEntry) bool, entry func(path string) config.PathEntry) *cobra.Command {
	root := &cobra.Command{
		Use:    use,
		Short:  "Deprecated: use `lite-sandbox config paths " + replacement + "`",
		Hidden: true,
	}
	deprecated := "use `lite-sandbox config paths " + replacement + "` instead"
	root.AddCommand(&cobra.Command{
		Use:        "list",
		Short:      "List these paths",
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, e := range cfg.AllPathEntries() {
				if kind(e) {
					fmt.Println(e.Path)
				}
			}
			return nil
		},
	})
	root.AddCommand(&cobra.Command{
		Use:        "add <path>...",
		Short:      "Add paths",
		Args:       cobra.MinimumNArgs(1),
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, p := range args {
				if err := cfg.SetPath(entry(p)); err != nil {
					return err
				}
			}
			return saveConfig(cfg)
		},
	})
	root.AddCommand(&cobra.Command{
		Use:        "remove <path>...",
		Short:      "Remove paths",
		Args:       cobra.MinimumNArgs(1),
		Deprecated: "use `lite-sandbox config paths remove` instead",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, p := range args {
				cfg.RemovePath(p)
			}
			return saveConfig(cfg)
		},
	})
	return root
}

func init() {
	configCmd.AddCommand(configPathsCmd)
	configPathsCmd.AddCommand(configPathsListCmd)
	configPathsCmd.AddCommand(configPathsAllowCmd)
	configPathsCmd.AddCommand(configPathsDenyCmd)
	configPathsCmd.AddCommand(configPathsRemoveCmd)
	configPathsCmd.AddCommand(configPathsMigrateCmd)

	configPathsAllowCmd.Flags().BoolVar(&pathsAllowWrite, "write", false, "grant write access as well as read")
	configPathsAllowCmd.Flags().BoolVar(&pathsAllowInternal, "internal", false, "grant only at the OS sandbox layer, for programs a command spawns; the agent's own reads and writes there stay refused")
	configPathsDenyCmd.Flags().BoolVar(&pathsDenyRead, "read", false, "hide the path entirely (the default)")
	configPathsDenyCmd.Flags().BoolVar(&pathsDenyWrite, "write", false, "keep the path readable but refuse writes")

	yes, no := true, false
	notInternal := func(e config.PathEntry) bool { return !e.Internal }
	internal := func(e config.PathEntry) bool { return e.Internal }
	configCmd.AddCommand(deprecatedPathListCommand("readable-paths", "allow",
		func(e config.PathEntry) bool { return e.GrantsRead() && notInternal(e) },
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Read: &yes} }))
	configCmd.AddCommand(deprecatedPathListCommand("writable-paths", "allow --write",
		func(e config.PathEntry) bool { return e.GrantsWrite() && notInternal(e) },
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Write: &yes} }))
	configCmd.AddCommand(deprecatedPathListCommand("internal-readable-paths", "allow --internal",
		func(e config.PathEntry) bool { return e.GrantsRead() && internal(e) },
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Read: &yes, Internal: true} }))
	configCmd.AddCommand(deprecatedPathListCommand("internal-writable-paths", "allow --write --internal",
		func(e config.PathEntry) bool { return e.GrantsWrite() && internal(e) },
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Write: &yes, Internal: true} }))
	configCmd.AddCommand(deprecatedPathListCommand("denied-read-paths", "deny",
		config.PathEntry.DeniesRead,
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Read: &no} }))
	configCmd.AddCommand(deprecatedPathListCommand("denied-write-paths", "deny --write",
		config.PathEntry.DeniesWrite,
		func(p string) config.PathEntry { return config.PathEntry{Path: p, Write: &no} }))
}
