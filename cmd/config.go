package cmd

import (
	"fmt"
	"os"
	"reflect"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gartnera/lite-sandbox/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long: `Manage configuration.

Every setting under ` + "`config`" + ` accepts --dir <path>, which scopes the change to
commands run at or under that directory instead of the whole machine: the value
is stored as a per-directory override (the ` + "`overrides`" + ` list in the config file)
and the base config is left alone. Reads honour it too, so
` + "`config <section> show --dir <path>`" + ` prints what that directory resolves to.`,
}

// configDir is the value of the `--dir` flag, registered once as a persistent
// flag on `config` so every subcommand under it inherits the same per-directory
// scoping without wiring up a flag of its own. When it is set, loadConfig hands
// the command the configuration in effect for that directory and saveConfig
// records whatever the command changed as a directory override rather than
// editing the base config.
var configDir string

// configEdit links a loadConfig/saveConfig pair for a --dir edit: the full
// config to write back, the override receiving the changes, and a snapshot of
// the view handed to the command, so saveConfig can tell which sections the
// command actually touched.
type configEdit struct {
	root     *config.Config
	override *config.DirectoryOverride
	before   *config.Config
}

// currentEdit holds the state of the in-flight --dir edit. Every command runs
// one loadConfig and at most one saveConfig, so a single slot is enough;
// loadConfig sets it (or clears it when no --dir is given).
var currentEdit *configEdit

func init() {
	configCmd.PersistentFlags().StringVar(&configDir, "dir", "",
		"apply the setting only to commands run at or under this directory (a per-directory override); reads resolve for it")

	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configOverridesCmd)
	configOverridesCmd.AddCommand(configOverridesListCmd)
	configOverridesCmd.AddCommand(configOverridesRemoveCmd)
	rootCmd.AddCommand(configCmd)
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		p, err := config.Path()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the current configuration as YAML (with --dir, as it resolves for that directory)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if configDir != "" {
			fmt.Printf("# configuration in effect for %s\n", resolveDirArg(configDir))
		}
		return yaml.NewEncoder(os.Stdout).Encode(cfg)
	},
}

var configOverridesCmd = &cobra.Command{
	Use:   "overrides",
	Short: "Inspect and remove the per-directory overrides written by --dir",
}

var configOverridesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the configured per-directory overrides",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if len(cfg.Overrides) == 0 {
			fmt.Println("No per-directory overrides configured")
			return nil
		}
		for i := range cfg.Overrides {
			o := &cfg.Overrides[i]
			fmt.Printf("%s:\n", o.Path)
			body, err := yaml.Marshal(&o.Config)
			if err != nil {
				return err
			}
			for _, line := range splitLines(string(body)) {
				fmt.Printf("  %s\n", line)
			}
		}
		return nil
	},
}

var configOverridesRemoveCmd = &cobra.Command{
	Use:   "remove [dir]",
	Short: "Remove every setting stored for a directory (defaults to --dir)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := dirArgOrFlag(args)
		if err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if !removeOverride(cfg, dir) {
			fmt.Printf("No override configured for %s\n", dir)
			return nil
		}
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Printf("Removed the override for %s\n", dir)
		return nil
	},
}

// loadConfig returns the configuration a config subcommand should read and
// mutate. Without --dir that is the config file itself. With --dir it is the
// configuration that directory resolves to today — the base with any override
// already stored for it applied — deep-copied so mutating it cannot reach the
// shared base sections. Commands therefore need no per-directory code of their
// own: they edit the values they would edit globally, and saveConfig works out
// what changed.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if configDir == "" {
		currentEdit = nil
		return cfg, nil
	}
	view, err := copyConfig(cfg.ForDirectory(configDir))
	if err != nil {
		return nil, err
	}
	before, err := copyConfig(view)
	if err != nil {
		return nil, err
	}
	// overridePtr appends an empty override when the directory has none yet;
	// nothing is written unless the command goes on to call saveConfig, and an
	// override still setting nothing by then is dropped again.
	currentEdit = &configEdit{root: cfg, override: overridePtr(cfg, configDir), before: before}
	return view, nil
}

// saveConfig persists the config a command edited. Without --dir it writes cfg
// straight back. With --dir it copies the sections the command changed into the
// directory override and writes the whole config, so unrelated sections keep
// inheriting from the base. Sections the command left alone are not recorded,
// and an override left setting nothing is removed.
func saveConfig(cfg *config.Config) error {
	ed := currentEdit
	if ed == nil {
		return config.Save(cfg)
	}
	currentEdit = nil

	applyChangedSections(&ed.override.Config, ed.before, cfg)
	dir := resolveDirArg(configDir)
	if ed.override.SetsAnySection() {
		fmt.Printf("Scoped to %s (per-directory override)\n", dir)
	} else {
		removeOverride(ed.root, dir)
		fmt.Printf("%s already resolves to that; no override needed\n", dir)
	}
	return config.Save(ed.root)
}

// configBase returns the base (unscoped) configuration behind the view
// loadConfig handed out, for the few commands that report what the base still
// says while editing a directory override. It must be called before saveConfig,
// which ends the edit.
func configBase(view *config.Config) *config.Config {
	if currentEdit != nil {
		return currentEdit.root
	}
	return view
}

// applyChangedSections copies into dst every top-level section whose value in
// after differs from before — that is, exactly what the command changed.
// Walking the struct reflectively keeps this complete as new config sections are
// added. Overrides itself is skipped: an override cannot nest overrides.
func applyChangedSections(dst, before, after *config.Config) {
	dv := reflect.ValueOf(dst).Elem()
	bv := reflect.ValueOf(before).Elem()
	av := reflect.ValueOf(after).Elem()
	t := dv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Overrides" || !f.IsExported() {
			continue
		}
		if reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
			continue
		}
		dv.Field(i).Set(av.Field(i))
	}
}

// copyConfig returns a deep copy of cfg (minus any overrides, which a resolved
// view does not carry anyway) by round-tripping it through YAML — the same
// representation the config file uses, so every field survives.
func copyConfig(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return &config.Config{}, nil
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("copying config: %w", err)
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("copying config: %w", err)
	}
	out.Overrides = nil
	return &out, nil
}

// rejectConfigDir fails a command that has nothing to scope to a directory (the
// config file path, a host capability check) rather than silently ignoring the
// flag.
func rejectConfigDir(cmd *cobra.Command) error {
	if configDir == "" {
		return nil
	}
	return fmt.Errorf("--dir is not supported by `%s`: it is not a per-directory setting", cmd.CommandPath())
}

// dirArgOrFlag resolves the directory a command was pointed at, accepting either
// a positional argument or --dir.
func dirArgOrFlag(args []string) (string, error) {
	switch {
	case len(args) == 1 && configDir != "":
		return "", fmt.Errorf("pass the directory either as an argument or with --dir, not both")
	case len(args) == 1:
		return resolveDirArg(args[0]), nil
	case configDir != "":
		return resolveDirArg(configDir), nil
	}
	return "", fmt.Errorf("no directory given; pass one as an argument or with --dir")
}

// configScope describes where a change landed, for the confirmation lines
// commands print: empty globally, " for <dir>" under --dir.
func configScope() string {
	if configDir == "" {
		return ""
	}
	return " for " + resolveDirArg(configDir)
}

// splitLines splits YAML output into printable lines, dropping the trailing
// empty one so indented blocks don't end with a stray line.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
