package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/configrequest"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long: `Manage configuration.

Every setting under ` + "`config`" + ` is scoped to the project by default: the root of
the git repository the working directory is in (a linked worktree's main
worktree), or the working directory itself outside one. The change applies to
commands run at or under it, stored as a per-directory override (the
` + "`overrides`" + ` list in the config file), and the base config is left alone.
--dir <path> scopes it to that directory instead, and --global edits the base
config, which applies everywhere. Reads honour the same scope, so
` + "`config <section> show`" + ` prints what the project resolves to and
` + "`config <section> show --global`" + ` prints the base config.`,
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
	// created is set when the edit created the override (see loadConfig), so
	// recordEdit may still pick how it combines with the base.
	created bool
}

// currentEdit holds the state of the in-flight --dir edit. Every command runs
// one loadConfig and at most one saveConfig, so a single slot is enough;
// loadConfig sets it (or clears it when no --dir is given).
var currentEdit *configEdit

// checkConfigRequestDir refuses a config subcommand run for a config request
// (configrequest.DirEnv set by the MCP server) unless what it parsed is the
// scope the user approved: the base config when configrequest.GlobalEnv is
// "1", and otherwise exactly the request's project directory. The server
// parsed the request the same way (parseConfigRequest); this holds even if
// the two ever disagree.
func checkConfigRequestDir() error {
	env := os.Getenv(configrequest.DirEnv)
	if env == "" {
		return nil
	}
	approvedGlobal := os.Getenv(configrequest.GlobalEnv) == "1"
	if configGlobal != approvedGlobal {
		return fmt.Errorf("refusing a config request whose --global (%v) differs from the one approved (%v)", configGlobal, approvedGlobal)
	}
	if configGlobal {
		return nil
	}
	if configDir == "" || resolveDirArg(configDir) != filepath.Clean(env) {
		return fmt.Errorf("refusing a config request scoped to %q: the approved scope is the project %s", configDir, env)
	}
	return nil
}

// configGlobal is the value of the `--global` flag: edit (and read) the base
// config rather than the per-directory override --dir defaults to.
var configGlobal bool

// configDirExplicit records that --dir was given on the command line rather
// than defaulted, so hints can repeat it only when the user typed it.
var configDirExplicit bool

// scopeFlags returns the scope flag the user gave, as it would be repeated in a
// suggested follow-up command: " --global", " --dir <dir>", or "" for the
// default (the project).
func scopeFlags() string {
	switch {
	case configGlobal:
		return " --global"
	case configDirExplicit:
		return " --dir " + configDir
	}
	return ""
}

// wholeFileAnnotation marks a config subcommand that is not a per-directory
// setting (the config file path, `edit`, `migrate`, the override listing):
// --dir does not default to the working directory for it.
const wholeFileAnnotation = "lite-sandbox/whole-file"

// wholeFile is the Annotations value marking a command wholeFileAnnotation.
var wholeFile = map[string]string{wholeFileAnnotation: "true"}

// interactiveAnnotation marks a config subcommand that needs a terminal (such
// as `edit`, which opens $EDITOR). A config request runs with none, so
// parseConfigRequest refuses one.
const interactiveAnnotation = "lite-sandbox/interactive"

// readOnlyAnnotation marks a config subcommand for a single setting that only
// prints it and changes nothing. An agent's config request for one runs
// without the user's approval (parseConfigRequest), as the user would run it,
// so mark only a single-setting command whose every run leaves the config as
// it was, never a wholeFileAnnotation or deprecated one (a test checks).
const readOnlyAnnotation = "lite-sandbox/read-only"

// readOnly is the Annotations value marking a command readOnlyAnnotation.
var readOnly = map[string]string{readOnlyAnnotation: "true"}

// applyDefaultConfigDir scopes a config subcommand to the project — the git
// root, a linked worktree's main worktree, or the working directory outside a
// repository (configrequest.DefaultDir) — when neither --dir nor --global is
// given, so a change reaches beyond the current project only when asked to
// with --global. Under a config request it is the directory the server hands
// over (configrequest.DirEnv), which the user approved, rather than one
// resolved again here.
func applyDefaultConfigDir(cmd *cobra.Command) error {
	configDirExplicit = configDir != ""
	if configGlobal && configDir != "" {
		return fmt.Errorf("--dir and --global cannot be used together")
	}
	if configGlobal || configDir != "" || cmd.Annotations[wholeFileAnnotation] != "" {
		return nil
	}
	if approved := os.Getenv(configrequest.DirEnv); approved != "" {
		configDir = approved
		return nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("finding the working directory to scope the change to (pass --dir or --global): %w", err)
	}
	configDir = configrequest.DefaultDir(wd)
	return nil
}

func init() {
	configCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// cobra runs only the nearest PersistentPreRun, so run the root's too.
		rootCmd.PersistentPreRun(cmd, args)
		if err := applyDefaultConfigDir(cmd); err != nil {
			return err
		}
		return checkConfigRequestDir()
	}
	configCmd.PersistentFlags().StringVar(&configDir, "dir", "",
		"apply the setting only to commands run at or under this directory (a per-directory override; default: the git root, else the working directory); reads resolve for it")
	configCmd.PersistentFlags().BoolVar(&configGlobal, "global", false,
		"apply the setting to every directory (the base config) instead of the project; reads show the base config")

	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configOverridesCmd)
	configOverridesCmd.AddCommand(configOverridesListCmd)
	configOverridesCmd.AddCommand(configOverridesRemoveCmd)
	rootCmd.AddCommand(configCmd)
}

var configPathCmd = &cobra.Command{
	Annotations: wholeFile,
	Use:         "path",
	Short:       "Print the config file path",
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
	Annotations: readOnly,
	Use:         "show",
	Short:       "Print the current configuration as YAML (with --dir, as it resolves for that directory)",
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
	Annotations: wholeFile,
	Use:         "list",
	Short:       "List the configured per-directory overrides",
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
	Annotations: wholeFile,
	Use:         "remove [dir]",
	Short:       "Remove every setting stored for a directory (defaults to --dir)",
	Args:        cobra.MaximumNArgs(1),
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
	// override still setting nothing by then is dropped again. A new override
	// deep-merges into the base, so it records only what the command changed
	// in `paths` and `commands`, where later edits to the base keep reaching
	// the directory (recordEdit falls back to replace-style when the change
	// clears a setting, which a deep merge would inherit back from the base).
	// An existing override keeps whichever merge setting it already has.
	isNew := findOverride(cfg, configDir) == nil
	o := overridePtr(cfg, configDir)
	if isNew {
		o.Merge = true
	}
	currentEdit = &configEdit{root: cfg, override: o, before: before, created: isNew}
	return view, nil
}

// saveConfig persists the config a command edited. Without --dir it writes cfg
// straight back. With --dir it copies the sections the command changed into the
// directory override and writes the whole config, so unrelated sections keep
// inheriting from the base. Sections the command left alone are not recorded,
// and an override left setting nothing is removed.
//
// On a merge: true override the keyed sections (`paths`, `commands`) are then
// reduced to the delta against the base, since that override inherits them
// entry by entry: it records what the command changed, not a frozen copy of
// the base's entries. What such an edit cannot do is unstate an inherited
// entry, so those are reported rather than silently ignored.
func saveConfig(cfg *config.Config) error {
	ed := currentEdit
	if ed == nil {
		return config.Save(cfg)
	}
	currentEdit = nil

	dir := resolveDirArg(configDir)
	recordEdit(ed.override, ed.root, ed.before, cfg, ed.created)
	scoped := ed.override.SetsAnySection()
	if !scoped {
		removeOverride(ed.root, dir)
	}
	// What the directory will actually resolve to once this is written, which
	// is not always what the command produced: an override inherits the
	// sections it does not set, and a merge: true override inherits `paths`
	// and `commands` entry by entry.
	inherited := inheritedStatements(ed.root.ForDirectory(dir), cfg)
	switch {
	case scoped:
		fmt.Printf("Scoped to %s (per-directory override)\n", dir)
	case len(inherited) == 0:
		fmt.Printf("%s already resolves to that; no override needed\n", dir)
	}
	reportInheritedEntries(dir, inherited)
	return config.Save(ed.root)
}

// recordEdit copies what a command changed into the directory override: the
// sections whose value differs from the view it was handed, reduced on a
// merge: true override to the delta against the base, since that override
// inherits `paths` and `commands` entry by entry.
//
// A deep merge cannot clear a setting: a field the override leaves unset
// inherits the base's. So when the edit created the override (which then holds
// nothing but this change) and the change clears one — `aws disable`, or
// `aws force-profile` dropping a base allow_raw_credentials — the override is
// written replace-style instead, storing each changed section whole.
func recordEdit(o *config.DirectoryOverride, base, before, after *config.Config, created bool) {
	applyChangedSections(&o.Config, before, after)
	if created && o.Merge && !mergeResolvesTo(o, base, before, after) {
		o.Merge = false
		o.Config = config.Config{}
		applyChangedSections(&o.Config, before, after)
	}
	config.PruneRestatedEntries(o, base)
}

// mergeResolvesTo reports whether the directory of override o, combined with
// base, resolves to after in every non-list section the command changed. List
// sections are left out: the leaf lists combine the same way in either merge
// mode, and an entry of a keyed list (`paths`, `commands`) that the override
// cannot drop is reported by inheritedStatements instead.
func mergeResolvesTo(o *config.DirectoryOverride, base, before, after *config.Config) bool {
	probe := *base
	probe.Overrides = []config.DirectoryOverride{*o}
	resolved := probe.ForDirectory(o.Path)
	rv := reflect.ValueOf(resolved).Elem()
	bv := reflect.ValueOf(before).Elem()
	av := reflect.ValueOf(after).Elem()
	t := av.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Overrides" || !f.IsExported() || f.Type.Kind() == reflect.Slice {
			continue
		}
		if reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
			continue
		}
		if !reflect.DeepEqual(rv.Field(i).Interface(), av.Field(i).Interface()) {
			return false
		}
	}
	return true
}

// inheritedStatement is one `paths` or `commands` entry a --dir edit could not
// drop: the directory goes on resolving to it however the command edited its
// view, because an override inherits what it does not state — a section it
// never sets, and, on a merge: true override, every entry it does not restate.
// An override can say something else about a subject; it cannot say nothing.
type inheritedStatement struct{ section, subject, effect string }

// inheritedStatements returns the statements resolved still makes that view —
// the configuration the command produced — no longer does. Both sides are read
// through AllPathEntries/AllCommandEntries, so the deprecated one-list-per-kind
// keys count as statements too, inherited the same way.
func inheritedStatements(resolved, view *config.Config) []inheritedStatement {
	var out []inheritedStatement
	paths := view.AllPathEntries()
	for _, e := range resolved.AllPathEntries() {
		if !slices.ContainsFunc(paths, func(v config.PathEntry) bool { return v.SamePath(e.Path) }) {
			out = append(out, inheritedStatement{"paths", e.Path, e.Describe()})
		}
	}
	commands := view.AllCommandEntries()
	for _, e := range resolved.AllCommandEntries() {
		if !slices.ContainsFunc(commands, func(v config.CommandEntry) bool { return v.SameCommand(e.Command) }) {
			out = append(out, inheritedStatement{"commands", e.Text(), e.Describe()})
		}
	}
	return out
}

// stillStated reports whether the directory of the in-flight --dir edit will
// go on resolving to a statement about a subject once the edit is written, so
// a command can tell that the removal it just made to its view will not take
// effect there. It answers by building the override exactly as saveConfig
// will and resolving the directory against a copy of the config, which is
// cheap and keeps the two answers from drifting apart.
func stillStated(view *config.Config, states func(*config.Config) bool) bool {
	ed := currentEdit
	if ed == nil {
		return false
	}
	dir := resolveDirArg(configDir)
	probe := *ed.root
	probe.Overrides = slices.Clone(ed.root.Overrides)
	i := slices.IndexFunc(probe.Overrides, func(o config.DirectoryOverride) bool { return o.Path == ed.override.Path })
	if i < 0 {
		return false
	}
	o := probe.Overrides[i]
	recordEdit(&o, &probe, ed.before, view, ed.created)
	if o.SetsAnySection() {
		probe.Overrides[i] = o
	} else {
		probe.Overrides = slices.Delete(probe.Overrides, i, i+1)
	}
	return states(probe.ForDirectory(dir))
}

// stillStatesPath reports whether the directory will still resolve to a
// statement about path p after the in-flight --dir edit.
func stillStatesPath(view *config.Config, p string) bool {
	return stillStated(view, func(c *config.Config) bool {
		return slices.ContainsFunc(c.AllPathEntries(), func(e config.PathEntry) bool { return e.SamePath(p) })
	})
}

// stillStatesCommand reports whether the directory will still resolve to a
// statement about the command text after the in-flight --dir edit.
func stillStatesCommand(view *config.Config, text string) bool {
	return stillStated(view, func(c *config.Config) bool {
		return slices.ContainsFunc(c.AllCommandEntries(), func(e config.CommandEntry) bool { return e.SameCommand(text) })
	})
}

// reportInheritedEntries explains the statements a --dir edit could not drop,
// so a removal that cannot take effect for the directory is never reported as
// one (see inheritedStatement).
func reportInheritedEntries(dir string, inherited []inheritedStatement) {
	for _, e := range inherited {
		fmt.Printf("%s: %q in the base config still applies to %s — an override can restate an entry, not drop it\n",
			e.subject, e.effect, dir)
		fmt.Printf("  remove it everywhere with `lite-sandbox config %s remove %s --global`, or state something else here with `lite-sandbox config %s allow|deny %s --dir %s`\n",
			e.section, e.subject, e.section, e.subject, dir)
	}
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
