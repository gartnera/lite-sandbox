package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/gartnera/lite-sandbox/config"
)

var launchWithToolHook bool
var launchBashASTHookMode bool
var launchAlwaysLoad bool
var launchPermissionMode string
var launchDryRun bool

var launchCmd = &cobra.Command{
	Use:   "launch <claude|codex|opencode|crush> [agent args...]",
	Short: "Run an agent CLI through lite-sandbox without changing its config",
	Long: `Starts an agent CLI configured to route shell commands through lite-sandbox,
without writing anything to the agent's configuration.

This is the temporary alternative to "lite-sandbox install": the same MCP
server, permissions, hook, and usage directive that install writes to disk are
passed on the agent's command line (or in its environment) for this one run.
The agent's configuration is not changed, so the sandbox applies to the
launched session only. The agent's own settings (including its sign-in state)
are still loaded and the sandbox settings are layered on top.

  lite-sandbox launch claude                      # interactive session, sandboxed
  lite-sandbox launch claude -p "run the tests"   # arguments after the agent are passed through
  lite-sandbox launch codex exec "run the tests"
  lite-sandbox launch opencode
  lite-sandbox launch crush
  lite-sandbox launch --with-tool-hook=false claude  # lite-sandbox's own flags come first

Everything after the agent name is handed to the agent untouched, so
lite-sandbox's flags must precede it (or be separated with --).

Per agent:

  claude    --mcp-config (MCP server), --settings (permissions, permission
            mode, PreToolUse hook), --append-system-prompt (directive).
  codex     -c overrides (MCP server, developer_instructions), --disable
            shell_tool (the built-in shell is removed, so no hook is needed to
            block it), and with a hook -c hooks.PreToolUse plus
            --dangerously-bypass-hook-trust: Codex skips hooks the user has not
            trusted, and trust can only be granted in its /hooks screen. The
            bypass applies to every enabled hook for the session, your own
            included; --with-tool-hook=false avoids it.
  opencode  OPENCODE_CONFIG_CONTENT (MCP server, bash denied, directive file).
  crush     CRUSH_GLOBAL_CONFIG pointing at a generated directory whose
            crushrc sources your own global crushrc (and links your
            crush.json), then adds the MCP server and denies bash.

opencode's directive and Crush's generated config are kept in lite-sandbox's
cache directory (rewritten on each launch), not in the agent's config. Grok
Build is not supported: its CLI has no way to add an MCP server or hook for a
single session. Use "lite-sandbox install grok".

Because it configures a single session rather than every project the user
opens, launch is stricter than install by default:

  --with-tool-hook      ON by default (claude, codex): a PreToolUse hook
                        confines the built-in file tools (Read/Glob/Grep,
                        Write/Edit/NotebookEdit, Codex's apply_patch) to the
                        sandbox's readable/writable paths. The built-in shell
                        stays blocked outright. Pass --with-tool-hook=false for
                        install's default posture. opencode and Crush have no
                        compatible hook, so their file tools are not confined.
  --permission-mode     Claude Code only: its permission mode for the session,
                        set as permissions.defaultMode; "acceptEdits" by
                        default, so edits inside the boundary apply without a
                        prompt — the hook is what keeps them inside it. Pass an
                        empty value to leave Claude Code's own default alone,
                        or your own --permission-mode after the agent name (a
                        CLI flag wins over the setting).
  --bash-ast-hook-mode  claude, codex: do not configure the MCP server;
                        instead AST-check each built-in shell command in the
                        hook and allow it when it passes (the shell still runs
                        UNSANDBOXED — a weaker guarantee; see "install --help")
  --always-load         claude, codex: exempt the sandbox MCP tools from
                        tool-search deferral so they load at session start (on
                        by default)

lite-sandbox's own config (lite-sandbox config path) is read as usual — launch
neither creates nor modifies it, so a host with no config runs at the strict
allowlist default. Use "lite-sandbox config ..." to change it, or "install" to
make the agent configuration permanent.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runLaunch,
}

func init() {
	launchCmd.Flags().BoolVar(&launchWithToolHook, "with-tool-hook", true,
		"confine the built-in file tools to the sandbox's readable/writable paths with a PreToolUse hook (claude, codex); --with-tool-hook=false for install's default posture (the built-in shell is blocked either way)")
	launchCmd.Flags().StringVar(&launchPermissionMode, "permission-mode", "acceptEdits",
		"Claude Code permission mode for the session (permissions.defaultMode), e.g. acceptEdits, plan, default; empty leaves Claude Code's own default alone")
	launchCmd.Flags().BoolVar(&launchBashASTHookMode, "bash-ast-hook-mode", false,
		"statically AST-check the built-in shell in the hook instead of replacing it (claude, codex) — the shell still runs unsandboxed (no runtime enforcement), no MCP server; combine with --with-tool-hook to also confine the file tools")
	launchCmd.Flags().BoolVar(&launchAlwaysLoad, "always-load", true,
		"exempt the sandbox MCP tools from tool-search deferral so they load at session start (claude, codex); --always-load=false to defer them")
	launchCmd.Flags().BoolVar(&launchDryRun, "dry-run", false,
		"print the command that would be run, with the generated configuration, instead of starting the agent")
	// Flags after the agent name belong to the agent, not to us.
	launchCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(launchCmd)
}

// launchSpec is how one agent is started through the sandbox: its arguments
// (the agent's own arguments already placed among them) and the environment
// variables to set on top of ours.
type launchSpec struct {
	args []string
	env  []string // KEY=VALUE
	// notes are printed to stderr before the agent starts.
	notes []string
}

// launchTarget is one agent CLI that can be launched through the sandbox.
type launchTarget struct {
	name        string // positional-arg name
	displayName string
	bin         string // executable to look up on PATH
	// hooks reports that the agent takes lite-sandbox's PreToolUse hook, so
	// --with-tool-hook and --bash-ast-hook-mode apply to it.
	hooks bool
	// permissionMode reports that --permission-mode applies.
	permissionMode bool
	prepare        func(binPath string, agentArgs []string) (launchSpec, error)
}

func launchTargets() []launchTarget {
	return []launchTarget{
		{"claude", "Claude Code", "claude", true, true, claudeLaunchSpec},
		{"codex", "Codex", "codex", true, false, codexLaunchSpec},
		{"opencode", "opencode", "opencode", false, false, opencodeLaunchSpec},
		{"crush", "Crush", "crush", false, false, crushLaunchSpec},
	}
}

// launchUnsupported explains, per agent install supports, why launch can't.
var launchUnsupported = map[string]string{
	"grok": "Grok Build's CLI can't add an MCP server or a hook for a single session (its GROK_CONFIG overlay only accepts soft settings, and --plugin-dir is limited to `grok agent stdio`)",
}

func runLaunch(cmd *cobra.Command, args []string) error {
	agent, agentArgs := args[0], args[1:]
	targets := launchTargets()
	i := slices.IndexFunc(targets, func(t launchTarget) bool { return t.name == agent })
	if i == -1 {
		names := make([]string, len(targets))
		for j, t := range targets {
			names[j] = t.name
		}
		why := ""
		if reason, ok := launchUnsupported[agent]; ok {
			why = ": " + reason
		}
		return fmt.Errorf("unsupported agent %q%s (launch supports: %s) — use `lite-sandbox install %s` to configure it permanently instead",
			agent, why, strings.Join(names, ", "), agent)
	}
	target := targets[i]
	if err := checkLaunchFlags(target, cmd.Flags()); err != nil {
		return err
	}

	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	agentPath, err := exec.LookPath(target.bin)
	if err != nil {
		return fmt.Errorf("%s CLI not found on PATH (looked for %q): %w", target.displayName, target.bin, err)
	}

	spec, err := target.prepare(binPath, agentArgs)
	if err != nil {
		return err
	}

	if launchDryRun {
		var line []string
		for _, kv := range spec.env {
			k, v, _ := strings.Cut(kv, "=")
			line = append(line, k+"="+shellQuote([]string{v}))
		}
		fmt.Println(strings.Join(append(line, shellQuote(append([]string{agentPath}, spec.args...))), " "))
		return nil
	}

	fmt.Fprintf(os.Stderr, "lite-sandbox: launching %s through the sandbox (mode: %s) — no %s configuration was changed\n",
		target.displayName, launchMode(), target.displayName)
	for _, note := range spec.notes {
		fmt.Fprintf(os.Stderr, "lite-sandbox: %s\n", note)
	}

	// Replace this process with the agent: it owns the terminal from here, and
	// signals, exit status, and job control all behave as if it had been run
	// directly. There is nothing to clean up afterwards — the configuration
	// lives in argv, the environment, and lite-sandbox's own cache.
	return syscall.Exec(agentPath, append([]string{agentPath}, spec.args...), withEnv(os.Environ(), spec.env))
}

// checkLaunchFlags rejects lite-sandbox flags the user set explicitly that do
// nothing for target, rather than silently running without them.
func checkLaunchFlags(target launchTarget, flags *pflag.FlagSet) error {
	if !target.permissionMode && flags.Changed("permission-mode") {
		return fmt.Errorf("--permission-mode applies only to Claude Code; pass %s's own permission flags after the agent name instead", target.displayName)
	}
	if !target.hooks {
		if launchBashASTHookMode {
			return fmt.Errorf("--bash-ast-hook-mode needs lite-sandbox's PreToolUse hook, which %s has no compatible protocol for", target.displayName)
		}
		if on, _ := flags.GetBool("with-tool-hook"); on && flags.Changed("with-tool-hook") {
			return fmt.Errorf("--with-tool-hook needs lite-sandbox's PreToolUse hook, which %s has no compatible protocol for", target.displayName)
		}
	}
	return nil
}

// withEnv returns environ with each KEY=VALUE in extra set, replacing any
// existing value for the key.
func withEnv(environ, extra []string) []string {
	out := slices.Clone(environ)
	for _, kv := range extra {
		key, _, _ := strings.Cut(kv, "=")
		out = slices.DeleteFunc(out, func(e string) bool { return strings.HasPrefix(e, key+"=") })
		out = append(out, kv)
	}
	return out
}

// launchMode reports the enforcement mode the launched agent's commands will be
// validated under, resolved for the current directory the way the MCP server
// resolves it. It is informational only, so any failure degrades to "unknown".
func launchMode() config.Mode {
	wd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	cfg, err := config.LoadSettingsForDirectory(wd)
	if err != nil || cfg == nil {
		return "unknown"
	}
	return cfg.EffectiveMode()
}

// launchCacheDir returns (creating it) the directory launch keeps generated
// files in for agent: lite-sandbox's own cache directory, never the agent's
// config. It is as protected as lite-sandbox's config: outside the path
// boundary, and write-denied under the OS sandbox in denylist mode (see
// config.DefaultDeniedWritePaths), which matters because Crush executes the
// crushrc kept there. The files are rewritten on every launch, so nothing
// needs cleaning up after the agent exits.
func launchCacheDir(agent string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine cache directory: %w", err)
	}
	dir := filepath.Join(cache, "lite-sandbox", "launch", agent)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", dir, err)
	}
	return dir, nil
}

// writeFileAtomic writes data to path through a temporary file and a rename,
// so an agent started by a concurrent launch never reads a partial file.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		os.Remove(f.Name())
		return err
	}
	return nil
}

// claudeLaunchSpec builds Claude Code's arguments for a sandboxed run: the same
// plan `install claude` writes to ~/.claude.json, settings.json and CLAUDE.md,
// expressed as the flags Claude Code accepts for a single session.
//
//   - --mcp-config adds the lite-sandbox MCP server (without --strict-mcp-config,
//     so the user's own servers still load);
//   - --settings layers the tool permissions, the permission mode, and the
//     PreToolUse hook over the user's settings (they are merged with the
//     user's own, not substituted for them);
//   - --append-system-prompt carries the usage directive that install appends to
//     CLAUDE.md.
//
// --mcp-config is variadic, so it goes first and the agent's own arguments go
// last: a variadic flag would otherwise swallow whatever follows it.
func claudeLaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	argv, err := claudeLaunchArgs(binPath, agentArgs)
	return launchSpec{args: argv}, err
}

func claudeLaunchArgs(binPath string, agentArgs []string) ([]string, error) {
	plan := claudeLaunchOptions().plan(binPath)

	var argv []string
	mcpConfig, err := plan.mcpConfigJSON(binPath)
	if err != nil {
		return nil, fmt.Errorf("building MCP config: %w", err)
	}
	if mcpConfig != "" {
		argv = append(argv, "--mcp-config", mcpConfig)
	}
	settings, err := plan.settingsJSON()
	if err != nil {
		return nil, fmt.Errorf("building settings: %w", err)
	}
	argv = append(argv, "--settings", settings)
	if plan.configMCP {
		argv = append(argv, "--append-system-prompt", strings.Join(claudeDirectives, "\n\n"))
	}
	return append(argv, agentArgs...), nil
}

// claudeLaunchOptions is the launch command's flags as the shared Claude
// options (see claudeOptions).
func claudeLaunchOptions() claudeOptions {
	return claudeOptions{
		withToolHook: launchWithToolHook,
		// Unlike install's --with-tool-hook, the hook governs the filesystem
		// tools while the built-in Bash tool stays denied by permission: the
		// model is not offered a shell it would only be redirected away from,
		// and the block does not depend on the hook running.
		redirectBash:    false,
		bashASTHookMode: launchBashASTHookMode,
		alwaysLoad:      launchAlwaysLoad,
		permissionMode:  launchPermissionMode,
	}
}

// shellQuote renders an argv as a copy-pasteable shell command line, for
// --dry-run.
func shellQuote(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\n\"'$`\\*?[]{}()<>|&;#~!=") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		quoted[i] = a
	}
	return strings.Join(quoted, " ")
}
