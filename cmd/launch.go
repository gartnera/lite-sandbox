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

	"github.com/gartnera/lite-sandbox/config"
)

var launchWithToolHook bool
var launchBashASTHookMode bool
var launchAlwaysLoad bool
var launchPermissionMode string
var launchDryRun bool

var launchCmd = &cobra.Command{
	Use:   "launch <agent> [agent args...]",
	Short: "Run an agent CLI through lite-sandbox without changing its config",
	Long: `Starts an agent CLI configured to route shell commands through lite-sandbox,
without writing anything to the agent's configuration.

This is the temporary alternative to "lite-sandbox install": the same MCP
server, permissions, PreToolUse hook, and usage directive that install writes
to disk are passed as command-line flags for this one run. Nothing on disk is
changed, so the sandbox applies to the launched session only and quitting it
leaves no trace. The agent's own settings (including its sign-in state) are
still loaded and the sandbox settings are layered on top.

Claude Code is the only supported agent for now:

  lite-sandbox launch claude                      # interactive session, sandboxed
  lite-sandbox launch claude -p "run the tests"   # arguments after the agent are passed through
  lite-sandbox launch --with-tool-hook=false claude  # lite-sandbox's own flags come first

Everything after the agent name is handed to the agent untouched, so
lite-sandbox's flags must precede it (or be separated with --).

Because it configures a single session rather than every project the user
opens, launch is stricter than install by default:

  --with-tool-hook      ON by default: a PreToolUse hook confines the built-in
                        Read/Glob/Grep to the sandbox's readable paths and
                        Write/Edit/NotebookEdit to its writable paths, so the
                        built-in file tools respect the same boundary as the
                        bash tool. The built-in Bash tool stays denied outright
                        (unlike "install --with-tool-hook", which moves that
                        block into the hook). Pass --with-tool-hook=false for
                        install's default posture.
  --permission-mode     Claude Code's permission mode for the session, set as
                        permissions.defaultMode; "acceptEdits" by default, so
                        edits inside the boundary apply without a prompt — the
                        hook is what keeps them inside it. Pass an empty value
                        to leave Claude Code's own default alone, or your own
                        --permission-mode after the agent name (a CLI flag wins
                        over the setting).
  --bash-ast-hook-mode  do not configure the MCP server; instead AST-check each
                        built-in Bash command in the hook and allow it when it
                        passes (Bash still runs UNSANDBOXED — a weaker
                        guarantee; see "install --help")
  --always-load         exempt the sandbox MCP tools from tool-search deferral
                        so they load at session start (on by default)

lite-sandbox's own config (lite-sandbox config path) is read as usual — launch
neither creates nor modifies it, so a host with no config runs at the strict
allowlist default. Use "lite-sandbox config ..." to change it, or "install" to
make the agent configuration permanent.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runLaunch,
}

func init() {
	launchCmd.Flags().BoolVar(&launchWithToolHook, "with-tool-hook", true,
		"confine the built-in Read/Write/Edit tools to the sandbox's readable/writable paths with a PreToolUse hook; --with-tool-hook=false for install's default posture (built-in Bash is denied either way)")
	launchCmd.Flags().StringVar(&launchPermissionMode, "permission-mode", "acceptEdits",
		"Claude Code permission mode for the session (permissions.defaultMode), e.g. acceptEdits, plan, default; empty leaves Claude Code's own default alone")
	launchCmd.Flags().BoolVar(&launchBashASTHookMode, "bash-ast-hook-mode", false,
		"statically AST-check the built-in Bash tool in the hook instead of redirecting it — Bash still runs unsandboxed (no runtime enforcement), no MCP server, no Bash deny; combine with --with-tool-hook to also confine Read/Write/Edit")
	launchCmd.Flags().BoolVar(&launchAlwaysLoad, "always-load", true,
		"exempt the sandbox MCP tools from tool-search deferral so they load at session start; --always-load=false to defer them")
	launchCmd.Flags().BoolVar(&launchDryRun, "dry-run", false,
		"print the command that would be run, with the generated configuration, instead of starting the agent")
	// Flags after the agent name belong to the agent, not to us.
	launchCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(launchCmd)
}

// launchTarget is one agent CLI that can be launched through the sandbox. args
// builds the agent's argv (after the binary name) from the sandbox binary path
// and the user's own arguments.
type launchTarget struct {
	name        string // positional-arg name
	displayName string
	bin         string // executable to look up on PATH
	args        func(binPath string, agentArgs []string) ([]string, error)
}

// launchTargets lists the supported agents. Only Claude Code is supported for
// now; the other agents' CLIs have no equivalent way to pass an MCP server,
// permissions, and a hook for a single run.
func launchTargets() []launchTarget {
	return []launchTarget{
		{"claude", "Claude Code", "claude", claudeLaunchArgs},
	}
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
		return fmt.Errorf("unsupported agent %q (supported: %s) — use `lite-sandbox install %s` to configure it permanently instead",
			agent, strings.Join(names, ", "), agent)
	}
	target := targets[i]

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

	argv, err := target.args(binPath, agentArgs)
	if err != nil {
		return err
	}

	if launchDryRun {
		fmt.Println(shellQuote(append([]string{agentPath}, argv...)))
		return nil
	}

	fmt.Fprintf(os.Stderr, "lite-sandbox: launching %s through the sandbox (mode: %s) — no %s configuration was changed\n",
		target.displayName, launchMode(), target.displayName)

	// Replace this process with the agent: it owns the terminal from here, and
	// signals, exit status, and job control all behave as if it had been run
	// directly. There is nothing to clean up afterwards — the configuration
	// lives entirely in argv.
	return syscall.Exec(agentPath, append([]string{agentPath}, argv...), os.Environ())
}

// launchMode reports the enforcement mode the launched agent's commands will be
// validated under, resolved for the current directory the way the MCP server
// resolves it. It is informational only, so any failure degrades to "unknown".
func launchMode() config.Mode {
	wd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	cfg, err := config.LoadForDirectory(wd)
	if err != nil || cfg == nil {
		return "unknown"
	}
	return cfg.EffectiveMode()
}

// claudeLaunchArgs builds Claude Code's arguments for a sandboxed run: the same
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
		argv = append(argv, "--append-system-prompt", claudeDirective)
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
		if a == "" || strings.ContainsAny(a, " \t\n\"'$`\\*?[]{}()<>|&;#~!") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		quoted[i] = a
	}
	return strings.Join(quoted, " ")
}
