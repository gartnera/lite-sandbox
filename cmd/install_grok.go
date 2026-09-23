package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// grokServerName is the name lite-sandbox is registered under in Grok Build's
// config.toml ([mcp_servers.<grokServerName>]). Grok names MCP tools
// `<server>__<tool>`, so the sandbox's bash tool is lite-sandbox__bash.
const grokServerName = "lite-sandbox"

// grokUseToolHint tells the model how to reach the sandbox's bash tool. Grok
// does not list MCP tools directly: the model finds them with search_tool and
// calls them through use_tool with the qualified name.
const grokUseToolHint = "run it with the `lite-sandbox__bash` MCP tool: call `use_tool` with " +
	"`tool_name` \"lite-sandbox__bash\" and `tool_input` {\"command\": \"<the command>\"} " +
	"(add \"run_in_background\": true for long-running commands; `lite-sandbox__bash_output`, " +
	"`lite-sandbox__kill_shell` and `lite-sandbox__list_shells` manage background shells)."

// grokRedirectHint is the short form of grokUseToolHint for the hook's deny
// reason, which Grok clips to 256 characters.
const grokRedirectHint = "Instead call use_tool with tool_name \"lite-sandbox__bash\" and tool_input {\"command\": \"<command>\"}."

// grokDirective is written to ~/.grok/rules/lite-sandbox.md, a rules file Grok
// loads into every session regardless of project or folder trust.
const grokDirective = "# lite-sandbox\n\n" +
	"For every shell command, " + grokUseToolHint + " " +
	"The built-in shell tools (`run_terminal_command`, `monitor`) are blocked and will not run. " +
	"The sandboxed tool is pre-approved and runs commands through lite-sandbox's AST validation " +
	"and filesystem path boundaries. The built-in file tools (`read_file`, `grep`, `list_dir`, " +
	"`search_replace`, `write`, ...) are confined to the same paths: reads and edits outside " +
	"the project are denied.\n"

// grokHookTimeoutSec is the timeout on the registered hook. Grok defaults
// PreToolUse hooks to 5 seconds and fails open on a timeout, so a boundary
// check that runs git or runtime detection on a cold cache must not be cut
// short.
const grokHookTimeoutSec = 30

// The permission rules live in a marker-delimited block appended to
// config.toml, like the Codex hook block: reconciling removes the old block and
// appends a fresh one, leaving the user's content untouched. The rules are
// written as [[permission.rules]] tables, which extend a [permission] table
// the user already has instead of redefining it.
const (
	grokPermissionBlockStart = "# >>> lite-sandbox permissions (managed by `lite-sandbox install grok`) — do not edit inside >>>"
	grokPermissionBlockEnd   = "# <<< lite-sandbox permissions (managed by `lite-sandbox install grok`) <<<"
)

// grokHome returns Grok Build's configuration directory: $GROK_HOME when set,
// otherwise ~/.grok. This mirrors how Grok itself resolves it.
func grokHome() (string, error) {
	if h := os.Getenv("GROK_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".grok"), nil
}

func detectGrok() bool {
	if cliOnPath("grok") {
		return true
	}
	dir, err := grokHome()
	return err == nil && dirExists(dir)
}

// grokPlan is what the install flags resolve to for Grok.
type grokPlan struct {
	// configMCP registers the MCP server, auto-allows its tools, and writes the
	// usage directive. Off in --bash-ast-hook-mode.
	configMCP bool
	// validateBash AST-checks the built-in shell in the hook instead of
	// redirecting it (--bash-ast-hook-mode).
	validateBash bool
	// denyShell adds a permission rule denying the built-in shell, a backstop
	// for the hook: Grok fails open when a hook crashes or times out, but a
	// deny rule always holds. Off when the hook validates the shell in place.
	denyShell   bool
	hookCommand string
}

func grokInstallPlan(binPath string) grokPlan {
	p := grokPlan{
		configMCP:    !installBashASTHookMode,
		validateBash: installBashASTHookMode,
		denyShell:    !installBashASTHookMode,
		hookCommand:  binPath + " hook",
	}
	if p.validateBash {
		p.hookCommand = binPath + " hook --validate-bash"
	}
	return p
}

// runInstallGrok configures Grok Build (xAI's `grok` CLI). Grok's PreToolUse
// protocol is Claude-compatible, so the same `lite-sandbox hook` governs it;
// only the tool names differ, and the hook knows Grok's. Unlike Claude Code,
// the file tools are always governed — --with-tool-hook is implied — because
// Grok's read_file, grep and list_dir otherwise run without a prompt anywhere
// on disk:
//
//   - MCP server in ~/.grok/config.toml, with a permission rule auto-allowing
//     its tools (a hook "allow" does not skip Grok's approval prompt).
//   - A permission rule denying the built-in shell (default mode only).
//   - ~/.grok/hooks/lite-sandbox.json: a PreToolUse hook that redirects the
//     built-in shell (or AST-checks it, in --bash-ast-hook-mode) and confines
//     the file tools to the sandbox's paths. Hooks in ~/.grok/hooks are always
//     trusted, unlike project hooks.
//   - ~/.grok/rules/lite-sandbox.md: the usage directive.
//
// All paths honor GROK_HOME.
func runInstallGrok(binPath string) error {
	grokDir, err := grokHome()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(grokDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", grokDir, err)
	}
	configPath := filepath.Join(grokDir, "config.toml")
	hookPath := filepath.Join(grokDir, "hooks", "lite-sandbox.json")
	rulesPath := filepath.Join(grokDir, "rules", "lite-sandbox.md")
	plan := grokInstallPlan(binPath)

	// 1. MCP server.
	if plan.configMCP {
		if err := configureGrokMCPServer(configPath, binPath); err != nil {
			return fmt.Errorf("failed to configure Grok MCP server: %w", err)
		}
		fmt.Printf("✓ Added MCP server to %s\n", configPath)
	}

	// 2. Permission rules.
	written, err := reconcileGrokPermissions(configPath, plan)
	if err != nil {
		return fmt.Errorf("failed to configure Grok permissions: %w", err)
	}
	switch {
	case !written:
		fmt.Printf("! Could not add permission rules to %s: its [permission] section cannot be\n", configPath)
		fmt.Println("  extended with [[permission.rules]] tables (e.g. it sets `rules = [...]` inline).")
		fmt.Println("  Add these rules to it by hand:")
		fmt.Print(indent(grokPermissionRules(plan), "    "))
	case plan.denyShell:
		fmt.Printf("✓ Allowed lite-sandbox MCP tools and denied the built-in shell in %s\n", configPath)
	case plan.configMCP:
		fmt.Printf("✓ Allowed lite-sandbox MCP tools in %s\n", configPath)
	}

	// 3. PreToolUse hook.
	if err := writeGrokHookFile(hookPath, plan.hookCommand); err != nil {
		return fmt.Errorf("failed to configure Grok hook: %w", err)
	}
	if plan.validateBash {
		fmt.Printf("✓ Registered PreToolUse hook to AST-check the built-in shell (runs unsandboxed) and confine file tools to sandbox paths in %s\n", hookPath)
	} else {
		fmt.Printf("✓ Registered PreToolUse hook to redirect the built-in shell and confine file tools to sandbox paths in %s\n", hookPath)
	}

	// 4. Usage directive. --bash-ast-hook-mode has no MCP tool to point at, so
	// a directive left by an earlier install is removed instead.
	if plan.configMCP {
		if err := writeFileMkdir(rulesPath, []byte(grokDirective)); err != nil {
			return fmt.Errorf("failed to write %s: %w", rulesPath, err)
		}
		fmt.Printf("✓ Added usage directive to %s\n", rulesPath)
	} else if err := os.Remove(rulesPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", rulesPath, err)
	}

	fmt.Println("\n✓ Grok Build installation complete!")
	if installBashASTHookMode {
		fmt.Println("(--bash-ast-hook-mode: MCP server not configured)")
	}
	fmt.Println("Restart Grok for the changes to take effect; /hooks lists the lite-sandbox hook.")
	fmt.Println("Grok also loads Claude Code's hooks, permissions and MCP servers by default; if")
	fmt.Println("Claude Code is configured with a different lite-sandbox mode, both hooks run and")
	fmt.Println("the stricter decision wins.")
	return nil
}

// configureGrokMCPServer registers (or updates) the lite-sandbox MCP server in
// Grok's config.toml, preserving the rest of the file (see upsertTOMLTable).
func configureGrokMCPServer(configPath, binPath string) error {
	header := "[mcp_servers." + grokServerName + "]"
	block := header + "\n" +
		"command = " + tomlString(binPath) + "\n" +
		`args = ["serve-mcp"]` + "\n"
	return upsertTOMLTable(configPath, header, block)
}

// grokPermissionRules renders the plan's permission rules as
// [[permission.rules]] tables, or "" when the plan needs none.
func grokPermissionRules(p grokPlan) string {
	var rules string
	if p.configMCP {
		// Grok's MCP rule patterns glob the qualified server__tool name.
		rules += "[[permission.rules]]\n" +
			`action = "allow"` + "\n" +
			`tool = "mcp"` + "\n" +
			"pattern = " + tomlString(grokMCPToolPrefix+"*") + "\n"
	}
	if p.denyShell {
		if rules != "" {
			rules += "\n"
		}
		// No pattern: every command of the built-in shell.
		rules += "[[permission.rules]]\n" +
			`action = "deny"` + "\n" +
			`tool = "bash"` + "\n"
	}
	return rules
}

// reconcileGrokPermissions makes the managed permission block in config.toml
// match the plan: any prior block is removed and, when the plan has rules, a
// fresh one appended. It reports false (and leaves the file as it was, minus
// any stale block) when appending would make the file invalid TOML — the one
// case being a [permission] section that already defines `rules` as an inline
// array, which [[permission.rules]] tables cannot extend.
func reconcileGrokPermissions(configPath string, p grokPlan) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	content := stripManagedBlock(string(data), grokPermissionBlockStart, grokPermissionBlockEnd)

	rules := grokPermissionRules(p)
	if rules == "" {
		return true, writeIfChanged(configPath, data, content)
	}
	updated := appendConfigBlock(content, grokPermissionBlockStart+"\n"+rules+grokPermissionBlockEnd+"\n")

	// Only refuse when our block is what breaks the file: a config that was
	// already invalid is Grok's to report, not a reason to skip the rules.
	if tomlValid(updated) || !tomlValid(content) {
		return true, os.WriteFile(configPath, []byte(updated), 0644)
	}
	return false, writeIfChanged(configPath, data, content)
}

func tomlValid(content string) bool {
	var v map[string]any
	return toml.Unmarshal([]byte(content), &v) == nil
}

// writeIfChanged writes content to path unless it equals the original bytes,
// so a no-op reconcile does not create or touch the file.
func writeIfChanged(path string, original []byte, content string) error {
	if string(original) == content {
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// writeGrokHookFile writes the hook file lite-sandbox owns in ~/.grok/hooks.
// Grok merges every *.json file in that directory, so owning a whole file
// needs no merging with the user's hooks; reinstalling rewrites it.
func writeGrokHookFile(hookPath, command string) error {
	doc := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": hook.GrokHookMatcher,
					"hooks": []any{
						map[string]any{
							"type":    "command",
							"command": command,
							"timeout": grokHookTimeoutSec,
						},
					},
				},
			},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileMkdir(hookPath, append(out, '\n'))
}

// writeFileMkdir writes data to path, creating its parent directory.
func writeFileMkdir(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// indent prefixes every non-blank line of s with prefix.
func indent(s, prefix string) string {
	var b strings.Builder
	for _, ln := range strings.SplitAfter(s, "\n") {
		if ln != "" && ln != "\n" {
			b.WriteString(prefix)
		}
		b.WriteString(ln)
	}
	return b.String()
}
