package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// installCodex selects the OpenAI Codex CLI install target instead of Claude
// Code. Set by the --codex flag on the install command.
var installCodex bool

// codexServerName is the name lite-sandbox is registered under in Codex's
// config.toml ([mcp_servers.<codexServerName>]). Codex namespaces MCP tools by
// this server name.
const codexServerName = "lite-sandbox"

// codexDirective is appended to ~/.codex/AGENTS.md so Codex prefers the
// sandboxed bash tool for shell commands (Codex has no Read tool — it reads by
// shelling out — so routing the shell through the sandbox is what governs reads).
const codexDirective = "Prefer the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands. It runs commands through lite-sandbox's AST validation and filesystem path " +
	"boundaries, which the built-in shell bypasses. Use it instead of the built-in shell whenever possible."

// Codex hooks are configured in config.toml as a TOML array of tables
// ([[hooks.PreToolUse]]), which is awkward to update in place. Instead we own a
// single marker-delimited block appended to the file: reconciling means removing
// the old block and appending a fresh one, leaving all other content untouched.
const (
	codexHookBlockStart = "# >>> lite-sandbox hook (managed by `lite-sandbox install --codex`) — do not edit inside >>>"
	codexHookBlockEnd   = "# <<< lite-sandbox hook (managed by `lite-sandbox install --codex`) <<<"
)

// codexHome returns Codex's configuration directory: $CODEX_HOME when set,
// otherwise ~/.codex. This mirrors how Codex itself resolves its home.
func codexHome() (string, error) {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".codex"), nil
}

// runInstallCodex configures OpenAI Codex CLI to use lite-sandbox. Codex's hook
// protocol matches Claude Code's (same PreToolUse event, stdin payload, and
// permissionDecision output), so the same `lite-sandbox hook` binary and the
// same config file (readable/writable paths) govern both agents. The install
// modes mirror the Claude ones:
//
//   - default: register the MCP server + AGENTS.md directive, and a PreToolUse
//     hook that redirects the built-in shell to the sandboxed MCP tool. (Codex
//     has no permission-deny, so the hook — not a deny rule — is what blocks the
//     built-in shell.)
//   - --with-tool-hook: additionally confine reads/writes to the sandbox paths
//     (Read/Edit/Write/Glob/Grep plus Codex's apply_patch).
//   - --bash-ast-hook-mode: no MCP server; AST-validate the built-in shell in
//     place, allowing it when it passes.
func runInstallCodex(binPath string) error {
	codexDir, err := codexHome()
	if err != nil {
		return err
	}
	if _, err := os.Stat(codexDir); os.IsNotExist(err) {
		return fmt.Errorf("%s not found — install Codex CLI first (or set CODEX_HOME)", codexDir)
	} else if err != nil {
		return fmt.Errorf("failed to access %s: %w", codexDir, err)
	}

	configTomlPath := filepath.Join(codexDir, "config.toml")

	// Resolve the install mode from the (composable) flags, mirroring the Claude
	// install: validateBash AST-checks the shell in place, governFS confines the
	// filesystem tools, configMCP registers the MCP server + directive.
	validateBash := installBashASTHookMode
	governFS := installWithToolHook
	configMCP := !installBashASTHookMode

	// 1. MCP server + AGENTS.md directive. Both are skipped in
	// --bash-ast-hook-mode, which routes nothing to the MCP tool, so the
	// directive would have nothing to point at.
	if configMCP {
		if err := configureCodexMCPServer(configTomlPath, binPath); err != nil {
			return fmt.Errorf("failed to configure Codex MCP server: %w", err)
		}
		fmt.Printf("✓ Added MCP server to %s\n", configTomlPath)

		if err := configureCodexAGENTSMD(codexDir); err != nil {
			return fmt.Errorf("failed to configure AGENTS.md: %w", err)
		}
		fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(codexDir, "AGENTS.md"))
	}

	// 3. PreToolUse hook. Unlike Claude, Codex always needs a hook (there is no
	// permission-deny fallback), so one is registered in every mode.
	hookCommand := binPath + " hook"
	if validateBash {
		hookCommand = binPath + " hook --validate-bash"
	}
	matcher := bashValidateMatcher
	if governFS {
		matcher = hookToolMatcher
	}
	if err := reconcileCodexHook(configTomlPath, binPath, hookCommand, matcher); err != nil {
		return fmt.Errorf("failed to configure Codex hook: %w", err)
	}
	switch {
	case governFS && validateBash:
		fmt.Printf("✓ Registered PreToolUse hook to AST-check the built-in shell (runs unsandboxed) and confine reads/writes to sandbox paths in %s\n", configTomlPath)
	case governFS:
		fmt.Printf("✓ Registered PreToolUse hook to redirect the built-in shell and confine reads/writes to sandbox paths in %s\n", configTomlPath)
	case validateBash:
		fmt.Printf("✓ Registered PreToolUse hook to AST-check the built-in shell (runs unsandboxed) in %s\n", configTomlPath)
	default:
		fmt.Printf("✓ Registered PreToolUse hook to redirect the built-in shell to the sandboxed MCP tool in %s\n", configTomlPath)
	}

	fmt.Println("\n✓ Codex installation complete!")
	if installBashASTHookMode {
		fmt.Println("(--bash-ast-hook-mode: MCP server not configured)")
	}
	fmt.Println("\nCodex hooks are enabled by default; if you have set [features] hooks = false in")
	fmt.Println("config.toml, re-enable it or the hook will not run. Restart Codex to apply changes.")
	if !governFS {
		fmt.Println("\nTip: add --with-tool-hook to also confine reads/writes (including apply_patch)")
		fmt.Println("to the sandbox's paths — the same config that governs Claude Code.")
	}
	return nil
}

// configureCodexMCPServer registers (or updates) the lite-sandbox MCP server in
// Codex's config.toml. The file is edited as text rather than parsed so the
// user's existing tables, ordering, and comments are preserved — only the
// [mcp_servers.lite-sandbox] table (and any of its sub-tables) is rewritten. The
// operation is idempotent: re-running replaces our table in place instead of
// appending a duplicate.
func configureCodexMCPServer(configTomlPath, binPath string) error {
	header := "[mcp_servers." + codexServerName + "]"
	block := header + "\n" +
		"command = " + tomlString(binPath) + "\n" +
		`args = ["serve-mcp"]` + "\n"

	data, err := os.ReadFile(configTomlPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// New file: write just our table.
		return os.WriteFile(configTomlPath, []byte(block), 0644)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Locate an existing [mcp_servers.lite-sandbox] table header.
	start := -1
	for i, ln := range lines {
		if strings.TrimSpace(ln) == header {
			start = i
			break
		}
	}

	if start == -1 {
		return os.WriteFile(configTomlPath, []byte(appendTOMLBlock(content, block)), 0644)
	}

	// Present: replace only our contiguous table body in place. Our table is a
	// run of key=value lines, so it ends at the first line that isn't part of it:
	// a blank line, a comment (which includes our managed hook block's marker),
	// or any table header. Stopping there — rather than scanning to the next
	// top-level header — preserves blank lines, comments, and any user-authored
	// [mcp_servers.lite-sandbox.*] sub-table that follows.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "[") {
			end = i
			break
		}
	}

	var b strings.Builder
	for _, ln := range lines[:start] {
		b.WriteString(ln)
		b.WriteString("\n")
	}
	b.WriteString(block) // block already ends with "\n"
	b.WriteString(strings.Join(lines[end:], "\n"))
	return os.WriteFile(configTomlPath, []byte(b.String()), 0644)
}

// reconcileCodexHook makes the managed PreToolUse hook block in config.toml
// match the requested mode: it removes any prior lite-sandbox hook block, then
// appends a fresh one registering `command` under `matcher`. Editing a single
// marker-delimited block keeps the operation idempotent and leaves the rest of
// the file (including the MCP table and user content) untouched.
func reconcileCodexHook(configTomlPath, binPath, command, matcher string) error {
	data, err := os.ReadFile(configTomlPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		data = nil
	}
	content := stripCodexHookBlock(string(data))

	block := codexHookBlockStart + "\n" +
		"[[hooks.PreToolUse]]\n" +
		"matcher = " + tomlString(matcher) + "\n\n" +
		"[[hooks.PreToolUse.hooks]]\n" +
		`type = "command"` + "\n" +
		"command = " + tomlString(command) + "\n" +
		codexHookBlockEnd + "\n"

	return os.WriteFile(configTomlPath, []byte(appendTOMLBlock(content, block)), 0644)
}

// stripCodexHookBlock removes every managed hook block (markers inclusive) from
// content, so re-running (or switching modes) converges to a single block after
// the fresh one is appended. Content without a block is returned unchanged.
//
// If a start marker has no matching end marker (a user hand-deleted the end
// marker), only the start-marker line is removed rather than everything to EOF,
// so user content below an orphaned marker is never destroyed.
func stripCodexHookBlock(content string) string {
	for {
		start := strings.Index(content, codexHookBlockStart)
		if start == -1 {
			return content
		}
		// Expand the removal to the start of the marker's own line.
		lineStart := strings.LastIndex(content[:start], "\n") + 1

		var cut int
		if rel := strings.Index(content[start:], codexHookBlockEnd); rel != -1 {
			// Remove through the end of the end-marker's line.
			endMarker := start + rel + len(codexHookBlockEnd)
			cut = lineEnd(content, endMarker)
		} else {
			// Malformed (no end marker): remove only the start-marker line.
			cut = lineEnd(content, start)
		}
		content = content[:lineStart] + content[cut:]
	}
}

// lineEnd returns the index just past the newline terminating the line that
// contains idx, or len(s) if that line is the last (unterminated) one.
func lineEnd(s string, idx int) int {
	if nl := strings.IndexByte(s[idx:], '\n'); nl != -1 {
		return idx + nl + 1
	}
	return len(s)
}

// appendTOMLBlock appends block (which ends in a newline) to content, ensuring
// exactly one blank line separates it from any existing content.
func appendTOMLBlock(content, block string) string {
	if content == "" {
		return block
	}
	return strings.TrimRight(content, "\n") + "\n\n" + block
}

// tomlString renders s as a TOML basic string, escaping backslashes and quotes.
func tomlString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// configureCodexAGENTSMD appends the usage directive to ~/.codex/AGENTS.md,
// creating the file if needed. Idempotent; existing content is preserved.
func configureCodexAGENTSMD(codexDir string) error {
	return appendDirectiveOnce(filepath.Join(codexDir, "AGENTS.md"), codexDirective)
}
