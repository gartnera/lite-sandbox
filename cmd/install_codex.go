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
// sandboxed bash tool. Codex has no per-tool deny or PreToolUse hook, so unlike
// the Claude Code install this cannot block the built-in shell — the directive
// is advisory.
const codexDirective = "Prefer the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands. It runs commands through lite-sandbox's AST validation and filesystem path " +
	"boundaries, which the built-in shell bypasses. Use it instead of the built-in shell whenever possible."

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

// runInstallCodex configures OpenAI Codex CLI to use lite-sandbox by:
//  1. Registering the MCP server in ~/.codex/config.toml
//  2. Adding a usage directive to ~/.codex/AGENTS.md
//
// Unlike the Claude Code install there is no permission deny or PreToolUse hook
// to install — Codex exposes no equivalent — so the sandbox cannot block Codex's
// built-in shell; the AGENTS.md directive steers Codex to the sandboxed tool.
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
	if err := configureCodexMCPServer(configTomlPath, binPath); err != nil {
		return fmt.Errorf("failed to configure Codex MCP server: %w", err)
	}
	fmt.Printf("✓ Added MCP server to %s\n", configTomlPath)

	agentsMDPath := filepath.Join(codexDir, "AGENTS.md")
	if err := configureCodexAGENTSMD(codexDir); err != nil {
		return fmt.Errorf("failed to configure AGENTS.md: %w", err)
	}
	fmt.Printf("✓ Added usage directive to %s\n", agentsMDPath)

	fmt.Println("\n✓ Codex installation complete!")
	fmt.Println("\nNote: Codex has no per-tool deny or PreToolUse hook, so lite-sandbox cannot")
	fmt.Println("block Codex's built-in shell the way it can with Claude Code. The AGENTS.md")
	fmt.Println("directive asks Codex to prefer the sandboxed bash tool; enforcement is advisory.")
	fmt.Println("\nRestart Codex for the changes to take effect.")
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
		// Not present: append our table, separated from existing content by a
		// blank line.
		sep := ""
		switch {
		case len(content) == 0:
			sep = ""
		case !strings.HasSuffix(content, "\n"):
			sep = "\n\n"
		case !strings.HasSuffix(content, "\n\n"):
			sep = "\n"
		}
		return os.WriteFile(configTomlPath, []byte(content+sep+block), 0644)
	}

	// Present: replace the table (and any [mcp_servers.lite-sandbox.*] sub-tables)
	// in place. The table ends at the next table header that isn't one of ours.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "[") && !isCodexSubTable(t) {
			end = i
			break
		}
	}
	// Keep any blank separator lines that precede the next table with that table.
	for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
		end--
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

// isCodexSubTable reports whether a trimmed line is a sub-table header of our
// server table (e.g. "[mcp_servers.lite-sandbox.env]"), which is considered part
// of the block we own and rewrite.
func isCodexSubTable(trimmed string) bool {
	return strings.HasPrefix(trimmed, "[mcp_servers."+codexServerName+".")
}

// tomlString renders s as a TOML basic string, escaping backslashes and quotes.
func tomlString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// configureCodexAGENTSMD appends the usage directive to ~/.codex/AGENTS.md,
// creating the file if needed. It is idempotent: the directive is added only
// when not already present, and existing content is preserved.
func configureCodexAGENTSMD(codexDir string) error {
	agentsMDPath := filepath.Join(codexDir, "AGENTS.md")

	data, err := os.ReadFile(agentsMDPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, create it with the directive.
		return os.WriteFile(agentsMDPath, []byte(codexDirective+"\n"), 0644)
	}

	content := string(data)
	if strings.Contains(content, codexDirective) {
		// Directive already present, nothing to do.
		return nil
	}

	newContent := content
	if len(newContent) > 0 && newContent[len(newContent)-1] != '\n' {
		newContent += "\n"
	}
	newContent += "\n" + codexDirective + "\n"

	return os.WriteFile(agentsMDPath, []byte(newContent), 0644)
}
