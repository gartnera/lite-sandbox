package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// grokServerID is the id lite-sandbox is registered under in Grok CLI's MCP
// server list (~/.grok/user-settings.json, mcp.servers). Grok namespaces MCP
// tools as mcp_<server-id>__<tool>, so the sandbox's shell surfaces as
// mcp_lite-sandbox__bash.
const grokServerID = "lite-sandbox"

// grokMCPBashTool is the name Grok CLI exposes the sandboxed bash tool under.
const grokMCPBashTool = "mcp_" + grokServerID + "__bash"

// grokDirective is appended to the global ~/.grok/AGENTS.md so Grok prefers
// the sandboxed bash tool.
const grokDirective = "ALWAYS use the `" + grokMCPBashTool + "` tool for running shell commands. " +
	"The built-in bash tool is blocked by a PreToolUse hook and will not run. The sandboxed tool " +
	"runs commands through lite-sandbox's AST validation and filesystem path boundaries."

// Grok hook matchers are matched by exact string comparison (no regex), so the
// hook is registered under one matcher group per governed tool rather than a
// single alternation like Claude Code's.
var (
	// grokBashMatchers governs only the built-in shell.
	grokBashMatchers = []string{"bash"}
	// grokToolMatchers additionally governs Grok's filesystem tools
	// (--with-tool-hook): reads via read_file/grep, writes via
	// write_file/edit_file.
	grokToolMatchers = []string{"bash", "read_file", "write_file", "edit_file", "grep"}
)

// grokConfigDir returns Grok CLI's configuration directory, ~/.grok (Grok has
// no env override for it).
func grokConfigDir() (string, error) {
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
	dir, err := grokConfigDir()
	return err == nil && dirExists(dir)
}

// runInstallGrok configures Grok CLI (github.com/superagent-ai/grok-cli) to
// use lite-sandbox. Grok's PreToolUse event carries the same stdin payload as
// Claude Code's (hook_event_name, tool_name, tool_input, cwd), but its tool
// names and decision protocol differ — hence the hook runs with `--format
// grok`, which understands Grok's tool names (bash, read_file, ...) and
// signals a deny the way Grok expects (reason on stderr, exit code 2). The
// install modes mirror the Codex ones:
//
//   - default: register the MCP server (mcp.servers in
//     ~/.grok/user-settings.json) + AGENTS.md directive, and a PreToolUse hook
//     that redirects the built-in bash tool to the sandboxed MCP tool. (Grok
//     has no permission-deny config, so the hook — not a deny rule — is what
//     blocks the built-in shell.)
//   - --with-tool-hook: additionally confine reads/writes to the sandbox paths
//     (read_file/grep and write_file/edit_file).
//   - --bash-ast-hook-mode: no MCP server; AST-validate the built-in shell in
//     place, allowing it when it passes.
//
// Hooks live only in the user-level settings (Grok intentionally ignores
// project-level hook definitions), which is also where the MCP servers live,
// so everything edits ~/.grok/user-settings.json.
func runInstallGrok(binPath string) error {
	grokDir, err := grokConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(grokDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", grokDir, err)
	}

	userSettingsPath := filepath.Join(grokDir, "user-settings.json")

	// Resolve the install mode from the (composable) flags, mirroring the
	// Claude/Codex installs.
	validateBash := installBashASTHookMode
	governFS := installWithToolHook
	configMCP := !installBashASTHookMode

	// 1. MCP server + AGENTS.md directive. Both are skipped in
	// --bash-ast-hook-mode, which routes nothing to the MCP tool.
	if configMCP {
		if err := configureGrokMCPServer(userSettingsPath, binPath); err != nil {
			return fmt.Errorf("failed to configure Grok MCP server: %w", err)
		}
		fmt.Printf("✓ Added MCP server to %s\n", userSettingsPath)

		if err := configureGrokAGENTSMD(grokDir); err != nil {
			return fmt.Errorf("failed to configure AGENTS.md: %w", err)
		}
		fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(grokDir, "AGENTS.md"))
	}

	// 2. PreToolUse hook. Like Codex, Grok always needs a hook (there is no
	// permission-deny fallback), so one is registered in every mode.
	hookCommand := binPath + " hook --format grok"
	if validateBash {
		hookCommand += " --validate-bash"
	}
	matchers := grokBashMatchers
	if governFS {
		matchers = grokToolMatchers
	}
	if err := reconcilePreToolUseHook(userSettingsPath, binPath, hookCommand, matchers...); err != nil {
		return fmt.Errorf("failed to configure Grok hook: %w", err)
	}
	switch {
	case governFS && validateBash:
		fmt.Printf("✓ Registered PreToolUse hooks to AST-check the built-in bash tool (runs unsandboxed) and confine reads/writes to sandbox paths in %s\n", userSettingsPath)
	case governFS:
		fmt.Printf("✓ Registered PreToolUse hooks to redirect the built-in bash tool and confine reads/writes to sandbox paths in %s\n", userSettingsPath)
	case validateBash:
		fmt.Printf("✓ Registered PreToolUse hook to AST-check the built-in bash tool (runs unsandboxed) in %s\n", userSettingsPath)
	default:
		fmt.Printf("✓ Registered PreToolUse hook to redirect the built-in bash tool to the sandboxed MCP tool in %s\n", userSettingsPath)
	}

	fmt.Println("\n✓ Grok CLI installation complete!")
	if installBashASTHookMode {
		fmt.Println("(--bash-ast-hook-mode: MCP server not configured)")
	}
	fmt.Println("Restart Grok for the changes to take effect.")
	return nil
}

// grokMCPServer is the McpServerConfig shape from Grok CLI's user settings
// (mcp.servers entries in ~/.grok/user-settings.json).
type grokMCPServer struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Enabled   bool     `json:"enabled"`
	Transport string   `json:"transport"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
}

// configureGrokMCPServer registers the lite-sandbox MCP server in Grok's
// user-settings.json under mcp.servers, creating the file if needed. Grok
// stores servers as an array, so the entry with id "lite-sandbox" is replaced
// in place (or appended). All other keys — top-level settings, other servers,
// and unknown fields inside mcp — are preserved by round-tripping them as raw
// JSON. Idempotent: re-running rewrites our entry.
func configureGrokMCPServer(settingsPath, binPath string) error {
	cfg, err := readSettingsFile(settingsPath)
	if err != nil {
		return err
	}

	mcp := make(map[string]json.RawMessage)
	if raw, ok := cfg["mcp"]; ok {
		if err := json.Unmarshal(raw, &mcp); err != nil {
			return fmt.Errorf("failed to parse mcp in %s: %w", settingsPath, err)
		}
	}

	var servers []json.RawMessage
	if raw, ok := mcp["servers"]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return fmt.Errorf("failed to parse mcp.servers in %s: %w", settingsPath, err)
		}
	}

	entryRaw, err := json.Marshal(grokMCPServer{
		ID:        grokServerID,
		Label:     grokServerID,
		Enabled:   true,
		Transport: "stdio",
		Command:   binPath,
		Args:      []string{"serve-mcp"},
	})
	if err != nil {
		return err
	}

	// Replace the existing lite-sandbox entry in place, else append.
	replaced := false
	for i, raw := range servers {
		var probe struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if probe.ID == grokServerID {
			servers[i] = entryRaw
			replaced = true
			break
		}
	}
	if !replaced {
		servers = append(servers, entryRaw)
	}

	serversRaw, err := json.Marshal(servers)
	if err != nil {
		return err
	}
	mcp["servers"] = serversRaw
	mcpRaw, err := json.Marshal(mcp)
	if err != nil {
		return err
	}
	cfg["mcp"] = mcpRaw

	return writeSettingsFile(settingsPath, cfg)
}

// configureGrokAGENTSMD appends the usage directive to the global
// ~/.grok/AGENTS.md, creating the file if needed. Idempotent; existing content
// is preserved.
func configureGrokAGENTSMD(grokDir string) error {
	return appendDirectiveOnce(filepath.Join(grokDir, "AGENTS.md"), grokDirective)
}
