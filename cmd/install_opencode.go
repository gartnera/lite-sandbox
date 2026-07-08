package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// opencodeDirective is appended to the global AGENTS.md so opencode prefers the
// sandboxed bash tool. opencode namespaces MCP tools as <server>_<tool>, so the
// sandbox's shell surfaces as lite-sandbox_bash.
const opencodeDirective = "ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands. The built-in bash tool is denied by the permission config and will not run. The sandboxed " +
	"tool runs commands through lite-sandbox's AST validation and filesystem path boundaries."

// opencodeConfigDir returns opencode's global configuration directory:
// $XDG_CONFIG_HOME/opencode when set, otherwise ~/.config/opencode. opencode
// uses the XDG layout on every platform (including macOS).
func opencodeConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "opencode"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".config", "opencode"), nil
}

// runInstallOpencode configures opencode to use lite-sandbox. Unlike Claude
// Code and Codex, opencode has no PreToolUse hook protocol (its plugins are
// JavaScript), so there is a single install mode:
//
//   - register the MCP server under mcp.lite-sandbox in the global
//     opencode.json;
//   - deny the built-in bash tool via permission.bash = "deny" (the analogue of
//     the Claude installer's Bash permission deny) and auto-allow the sandbox's
//     tools via the lite-sandbox* permission pattern;
//   - append a usage directive to the global AGENTS.md.
//
// --with-tool-hook therefore has nothing to attach to (a note is printed), and
// --bash-ast-hook-mode — which exists to keep using the built-in shell behind a
// validating hook — skips opencode entirely.
func runInstallOpencode(binPath string) error {
	if installBashASTHookMode {
		fmt.Println("⚠ opencode has no PreToolUse hook protocol, so --bash-ast-hook-mode cannot govern its built-in bash tool — skipping opencode.")
		fmt.Println("  Run `lite-sandbox install opencode` (without the flag) for the standard opencode setup.")
		return nil
	}

	opencodeDir, err := opencodeConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opencodeDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", opencodeDir, err)
	}

	configPath := filepath.Join(opencodeDir, "opencode.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// A JSONC global config can't be edited safely with encoding/json (its
		// comments would be rejected on read and lost on write), and writing a
		// sibling opencode.json next to it would be confusing. Bail with pointers.
		jsoncPath := filepath.Join(opencodeDir, "opencode.jsonc")
		if _, err := os.Stat(jsoncPath); err == nil {
			return fmt.Errorf("found %s — lite-sandbox can only edit plain JSON; add the mcp/permission entries manually (see docs/installation.md#opencode)", jsoncPath)
		}
	}

	if err := configureOpencodeConfig(configPath, binPath); err != nil {
		return fmt.Errorf("failed to configure opencode: %w", err)
	}
	fmt.Printf("✓ Added MCP server, denied the built-in bash tool, and auto-allowed the sandbox tools in %s\n", configPath)

	if err := configureOpencodeAGENTSMD(opencodeDir); err != nil {
		return fmt.Errorf("failed to configure AGENTS.md: %w", err)
	}
	fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(opencodeDir, "AGENTS.md"))

	fmt.Println("\n✓ opencode installation complete!")
	if installWithToolHook {
		fmt.Println("(--with-tool-hook: opencode has no PreToolUse hook protocol, so the flag does not apply to it;")
		fmt.Println(" use opencode's own permission config — e.g. permission.edit / permission.external_directory — to confine its file tools)")
	}
	fmt.Println("Restart opencode for the changes to take effect.")
	return nil
}

// opencodeMCPLocal is the McpLocalConfig shape from opencode's config schema
// (https://opencode.ai/config.json).
type opencodeMCPLocal struct {
	Type    string   `json:"type"`
	Command []string `json:"command"`
	Enabled bool     `json:"enabled"`
}

// configureOpencodeConfig registers the lite-sandbox MCP server and the bash
// permission rules in opencode's global opencode.json, creating the file if
// needed. All other keys — and unknown fields inside mcp/permission — are
// preserved by round-tripping them as raw JSON. Idempotent: re-running rewrites
// the same entries in place.
func configureOpencodeConfig(configPath, binPath string) error {
	cfg := make(map[string]json.RawMessage)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse %s (note lite-sandbox can only edit plain JSON, not JSONC comments): %w", configPath, err)
	}

	if _, ok := cfg["$schema"]; !ok {
		cfg["$schema"] = json.RawMessage(`"https://opencode.ai/config.json"`)
	}

	// mcp.lite-sandbox — a local server launched via `lite-sandbox serve-mcp`.
	mcp := make(map[string]json.RawMessage)
	if raw, ok := cfg["mcp"]; ok {
		if err := json.Unmarshal(raw, &mcp); err != nil {
			return fmt.Errorf("failed to parse mcp in %s: %w", configPath, err)
		}
	}
	serverRaw, err := json.Marshal(opencodeMCPLocal{
		Type:    "local",
		Command: []string{binPath, "serve-mcp"},
		Enabled: true,
	})
	if err != nil {
		return err
	}
	mcp["lite-sandbox"] = serverRaw
	mcpRaw, err := json.Marshal(mcp)
	if err != nil {
		return err
	}
	cfg["mcp"] = mcpRaw

	// permission.bash = "deny" blocks the built-in shell so opencode must use
	// the sandbox (any existing bash rule object is intentionally replaced —
	// granular allows would defeat the deny). lite-sandbox* auto-allows the
	// sandbox's own tools (lite-sandbox_bash, lite-sandbox_bash_output, ...) so
	// they never prompt, mirroring the Claude installer's allow entries.
	perm := make(map[string]json.RawMessage)
	if raw, ok := cfg["permission"]; ok {
		if err := json.Unmarshal(raw, &perm); err != nil {
			// permission may also be a bare action string ("allow"/"ask"/"deny")
			// applying to everything; preserve that as the catch-all "*" rule.
			var action string
			if err2 := json.Unmarshal(raw, &action); err2 != nil {
				return fmt.Errorf("failed to parse permission in %s: %w", configPath, err)
			}
			perm["*"] = raw
		}
	}
	perm["bash"] = json.RawMessage(`"deny"`)
	perm["lite-sandbox*"] = json.RawMessage(`"allow"`)
	permRaw, err := json.Marshal(perm)
	if err != nil {
		return err
	}
	cfg["permission"] = permRaw

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, append(out, '\n'), 0644)
}

// configureOpencodeAGENTSMD appends the usage directive to the global
// AGENTS.md, creating the file if needed. Idempotent; existing content is
// preserved.
func configureOpencodeAGENTSMD(opencodeDir string) error {
	return appendDirectiveOnce(filepath.Join(opencodeDir, "AGENTS.md"), opencodeDirective)
}
