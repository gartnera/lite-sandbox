package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Automatically configure Claude Code to use lite-sandbox",
	Long: `Automatically configures Claude Code by:
1. Adding the MCP server to ~/.claude.json (user-scoped)
2. Adding auto-allow permission for mcp__lite-sandbox__bash and denying the built-in Bash tool in ~/.claude/settings.json
3. Adding usage directive to ~/.claude/CLAUDE.md`,
	RunE: runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	// Get the path to the current binary
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	claudeDir := filepath.Join(homeDir, ".claude")
	if _, err := os.Stat(claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("~/.claude directory not found — install Claude Code first")
	} else if err != nil {
		return fmt.Errorf("failed to access ~/.claude directory: %w", err)
	}

	// 1. Configure MCP server in ~/.claude.json (user-scoped)
	claudeJsonPath := filepath.Join(homeDir, ".claude.json")
	if err := configureMCPServer(claudeJsonPath, binPath); err != nil {
		return fmt.Errorf("failed to configure MCP server: %w", err)
	}
	fmt.Println("✓ Added MCP server to ~/.claude.json")

	// 2. Configure permissions (allow the sandbox tool, deny the built-in Bash tool)
	if err := configurePermissions(claudeDir); err != nil {
		return fmt.Errorf("failed to configure permissions: %w", err)
	}
	fmt.Println("✓ Allowed mcp__lite-sandbox__bash and denied built-in Bash in ~/.claude/settings.json")

	// 3. Configure CLAUDE.md
	if err := configureCLAUDEMD(claudeDir); err != nil {
		return fmt.Errorf("failed to configure CLAUDE.md: %w", err)
	}
	fmt.Println("✓ Added usage directive to ~/.claude/CLAUDE.md")

	fmt.Println("\n✓ Installation complete!")
	fmt.Println("\nRestart Claude Code for the changes to take effect.")
	return nil
}

type mcpServerConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func configureMCPServer(claudeJsonPath, binPath string) error {
	// Read existing ~/.claude.json (preserving all other keys)
	var cfg map[string]json.RawMessage
	data, err := os.ReadFile(claudeJsonPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, start with empty config
		cfg = make(map[string]json.RawMessage)
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("failed to parse existing ~/.claude.json: %w", err)
		}
	}

	// Parse existing mcpServers if present
	mcpServers := make(map[string]mcpServerConfig)
	if raw, ok := cfg["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &mcpServers); err != nil {
			return fmt.Errorf("failed to parse mcpServers in ~/.claude.json: %w", err)
		}
	}

	// Add or update the lite-sandbox server
	mcpServers["lite-sandbox"] = mcpServerConfig{
		Command: binPath,
		Args:    []string{"serve-mcp"},
	}

	// Marshal mcpServers back into the config
	mcpServersRaw, err := json.Marshal(mcpServers)
	if err != nil {
		return err
	}
	cfg["mcpServers"] = mcpServersRaw

	// Write back
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(claudeJsonPath, data, 0644)
}

type permissionsConfig struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// readSettingsFile reads and parses a settings.json file into a generic map,
// preserving all keys. Returns an empty map if the file doesn't exist.
func readSettingsFile(settingsPath string) (map[string]json.RawMessage, error) {
	cfg := make(map[string]json.RawMessage)
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse existing settings.json: %w", err)
	}
	return cfg, nil
}

// writeSettingsFile writes a generic map back to settings.json.
func writeSettingsFile(settingsPath string, cfg map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath, data, 0644)
}

func configurePermissions(claudeDir string) error {
	settingsPath := filepath.Join(claudeDir, "settings.json")

	cfg, err := readSettingsFile(settingsPath)
	if err != nil {
		return err
	}

	// Parse existing permissions if present
	var perms permissionsConfig
	if raw, ok := cfg["permissions"]; ok {
		if err := json.Unmarshal(raw, &perms); err != nil {
			return fmt.Errorf("failed to parse permissions in settings.json: %w", err)
		}
	}

	// Auto-allow the sandboxed bash tool
	allowPermission := "mcp__lite-sandbox__bash"
	if !slices.Contains(perms.Allow, allowPermission) {
		perms.Allow = append(perms.Allow, allowPermission)
	}

	// Ban the built-in Bash tool outright so Claude must use the sandbox
	denyPermission := "Bash"
	if !slices.Contains(perms.Deny, denyPermission) {
		perms.Deny = append(perms.Deny, denyPermission)
	}

	// Marshal permissions back into the config
	permsRaw, err := json.Marshal(perms)
	if err != nil {
		return err
	}
	cfg["permissions"] = permsRaw

	return writeSettingsFile(settingsPath, cfg)
}

func configureCLAUDEMD(claudeDir string) error {
	claudeMDPath := filepath.Join(claudeDir, "CLAUDE.md")

	directive := `ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.`

	// Check if the file exists and already contains the directive
	data, err := os.ReadFile(claudeMDPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, create it with the directive
		return os.WriteFile(claudeMDPath, []byte(directive+"\n"), 0644)
	}

	content := string(data)
	if strings.Contains(content, directive) {
		// Directive already exists, no need to add it again
		return nil
	}

	// Append the directive
	newContent := content
	if len(newContent) > 0 && newContent[len(newContent)-1] != '\n' {
		newContent += "\n"
	}
	newContent += "\n" + directive + "\n"

	return os.WriteFile(claudeMDPath, []byte(newContent), 0644)
}
