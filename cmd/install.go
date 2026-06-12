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

var installWithToolHook bool
var installBashASTHookMode bool

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Automatically configure Claude Code to use lite-sandbox",
	Long: `Automatically configures Claude Code by:
1. Adding the MCP server to ~/.claude.json (user-scoped)
2. Adding auto-allow permission for mcp__lite-sandbox__bash and denying the built-in Bash tool in ~/.claude/settings.json
3. Adding usage directive to ~/.claude/CLAUDE.md

With --with-tool-hook, registers a PreToolUse hook that governs the built-in
tools instead of the blunt Bash deny: it blocks the built-in Bash tool with a
message redirecting to mcp__lite-sandbox__bash, and denies Read outside the
sandbox's readable paths and Write/Edit/NotebookEdit outside its writable paths,
matching the boundaries the bash tool enforces.

With --bash-ast-hook-mode, the MCP server is NOT configured. Instead, the PreToolUse
hook statically parses each built-in Bash command's AST and checks it against the
sandbox's whitelist and path boundaries, allowing it when it passes and denying it
otherwise. Note Bash itself still runs UNSANDBOXED — there is no runtime
enforcement, only this up-front static check — so it is a weaker guarantee than
routing execution through the MCP tool. Combine it with --with-tool-hook to also
confine the built-in Read/Write/Edit tools to the sandbox's paths; on its own it
governs only Bash.`,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().BoolVar(&installWithToolHook, "with-tool-hook", false,
		"register a PreToolUse hook that redirects built-in Bash to the MCP tool and confines built-in Read/Write/Edit to the sandbox's readable/writable paths")
	installCmd.Flags().BoolVar(&installBashASTHookMode, "bash-ast-hook-mode", false,
		"statically AST-check the built-in Bash tool in the hook instead of redirecting it — Bash still runs unsandboxed (no runtime enforcement), no MCP server, no Bash deny; combine with --with-tool-hook to also confine Read/Write/Edit")
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

	claudeJsonPath := filepath.Join(homeDir, ".claude.json")

	// Resolve the install mode from the (composable) flags:
	//   wantHook    — register a PreToolUse hook at all.
	//   validateBash — the hook validates Bash's AST and allows it on pass,
	//                  rather than redirecting it to the MCP tool.
	//   governFS    — the hook also confines Read/Write/Edit/Glob/Grep paths,
	//                  so it matches those tools (full matcher).
	//   configMCP   — configure the MCP server (and its allow + CLAUDE.md
	//                  directive). Skipped when Bash is validated in place,
	//                  since nothing redirects to the MCP tool then.
	validateBash := installBashASTHookMode
	governFS := installWithToolHook
	wantHook := installWithToolHook || installBashASTHookMode
	configMCP := !installBashASTHookMode

	// 1. Configure MCP server in ~/.claude.json (user-scoped)
	if configMCP {
		if err := configureMCPServer(claudeJsonPath, binPath); err != nil {
			return fmt.Errorf("failed to configure MCP server: %w", err)
		}
		fmt.Println("✓ Added MCP server to ~/.claude.json")
	}

	// 2. Configure permissions. Allow the MCP tool only when it's configured.
	// Deny the built-in Bash tool only in the default mode; when a hook governs
	// Bash, a deny rule would override the hook's decision, so it's left off.
	denyBash := !wantHook
	if err := configurePermissions(claudeDir, configMCP, denyBash); err != nil {
		return fmt.Errorf("failed to configure permissions: %w", err)
	}
	switch {
	case denyBash:
		fmt.Println("✓ Allowed mcp__lite-sandbox__bash and denied built-in Bash in ~/.claude/settings.json")
	case configMCP:
		fmt.Println("✓ Allowed mcp__lite-sandbox__bash in ~/.claude/settings.json (built-in Bash governed by the tool hook)")
	default:
		fmt.Println("✓ Ensured built-in Bash is not denied in ~/.claude/settings.json (governed by the validating hook)")
	}

	// 3. Configure CLAUDE.md (only meaningful when the MCP tool exists for the
	// directive to point at).
	if configMCP {
		if err := configureCLAUDEMD(claudeDir); err != nil {
			return fmt.Errorf("failed to configure CLAUDE.md: %w", err)
		}
		fmt.Println("✓ Added usage directive to ~/.claude/CLAUDE.md")
	}

	// 4. Reconcile the built-in tool PreToolUse hook (register the right one for
	// the chosen mode, removing any stale lite-sandbox hook from a prior install).
	hookCommand := ""
	matcher := hookToolMatcher
	if wantHook {
		if validateBash {
			hookCommand = binPath + " hook --validate-bash"
		} else {
			hookCommand = binPath + " hook"
		}
		// On its own, --bash-ast-hook-mode governs only Bash; with --with-tool-hook
		// it also confines the filesystem tools, so it matches all of them.
		if !governFS {
			matcher = bashValidateMatcher
		}
	}
	if err := reconcilePreToolUseHook(claudeDir, binPath, hookCommand, matcher); err != nil {
		return fmt.Errorf("failed to configure tool hook: %w", err)
	}
	switch {
	case governFS && validateBash:
		fmt.Println("✓ Registered PreToolUse hook to AST-check built-in Bash (runs unsandboxed) and confine reads/writes to sandbox paths in ~/.claude/settings.json")
	case governFS:
		fmt.Println("✓ Registered PreToolUse hook to redirect built-in Bash and confine reads/writes to sandbox paths in ~/.claude/settings.json")
	case validateBash:
		fmt.Println("✓ Registered PreToolUse hook to AST-check built-in Bash (runs unsandboxed) in ~/.claude/settings.json")
	}

	fmt.Println("\n✓ Installation complete!")
	if installBashASTHookMode {
		fmt.Println("(--bash-ast-hook-mode: MCP server not configured)")
	}
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

// configurePermissions controls the sandboxed bash tool allow and the built-in
// Bash deny. allowMCP adds the mcp__lite-sandbox__bash auto-allow (skipped in
// --bash-ast-hook-mode, which doesn't configure the MCP server). denyBash
// hard-denies the built-in Bash tool via a permission rule so Claude must use
// the sandbox; when false (a hook governs Bash instead) any existing Bash deny
// is removed, since a permission deny takes precedence over the hook's
// allow/redirect decision and would suppress it.
func configurePermissions(claudeDir string, allowMCP, denyBash bool) error {
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
	if allowMCP && !slices.Contains(perms.Allow, allowPermission) {
		perms.Allow = append(perms.Allow, allowPermission)
	}

	const denyPermission = "Bash"
	if !denyBash {
		// Let the hook own the Bash block; a deny rule would suppress its
		// decision. Strip any Bash deny a prior install added.
		perms.Deny = slices.DeleteFunc(perms.Deny, func(p string) bool { return p == denyPermission })
	} else if !slices.Contains(perms.Deny, denyPermission) {
		// Ban the built-in Bash tool outright so Claude must use the sandbox.
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

// reconcilePreToolUseHook makes the registered lite-sandbox PreToolUse hook
// match the requested install mode. It first removes any stale lite-sandbox hook
// entry (so switching between modes — or back to no hook — doesn't leave a
// conflicting one behind), then registers `command` under `matcher` when command
// is non-empty. binPath identifies our hook entries to remove.
func reconcilePreToolUseHook(claudeDir, binPath, command, matcher string) error {
	if err := removeLiteSandboxHooks(claudeDir, binPath); err != nil {
		return err
	}
	if command == "" {
		return nil
	}
	return configurePreToolUseHook(claudeDir, command, matcher)
}

// removeLiteSandboxHooks strips any PreToolUse hook entry that invokes the
// lite-sandbox binary (command `<binPath> hook ...`), dropping matcher groups
// that become empty. Other hooks and settings are preserved. It is a no-op when
// no hooks are configured.
func removeLiteSandboxHooks(claudeDir, binPath string) error {
	settingsPath := filepath.Join(claudeDir, "settings.json")

	cfg, err := readSettingsFile(settingsPath)
	if err != nil {
		return err
	}
	raw, ok := cfg["hooks"]
	if !ok {
		return nil
	}
	var hooks map[string]any
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return fmt.Errorf("failed to parse hooks in settings.json: %w", err)
	}

	hookPrefix := binPath + " hook"
	isOurs := func(cmd string) bool {
		return cmd == hookPrefix || strings.HasPrefix(cmd, hookPrefix+" ")
	}

	pre := asSlice(hooks["PreToolUse"])
	var kept []any
	for _, rawGroup := range pre {
		group := asMap(rawGroup)
		var cmds []any
		for _, c := range asSlice(group["hooks"]) {
			if isOurs(asString(asMap(c)["command"])) {
				continue
			}
			cmds = append(cmds, c)
		}
		if len(cmds) == 0 {
			// Whole group was lite-sandbox's; drop it.
			continue
		}
		group["hooks"] = cmds
		kept = append(kept, group)
	}
	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
	}

	hooksRaw, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	cfg["hooks"] = hooksRaw

	return writeSettingsFile(settingsPath, cfg)
}

// configurePreToolUseHook registers (or updates) a PreToolUse hook entry in
// settings.json that invokes `command` for the given tool matcher. Existing
// settings and other hooks are preserved, and the operation is idempotent:
// re-running with the same command/matcher does not duplicate the entry. The
// hooks subtree is manipulated as untyped JSON so unrelated events
// (PostToolUse, etc.) and fields (timeouts) survive the round-trip.
func configurePreToolUseHook(claudeDir, command, matcher string) error {
	settingsPath := filepath.Join(claudeDir, "settings.json")

	cfg, err := readSettingsFile(settingsPath)
	if err != nil {
		return err
	}

	var hooks map[string]any
	if raw, ok := cfg["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return fmt.Errorf("failed to parse hooks in settings.json: %w", err)
		}
	}
	if hooks == nil {
		hooks = map[string]any{}
	}

	pre := asSlice(hooks["PreToolUse"])
	entry := map[string]any{"type": "command", "command": command}

	// Find an existing matcher group; update it in place if present.
	updated := false
	for i, raw := range pre {
		group := asMap(raw)
		if asString(group["matcher"]) != matcher {
			continue
		}
		cmds := asSlice(group["hooks"])
		// Replace any existing entry with the same command, else append.
		replaced := false
		for j, c := range cmds {
			if asString(asMap(c)["command"]) == command {
				cmds[j] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			cmds = append(cmds, entry)
		}
		group["hooks"] = cmds
		pre[i] = group
		updated = true
		break
	}
	if !updated {
		pre = append(pre, map[string]any{"matcher": matcher, "hooks": []any{entry}})
	}
	hooks["PreToolUse"] = pre

	hooksRaw, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	cfg["hooks"] = hooksRaw

	return writeSettingsFile(settingsPath, cfg)
}

// Helpers tolerant of the untyped map[string]any decoded from arbitrary JSON.

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
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
