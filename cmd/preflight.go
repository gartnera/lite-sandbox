package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gartnera/lite-sandbox/config"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

var preflightInstallFlag bool

var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Claude Code PreToolUse hook for redirecting Bash to lite-sandbox",
	Long: `When invoked as a hook (stdin is a pipe), reads Claude Code PreToolUse JSON
from stdin and denies Bash tool calls whose commands would pass sandbox validation,
redirecting Claude to use mcp__lite-sandbox__bash instead.

When invoked from a terminal (or with --install), installs the hook into
~/.claude/settings.json.`,
	RunE: runPreflight,
}

func init() {
	preflightCmd.Flags().BoolVar(&preflightInstallFlag, "install", false, "Install the preflight hook into ~/.claude/settings.json")
	rootCmd.AddCommand(preflightCmd)
}

// preflightHookInput is the JSON structure Claude Code sends to PreToolUse hooks.
type preflightHookInput struct {
	SessionID string `json:"session_id"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command                   string `json:"command"`
		DangerouslyDisableSandbox bool   `json:"dangerouslyDisableSandbox"`
	} `json:"tool_input"`
	CWD string `json:"cwd"`
}

// preflightHookOutput is the JSON deny response for Claude Code hooks.
type preflightHookOutput struct {
	HookSpecificOutput struct {
		HookEventName          string `json:"hookEventName"`
		PermissionDecision     string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func runPreflight(cmd *cobra.Command, args []string) error {
	// Determine mode: install if --install flag or if stdin is a terminal
	if preflightInstallFlag || term.IsTerminal(int(os.Stdin.Fd())) {
		return runPreflightInstall()
	}
	return runPreflightHook()
}

// runPreflightHook reads PreToolUse JSON from stdin and validates.
// Fail-open: any error results in silent exit 0 (allow Bash).
func runPreflightHook() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil // fail open
	}

	var input preflightHookInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil // fail open
	}

	// Only intercept Bash tool calls
	if input.ToolName != "Bash" {
		return nil
	}

	// Escalate to user approval if the LLM is explicitly bypassing the sandbox
	if input.ToolInput.DangerouslyDisableSandbox {
		output := preflightHookOutput{}
		output.HookSpecificOutput.HookEventName = "PreToolUse"
		output.HookSpecificOutput.PermissionDecision = "ask"
		output.HookSpecificOutput.PermissionDecisionReason = "This command is bypassing the lite-sandbox (dangerouslyDisableSandbox=true). Please confirm execution."
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	command := input.ToolInput.Command
	if command == "" {
		return nil // fail open
	}

	cwd := input.CWD
	if cwd == "" {
		return nil // fail open
	}

	// Create sandbox and load config
	sandbox := bash_sandboxed.NewSandbox()
	cfg, err := config.Load()
	if err == nil && cfg != nil {
		sandbox.UpdateConfig(cfg, cwd)
	}

	// Mirror serve.go's path construction so a command we'd accept here is
	// the same set a command serve.go would accept. Diverging here breaks
	// the redirect contract: preflight rejects → Claude falls back to the
	// unsandboxed Bash tool, even though the sandbox would have accepted it.
	readPaths := append([]string{cwd}, sandbox.RuntimeReadPaths()...)
	readPaths = append(readPaths, sandbox.ConfigReadPaths()...)
	writePaths := append([]string{cwd}, sandbox.ConfigWritePaths()...)

	// Validate against sandbox
	if err := sandbox.ValidateCommand(command, cwd, readPaths, writePaths); err != nil {
		return nil // command would fail in sandbox, allow Bash
	}

	// Command would pass sandbox validation — deny Bash and redirect
	output := preflightHookOutput{}
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.PermissionDecision = "deny"
	output.HookSpecificOutput.PermissionDecisionReason = "This command can run in the lite-sandbox. Use the mcp__lite-sandbox__bash tool instead of the built-in Bash tool."

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// runPreflightInstall installs the preflight hook into ~/.claude/settings.json.
func runPreflightInstall() error {
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

	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	if err := configurePreflightHook(settingsPath, binPath); err != nil {
		return fmt.Errorf("failed to configure preflight hook: %w", err)
	}

	fmt.Println("✓ Installed preflight hook into ~/.claude/settings.json")
	return nil
}

// hookEntry represents a single hook command entry.
type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// hookMatcher represents a hook matcher with its hooks.
type hookMatcher struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

// configurePreflightHook merges the preflight hook into settings.json,
// preserving all existing keys.
func configurePreflightHook(settingsPath string, binPath string) error {
	cfg, err := readSettingsFile(settingsPath)
	if err != nil {
		return err
	}

	// Parse existing hooks if present
	var hooks map[string][]hookMatcher
	if raw, ok := cfg["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return fmt.Errorf("failed to parse hooks in settings.json: %w", err)
		}
	}
	if hooks == nil {
		hooks = make(map[string][]hookMatcher)
	}

	hookCommand := binPath + " preflight"

	// Check if our hook already exists in PreToolUse
	preToolUseHooks := hooks["PreToolUse"]
	found := false
	for i, m := range preToolUseHooks {
		if m.Matcher == "Bash" {
			// Check if our command is already in this matcher's hooks
			for _, h := range m.Hooks {
				if h.Command == hookCommand {
					found = true
					break
				}
			}
			if !found {
				// Matcher exists but our command isn't there — add it
				preToolUseHooks[i].Hooks = append(preToolUseHooks[i].Hooks, hookEntry{
					Type:    "command",
					Command: hookCommand,
				})
				found = true
			}
			break
		}
	}

	if !found {
		// Add new matcher entry
		preToolUseHooks = append(preToolUseHooks, hookMatcher{
			Matcher: "Bash",
			Hooks: []hookEntry{
				{Type: "command", Command: hookCommand},
			},
		})
	}

	hooks["PreToolUse"] = preToolUseHooks

	// Marshal hooks back into the config
	hooksRaw, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	cfg["hooks"] = hooksRaw

	return writeSettingsFile(settingsPath, cfg)
}
