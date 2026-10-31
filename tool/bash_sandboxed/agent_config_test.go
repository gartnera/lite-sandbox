package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAgentConfigPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Directories, at any depth and in any case.
		{"/repo/.claude/settings.json", true},
		{"/repo/.codex", true},
		{"/repo/.codex/config.toml", true},
		{"/repo/.codex/hooks.json", true},
		{"/home/u/.codex/config.toml", true},
		{"/repo/.agents/skills/x/SKILL.md", true},
		{"/repo/.opencode", true},
		{"/repo/.opencode/plugin/x.ts", true},
		{"/repo/pkg/.opencode/opencode.json", true},
		{"/home/u/.opencode/agent/a.md", true},
		{"/repo/.crush/commands/x.md", true},
		{"/repo/.grok/hooks/h.json", true},
		{"/repo/.grok/config.toml", true},
		{"/repo/.OpenCode/plugin/x.ts", true},
		{"/repo/.pi", true},
		{"/repo/.pi/extensions/x.ts", true},
		{"/home/u/.pi/agent/settings.json", true},
		{"/repo/.PI/mcp.json", true},
		{"/repo/.pi/worktrees/x", true},
		{"/repo/.pip/x", false},
		{"/repo/.pi.json", false},
		// Worktree exemptions: Claude Code's and the Codex app's, each only
		// directly under its own directory, and a config directory inside
		// the worktree is protected again.
		{"/repo/.claude/worktrees/feat/main.go", false},
		{"/home/u/.codex/worktrees", false},
		{"/home/u/.codex/worktrees/1a2b/repo/main.go", false},
		{"/home/u/.codex/worktrees/1a2b/repo/.codex/config.toml", true},
		{"/home/u/.codex/worktrees/1a2b/repo/opencode.json", true},
		{"/repo/.opencode/worktrees/x", true},
		{"/repo/.agents/worktrees/x", true},
		// Config files, by name, anywhere.
		{"/repo/.mcp.json", true},
		{"/repo/opencode.json", true},
		{"/repo/pkg/opencode.jsonc", true},
		{"/repo/tui.json", true},
		{"/repo/tui.jsonc", true},
		{"/repo/crushrc", true},
		{"/repo/.crushrc", true},
		{"/repo/crush.json", true},
		{"/repo/.crush.json", true},
		{"/repo/OpenCode.JSON", true},
		// Not agent configuration.
		{"/repo/src/main.go", false},
		{"/repo/AGENTS.md", false},
		{"/repo/CLAUDE.md", false},
		{"/repo/codex/config.toml", false},
		{"/repo/agents/x.md", false},
		{"/repo/opencode.json.bak", false},
		{"/repo/my-opencode.json", false},
		{"/repo/mcp.json", false},
		{"/repo/.codexrc", false},
		{"/", false},
	}
	for _, tt := range tests {
		if got := IsAgentConfigPath(tt.path); got != tt.want {
			t.Errorf("IsAgentConfigPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestBashSandboxed_AgentConfigReadOnly checks that every agent's project
// configuration, not just .claude (see TestBashSandboxed_ClaudeDirReadOnly),
// can be read but not written: the opencode.json or .opencode/ a command
// could otherwise plant to turn opencode's built-in shell back on or add a
// plugin that runs outside the sandbox, and the same for the other agents.
func TestBashSandboxed_AgentConfigReadOnly(t *testing.T) {
	workDir := t.TempDir()
	for _, d := range []string{".codex", ".agents/skills", ".opencode/plugin", ".crush", ".grok/hooks", "pkg"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"opencode.json":           "{}\n",
		".opencode/opencode.json": "{}\n",
		".codex/config.toml":      "\n",
		"crush.json":              "{}\n",
		".mcp.json":               "{}\n",
		"a.txt":                   "a\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("opencode.json", filepath.Join(workDir, "oc-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".opencode", filepath.Join(workDir, "oc-dir")); err != nil {
		t.Fatal(err)
	}

	allowed := []struct {
		name, command string
	}{
		{"cat opencode.json", "cat opencode.json"},
		{"ls .opencode", "ls .opencode"},
		{"cp from opencode.json", "cp opencode.json backup.json"},
		{"sed -n .codex", "sed -n 1p .codex/config.toml"},
		{"cd .grok and ls", "cd .grok && ls"},
		{"write a lookalike", "touch my-opencode.json opencode.json.bak codex.toml"},
		{"write AGENTS.md", "echo x > AGENTS.md"},
	}
	for _, tt := range allowed {
		t.Run("allowed/"+tt.name, func(t *testing.T) {
			if _, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	blocked := []struct {
		name, command string
	}{
		// opencode (v1 and v2).
		{"redirect opencode.json", `echo '{"permission":{"bash":"allow"}}' > opencode.json`},
		{"create opencode.jsonc", "touch opencode.jsonc"},
		{"nested opencode.json", "cp a.txt pkg/opencode.json"},
		{"tui.json", "echo '{}' > tui.json"},
		{"rm .opencode", "rm -rf .opencode"},
		{"plugin", "echo x > .opencode/plugin/escape.ts"},
		{"plugins dir", "mkdir -p .opencode/plugins"},
		{".opencode/opencode.json", "sed -i s/a/b/ .opencode/opencode.json"},
		{"through file symlink", "echo x > oc-link"},
		{"through dir symlink", "touch oc-dir/plugin/x.ts"},
		{"cd then write", "cd .opencode && echo x > opencode.json"},
		{"variable", "F=opencode.json; echo x > $F"},
		{"other case", "touch .OpenCode/x"},
		// Codex.
		{"codex config", "echo 'x' >> .codex/config.toml"},
		{"codex hooks", "touch .codex/hooks.json"},
		{"agents skill", "mkdir .agents/skills/evil"},
		// Crush.
		{"crushrc", "echo 'bash' > crushrc"},
		{".crushrc", "touch .crushrc"},
		{"crush.json", "tee crush.json < a.txt"},
		{".crush.json", "cp a.txt .crush.json"},
		{".crush commands", "mkdir .crush/commands"},
		// Grok Build.
		{"grok hook", "cp a.txt .grok/hooks/h.json"},
		{"grok config", "touch .grok/config.toml"},
		// Claude Code's project MCP servers.
		{".mcp.json", "sort -o .mcp.json a.txt"},
		{"mv over .mcp.json", "mv a.txt .mcp.json"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.name, func(t *testing.T) {
			_, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected the agent configuration write to be blocked")
			}
			if !strings.Contains(err.Error(), "a coding agent's configuration") {
				t.Fatalf("expected agent configuration error, got %q", err.Error())
			}
		})
	}

	for name, content := range files {
		if got, err := os.ReadFile(filepath.Join(workDir, name)); err != nil || string(got) != content {
			t.Errorf("%s changed: %q, %v", name, got, err)
		}
	}
}
