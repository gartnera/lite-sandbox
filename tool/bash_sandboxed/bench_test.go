package bash_sandboxed

import (
	"context"
	"os"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

const benchCommand = `grep -rn "foo" ./cmd | sort | head -20 && wc -l ./main.go`

// BenchmarkParseBash measures bash AST parsing alone.
func BenchmarkParseBash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParseBash(benchCommand); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateCommand measures full pre-execution validation (parse, AST
// whitelist, path boundaries, script-content scanning).
func BenchmarkValidateCommand(b *testing.B) {
	s := NewSandbox()
	cwd, _ := os.Getwd()
	read := []string{cwd}
	write := []string{cwd}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.ValidateCommand(benchCommand, cwd, read, write); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExecuteEcho measures Execute for a trivial builtin-only command:
// the sandbox's fixed per-command overhead without subprocess cost.
func BenchmarkExecuteEcho(b *testing.B) {
	s := NewSandbox()
	cwd, _ := os.Getwd()
	read := []string{cwd}
	write := []string{cwd}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Execute(ctx, "echo hello", cwd, read, write); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUpdateConfigRuntimes measures applying a config with go and pnpm
// runtimes enabled — the path both the MCP server (startup/reload) and the
// hook (every invocation) go through.
func BenchmarkUpdateConfigRuntimes(b *testing.B) {
	cfg := &config.Config{
		Runtimes: &config.RuntimesConfig{
			Go:   &config.GoConfig{Enabled: boolPtr(true)},
			Pnpm: &config.PnpmConfig{Enabled: boolPtr(true)},
		},
	}
	cwd, _ := os.Getwd()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewSandbox()
		s.UpdateConfig(cfg, cwd)
		s.RuntimeReadPaths()
		s.Close()
	}
}

// BenchmarkWorktreeParentPath measures the worktree-parent lookup the MCP
// server performs on every bash tool call when allow_worktree_parent is set.
func BenchmarkWorktreeParentPath(b *testing.B) {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		Git: &config.GitConfig{AllowWorktreeParent: boolPtr(true)},
	}, "")
	cwd, _ := os.Getwd()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.WorktreeParentPath(cwd)
	}
}
