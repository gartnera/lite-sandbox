package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// writeBenchConfig writes a config fixture and points LITE_SANDBOX_CONFIG at it
// so the hook path under benchmark loads it the same way a real invocation does.
func writeBenchConfig(b *testing.B, yaml string) {
	b.Helper()
	p := filepath.Join(b.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		b.Fatal(err)
	}
	b.Setenv("LITE_SANDBOX_CONFIG", p)
}

func benchEvent(b *testing.B, json string) *hook.Event {
	b.Helper()
	event, err := hook.ParseEvent(strings.NewReader(json))
	if err != nil {
		b.Fatal(err)
	}
	return event
}

const benchRuntimesConfig = `
runtimes:
  go:
    enabled: true
  pnpm:
    enabled: true
git:
  allow_worktree_parent: true
`

// readEventJSON returns a Read tool event targeting a file inside cwd — the
// common case the hook sees on nearly every tool call.
func readEventJSON(cwd string) string {
	return `{"cwd":"` + cwd + `","hook_event_name":"PreToolUse","tool_name":"Read",` +
		`"tool_input":{"file_path":"` + cwd + `/main.go"}}`
}

func bashEventJSON(cwd string) string {
	return `{"cwd":"` + cwd + `","hook_event_name":"PreToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":"grep -rn foo ./cmd | head -5"}}`
}

// BenchmarkHookEvaluateRead measures the hook's path-policy evaluation for a
// Read inside cwd with no runtimes configured.
func BenchmarkHookEvaluateRead(b *testing.B) {
	writeBenchConfig(b, "{}")
	cwd, _ := os.Getwd()
	event := benchEvent(b, readEventJSON(cwd))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := evaluate(event, false); d != nil {
			b.Fatalf("expected defer, got %+v", d)
		}
	}
}

// BenchmarkHookEvaluateReadRuntimes is the same evaluation with go and pnpm
// runtimes enabled — the configuration that triggers runtime path detection.
func BenchmarkHookEvaluateReadRuntimes(b *testing.B) {
	writeBenchConfig(b, benchRuntimesConfig)
	cwd, _ := os.Getwd()
	event := benchEvent(b, readEventJSON(cwd))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := evaluate(event, false); d != nil {
			b.Fatalf("expected defer, got %+v", d)
		}
	}
}

// BenchmarkHookValidateBash measures --validate-bash evaluation of a typical
// pipeline with no runtimes configured.
func BenchmarkHookValidateBash(b *testing.B) {
	writeBenchConfig(b, "{}")
	cwd, _ := os.Getwd()
	event := benchEvent(b, bashEventJSON(cwd))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := evaluate(event, true); d == nil {
			b.Fatal("expected allow decision, got defer")
		}
	}
}

// BenchmarkHookValidateBashRuntimes is the same with runtimes enabled.
func BenchmarkHookValidateBashRuntimes(b *testing.B) {
	writeBenchConfig(b, benchRuntimesConfig)
	cwd, _ := os.Getwd()
	event := benchEvent(b, bashEventJSON(cwd))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := evaluate(event, true); d == nil {
			b.Fatal("expected allow decision, got defer")
		}
	}
}

// BenchmarkMCPBashEcho measures a full in-process MCP tool call running a
// trivial command, i.e. the server's fixed per-call overhead.
func BenchmarkMCPBashEcho(b *testing.B) {
	ctx := context.Background()
	s := NewMCPServer()
	c, err := client.NewInProcessClient(s)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo:      mcp.Implementation{Name: "bench", Version: "0.0.1"},
		},
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := c.CallTool(ctx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "bash",
				Arguments: map[string]any{"command": "echo hello"},
			},
		})
		if err != nil {
			b.Fatal(err)
		}
		if result.IsError {
			b.Fatalf("tool error: %+v", result.Content)
		}
	}
}
