package cmd

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func setupClient(t *testing.T) *client.Client {
	t.Helper()
	ctx := context.Background()

	s := NewMCPServer()
	c, err := client.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("failed to create in-process client: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo: mcp.Implementation{
				Name:    "test-client",
				Version: "0.0.1",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}

	return c
}

func TestBashSandboxedTool_Success(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "echo hello"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %+v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if text.Text != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_InvalidSyntax(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "echo 'hello"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for invalid syntax")
	}
}

func TestBashSandboxedTool_MissingCommand(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for missing command")
	}
}

func TestListTools(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	got := make(map[string]bool)
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"bash", "bash_output", "kill_shell", "list_shells"} {
		if !got[want] {
			t.Fatalf("expected tool %q to be registered, got tools %v", want, got)
		}
	}
}

func TestBashSandboxedTool_Timeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with a command that takes longer than the timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "sleep 10",
				"timeout": 100.0, // 100ms timeout
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for timeout")
	}
	// Check that the error message mentions context deadline
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "context deadline exceeded") {
				t.Fatalf("expected timeout error message, got: %q", text.Text)
			}
		}
	}
}

func TestBashSandboxedTool_CompletesBeforeTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with a command that completes before the timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo quick",
				"timeout": 5000.0, // 5 second timeout, plenty of time
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %+v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if text.Text != "quick\n" {
		t.Fatalf("expected 'quick\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_DefaultTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test without specifying timeout (should use default of 120000ms)
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "echo default"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %+v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if text.Text != "default\n" {
		t.Fatalf("expected 'default\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_TimeoutExceedsMaximum(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with timeout exceeding maximum (600000ms)
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo test",
				"timeout": 700000.0, // Exceeds max
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for timeout exceeding maximum")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "exceeds maximum") {
				t.Fatalf("expected max timeout error message, got: %q", text.Text)
			}
		}
	}
}

func TestBashSandboxedTool_NormalExitNoFallbackHint(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// `false` is an allowed command that always exits with status 1 (normal failure)
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "false"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for `false` command")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if strings.Contains(text.Text, "dangerouslyDisableSandbox") {
				t.Fatalf("normal exit errors should NOT contain fallback hint, got: %q", text.Text)
			}
		}
	}
}

func TestBashSandboxedTool_ValidationErrorNoFallbackHint(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// `python` is not in the allowed commands whitelist
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "python evil.py"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for disallowed command")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if strings.Contains(text.Text, "dangerouslyDisableSandbox") {
				t.Fatalf("validation errors should NOT contain fallback hint, got: %q", text.Text)
			}
		}
	}
}

// callBash is a small helper that invokes a tool and returns the first text content.
func callTextTool(t *testing.T, c *client.Client, name string, args map[string]any) (string, bool) {
	t.Helper()
	result, err := c.CallTool(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: name, Arguments: args},
	})
	if err != nil {
		t.Fatalf("CallTool %s failed: %v", name, err)
	}
	if len(result.Content) == 0 {
		return "", result.IsError
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent from %s, got %T", name, result.Content[0])
	}
	return text.Text, result.IsError
}

func extractShellID(t *testing.T, s string) string {
	t.Helper()
	start := strings.Index(s, "shell id \"")
	if start < 0 {
		t.Fatalf("could not find shell id in %q", s)
	}
	rest := s[start+len("shell id \""):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		t.Fatalf("could not parse shell id in %q", s)
	}
	return rest[:end]
}

func TestBashBackground_OutputAndStatus(t *testing.T) {
	c := setupClient(t)

	text, isErr := callTextTool(t, c, "bash", map[string]any{
		"command":           "echo background-hello",
		"run_in_background": true,
	})
	if isErr {
		t.Fatalf("expected success starting background, got error: %q", text)
	}
	id := extractShellID(t, text)

	// Poll bash_output until the process completes.
	var out string
	for i := 0; i < 200; i++ {
		var isErr bool
		out, isErr = callTextTool(t, c, "bash_output", map[string]any{"bash_id": id})
		if isErr {
			t.Fatalf("bash_output returned error: %q", out)
		}
		if strings.Contains(out, "<status>completed</status>") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out, "background-hello") {
		t.Fatalf("expected background output to contain greeting, got %q", out)
	}
	if !strings.Contains(out, "<status>completed</status>") {
		t.Fatalf("expected completed status, got %q", out)
	}
	if !strings.Contains(out, "<exit_code>0</exit_code>") {
		t.Fatalf("expected exit code 0, got %q", out)
	}
}

func TestBashBackground_Kill(t *testing.T) {
	c := setupClient(t)

	text, isErr := callTextTool(t, c, "bash", map[string]any{
		"command":           "sleep 30",
		"run_in_background": true,
	})
	if isErr {
		t.Fatalf("expected success starting background, got error: %q", text)
	}
	id := extractShellID(t, text)

	killText, isErr := callTextTool(t, c, "kill_shell", map[string]any{"shell_id": id})
	if isErr {
		t.Fatalf("kill_shell returned error: %q", killText)
	}

	// list_shells should report it as killed eventually.
	var listOut string
	for i := 0; i < 200; i++ {
		listOut, _ = callTextTool(t, c, "list_shells", nil)
		if strings.Contains(listOut, "killed") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(listOut, id) || !strings.Contains(listOut, "killed") {
		t.Fatalf("expected list_shells to show %q as killed, got %q", id, listOut)
	}
}

func TestBashBackground_ValidationError(t *testing.T) {
	c := setupClient(t)

	text, isErr := callTextTool(t, c, "bash", map[string]any{
		"command":           "python evil.py",
		"run_in_background": true,
	})
	if !isErr {
		t.Fatalf("expected validation error for disallowed background command, got %q", text)
	}
}

func TestBashOutput_UnknownID(t *testing.T) {
	c := setupClient(t)

	text, isErr := callTextTool(t, c, "bash_output", map[string]any{"bash_id": "bash_404"})
	if !isErr {
		t.Fatalf("expected error for unknown id, got %q", text)
	}
}

func TestListShells_Empty(t *testing.T) {
	c := setupClient(t)

	text, isErr := callTextTool(t, c, "list_shells", nil)
	if isErr {
		t.Fatalf("list_shells returned error: %q", text)
	}
	if !strings.Contains(text, "No background processes") {
		t.Fatalf("expected empty message, got %q", text)
	}
}

func TestBashSandboxedTool_NegativeTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with negative timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo test",
				"timeout": -1000.0,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for negative timeout")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "must be positive") {
				t.Fatalf("expected positive timeout error message, got: %q", text.Text)
			}
		}
	}
}

// TestSandboxPaths_WritableIsReadable guards against the bash tool and the
// PreToolUse hook disagreeing about whether a configured writable path is also
// readable. Both now share sandboxPaths, so a writable path must appear in the
// read set (otherwise `cat /granted/writable/f` would be denied in bash but
// allowed for the built-in file tools).
func TestSandboxPaths_WritableIsReadable(t *testing.T) {
	sb := bash_sandboxed.NewSandbox()
	defer sb.Close()
	sb.UpdateConfig(&config.Config{
		WritablePaths: []string{"/granted/writable"},
		ReadablePaths: []string{"/granted/readable"},
	}, "/work")

	readPaths, writePaths := sandboxPaths(sb, "/work")

	if !slices.Contains(writePaths, "/granted/writable") {
		t.Fatalf("expected writable path in writePaths, got %v", writePaths)
	}
	if !slices.Contains(readPaths, "/granted/writable") {
		t.Fatalf("writable path must also be readable; readPaths=%v", readPaths)
	}
	if !slices.Contains(readPaths, "/granted/readable") {
		t.Fatalf("expected readable path in readPaths, got %v", readPaths)
	}
}

// TestSandboxPaths_InternalPathsExcluded guards the security property of
// internal_readable_paths / internal_writable_paths: they only loosen the OS
// sandbox worker's profile and must never appear in the AST-level path sets.
// If one leaked into sandboxPaths, the agent could read/write it directly and
// Deno's injected --allow-read/--allow-write would grant executed code the
// same access — exactly the sandbox workaround the fields are designed to
// prevent.
func TestSandboxPaths_InternalPathsExcluded(t *testing.T) {
	sb := bash_sandboxed.NewSandbox()
	defer sb.Close()
	sb.UpdateConfig(&config.Config{
		InternalReadablePaths: []string{"/internal/readable"},
		InternalWritablePaths: []string{"/internal/writable"},
	}, "/work")

	readPaths, writePaths := sandboxPaths(sb, "/work")

	for _, p := range []string{"/internal/readable", "/internal/writable"} {
		if slices.Contains(readPaths, p) {
			t.Fatalf("internal path %q must not be in readPaths, got %v", p, readPaths)
		}
		if slices.Contains(writePaths, p) {
			t.Fatalf("internal path %q must not be in writePaths, got %v", p, writePaths)
		}
	}
}
