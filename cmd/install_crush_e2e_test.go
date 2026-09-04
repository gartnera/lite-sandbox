package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCrushEndToEnd drives a real crush binary through `lite-sandbox install
// crush` and a non-interactive `crush run`, with a local mock
// OpenAI-compatible model server standing in for the LLM. The mock asks Crush
// to call mcp_lite-sandbox_bash, so the run proves that Crush (1) loads the
// generated config, (2) launches `lite-sandbox serve-mcp` and exposes its tools
// under Crush's mcp_<server>_<tool> names, (3) no longer offers the built-in
// bash tool, and (4) executes the sandboxed command and feeds the result back.
//
// It always compiles but only runs when CRUSH_E2E_TESTS is set and both a
// `crush` binary (on PATH, or at $CRUSH_BIN) and the built `lite-sandbox`
// binary at the repo root are present.
func TestCrushEndToEnd(t *testing.T) {
	if os.Getenv("CRUSH_E2E_TESTS") == "" {
		t.Skip("requires a crush binary; set CRUSH_E2E_TESTS=1 (and optionally CRUSH_BIN) to run")
	}
	crushBin := os.Getenv("CRUSH_BIN")
	if crushBin == "" {
		var err error
		if crushBin, err = exec.LookPath("crush"); err != nil {
			t.Skip("crush not on PATH and CRUSH_BIN unset")
		}
	}
	sandboxBin, err := filepath.Abs(filepath.Join("..", "lite-sandbox"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sandboxBin); err != nil {
		t.Skipf("lite-sandbox binary not built at %s (run `go build -o lite-sandbox` first)", sandboxBin)
	}

	for _, format := range []string{"crushrc", "crush.json"} {
		t.Run(format, func(t *testing.T) {
			runCrushEndToEnd(t, crushBin, sandboxBin, format)
		})
	}
}

// mockToolCalls is the scripted sequence of sandbox commands the mock model
// asks for, one per agent turn: first a command the sandbox must reject (curl
// is not whitelisted), then one it must run.
var mockToolCalls = []string{"curl http://example.com", "echo hello-from-sandbox"}

// mockModel is a minimal OpenAI-compatible chat-completions server. On each
// agent turn it issues the next scripted mcp_lite-sandbox_bash call; once every
// call has a tool result in the transcript, it answers with text quoting the
// last result.
type mockModel struct {
	mu       sync.Mutex
	requests []map[string]any
}

func (m *mockModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.requests = append(m.requests, req)
	m.mu.Unlock()

	// Decide the reply from the transcript: a tool-role message means our tool
	// call already ran. Requests without a tools list (Crush's session-title
	// generation) just get a short text answer.
	_, isAgentTurn := req["tools"]
	results := toolResults(req)

	stream, _ := req["stream"].(bool)
	var delta map[string]any
	finish := "stop"
	switch {
	case !isAgentTurn:
		delta = map[string]any{"role": "assistant", "content": "Sandbox test"}
	case len(results) < len(mockToolCalls):
		args, _ := json.Marshal(map[string]string{"command": mockToolCalls[len(results)]})
		delta = map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"index": 0, "id": fmt.Sprintf("call_%d", len(results)+1), "type": "function",
				"function": map[string]any{
					"name":      "mcp_lite-sandbox_bash",
					"arguments": string(args),
				},
			}},
		}
		finish = "tool_calls"
	default:
		delta = map[string]any{"role": "assistant", "content": "The sandbox printed: " + strings.TrimSpace(results[len(results)-1])}
	}
	usage := map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}

	if !stream {
		msg := map[string]any{"role": "assistant", "content": delta["content"], "tool_calls": delta["tool_calls"]}
		writeJSON(w, map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion", "created": 1, "model": "mock-model",
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   usage,
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	chunk := func(d map[string]any, fin any, u any) {
		c := map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 1, "model": "mock-model",
			"choices": []any{map[string]any{"index": 0, "delta": d, "finish_reason": fin}},
		}
		if u != nil {
			c["usage"] = u
		}
		b, _ := json.Marshal(c)
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	chunk(delta, nil, nil)
	chunk(map[string]any{}, finish, usage)
	fmt.Fprint(w, "data: [DONE]\n\n")
}

// toolResults returns the contents of the tool-role messages in the request's
// transcript, in order.
func toolResults(req map[string]any) []string {
	var results []string
	msgs, _ := req["messages"].([]any)
	for _, raw := range msgs {
		msg, _ := raw.(map[string]any)
		if msg["role"] == "tool" {
			results = append(results, flattenContent(msg["content"]))
		}
	}
	return results
}

// agentRequests returns the recorded requests that carried a tools list, i.e.
// the coder agent's turns (as opposed to Crush's title-generation request).
func (m *mockModel) agentRequests() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []map[string]any
	for _, req := range m.requests {
		if _, ok := req["tools"]; ok {
			out = append(out, req)
		}
	}
	return out
}

func flattenContent(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var parts []string
		for _, p := range c {
			if pm, ok := p.(map[string]any); ok {
				if s, ok := pm["text"].(string); ok {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func runCrushEndToEnd(t *testing.T, crushBin, sandboxBin, format string) {
	model := &mockModel{}
	srv := httptest.NewServer(model)
	defer srv.Close()

	// Isolate Crush completely: its config dir, data dir, and HOME all point at
	// temp directories, so the real user's config is never read or written.
	configDir := t.TempDir()
	dataDir := t.TempDir()
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("CRUSH_GLOBAL_CONFIG", configDir)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	// The provider/model half of the config is what a user would already have.
	// Crush will only use the mock; provider auto-update and metrics are off so
	// the run makes no network calls beyond our server.
	baseURL := srv.URL + "/v1"
	switch format {
	case "crushrc":
		rc := strings.Join([]string{
			"# user config",
			"provider add mock --type openai-compat --base-url " + baseURL + " --api-key dummy",
			"model add mock/mock-model --name Mock --context-window 128000 --default-max-tokens 4096",
			"model large mock/mock-model",
			"model small mock/mock-model",
			"option provider-auto-update false",
			"option metrics false",
			"option notifications disabled",
			"",
		}, "\n")
		if err := os.WriteFile(filepath.Join(configDir, "crushrc"), []byte(rc), 0644); err != nil {
			t.Fatal(err)
		}
	case "crush.json":
		cfg := map[string]any{
			"providers": map[string]any{
				"mock": map[string]any{
					"type": "openai-compat", "base_url": baseURL, "api_key": "dummy",
					"models": []any{map[string]any{"id": "mock-model", "name": "Mock", "context_window": 128000, "default_max_tokens": 4096}},
				},
			},
			"models": map[string]any{
				"large": map[string]any{"provider": "mock", "model": "mock-model"},
				"small": map[string]any{"provider": "mock", "model": "mock-model"},
			},
			"options": map[string]any{"disable_provider_auto_update": true, "disable_metrics": true, "notifications": "disabled"},
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(filepath.Join(configDir, "crush.json"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// The install under test.
	if err := runInstallCrush(sandboxBin); err != nil {
		t.Fatalf("runInstallCrush failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "crushrc")); (err == nil) != (format == "crushrc") {
		t.Fatalf("install edited the wrong config file for %s", format)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, crushBin, "run", "--quiet", "--verbose", "--cwd", project,
		"Run the command echo hello-from-sandbox and tell me what it printed.")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"CRUSH_GLOBAL_CONFIG="+configDir,
		"CRUSH_GLOBAL_DATA="+dataDir,
		"XDG_DATA_HOME="+dataDir,
		"XDG_CONFIG_HOME=",
		"NO_COLOR=1",
	)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("crush run failed: %v\n%s", err, output)
	}
	t.Logf("crush output:\n%s", output)

	if !strings.Contains(output, "The sandbox printed: hello-from-sandbox") {
		t.Errorf("final answer missing the sandboxed command's output:\n%s", output)
	}

	turns := model.agentRequests()
	if want := len(mockToolCalls) + 1; len(turns) < want {
		t.Fatalf("expected at least %d agent turns (%d tool calls + answer), got %d", want, len(mockToolCalls), len(turns))
	}
	tools := toolNames(turns[0])
	t.Logf("tools offered on the first agent turn: %v", keys(tools))
	for _, want := range crushToolPermissions {
		if !tools[want] {
			t.Errorf("sandbox tool %s not offered to the model; tools: %v", want, keys(tools))
		}
	}
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model; tools: %v", keys(tools))
	}
	if !tools["view"] {
		t.Errorf("unrelated built-in tools were hidden too; tools: %v", keys(tools))
	}

	// The tool results Crush fed back must show the sandbox enforcing its
	// whitelist (curl rejected) and running the allowed command.
	results := toolResults(turns[len(turns)-1])
	t.Logf("tool results fed back: %q", results)
	if len(results) != len(mockToolCalls) {
		t.Fatalf("expected %d tool results, got %d", len(mockToolCalls), len(results))
	}
	if !strings.Contains(results[0], `command "curl" is not allowed`) {
		t.Errorf("sandbox did not reject curl: %q", results[0])
	}
	if got := results[1]; strings.TrimSpace(got) != "hello-from-sandbox" {
		t.Errorf("tool result is not the sandbox's output: %q", got)
	}
}

func toolNames(req map[string]any) map[string]bool {
	names := map[string]bool{}
	tools, _ := req["tools"].([]any)
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		fn, _ := tool["function"].(map[string]any)
		if name, ok := fn["name"].(string); ok {
			names[name] = true
		}
	}
	return names
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
