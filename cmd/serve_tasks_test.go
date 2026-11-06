package cmd

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"

	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// taskTestServer is a server driven over raw JSON-RPC on protocol revision
// 2026-07-28, so each request carries its own client capabilities, as Claude
// Code sends them.
type taskTestServer struct {
	t       *testing.T
	sandbox *bash_sandboxed.Sandbox
	srv     *server.MCPServer
	nextID  atomic.Int64
}

func newTaskTestServer(t *testing.T) *taskTestServer {
	t.Helper()
	sb := bash_sandboxed.NewSandbox()
	t.Cleanup(func() { sb.Close() })
	return &taskTestServer{t: t, sandbox: sb, srv: newMCPServer(sb, serveOptions{})}
}

// call sends method with params, declaring the tasks extension when tasks is
// set, and returns the JSON-RPC result, failing the test on an error reply.
func (s *taskTestServer) call(method string, params map[string]any, tasks bool) map[string]any {
	s.t.Helper()
	caps := map[string]any{}
	if tasks {
		caps["extensions"] = map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}}
	}
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "test-client", "version": "0.0.1"},
		"io.modelcontextprotocol/clientCapabilities": caps,
	}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": s.nextID.Add(1), "method": method, "params": params})
	if err != nil {
		s.t.Fatal(err)
	}
	reply, err := json.Marshal(s.srv.HandleMessage(s.t.Context(), raw))
	if err != nil {
		s.t.Fatal(err)
	}
	var msg struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	if err := json.Unmarshal(reply, &msg); err != nil {
		s.t.Fatal(err)
	}
	if msg.Error != nil {
		s.t.Fatalf("%s returned an error: %s", method, reply)
	}
	return msg.Result
}

func (s *taskTestServer) bash(command string, background, tasks bool) map[string]any {
	s.t.Helper()
	return s.call("tools/call", map[string]any{
		"name":      "bash",
		"arguments": map[string]any{"command": command, "run_in_background": background},
	}, tasks)
}

// awaitTask polls tasks/get until the task leaves "working", and returns the
// final reply.
func (s *taskTestServer) awaitTask(taskID string) map[string]any {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got := s.call("tasks/get", map[string]any{"taskId": taskID}, true)
		if got["status"] != "working" {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.t.Fatalf("task %s still working after 10s", taskID)
	return nil
}

// resultText returns the text of a tools/call result and whether it is an
// error.
func resultText(t *testing.T, result map[string]any) (string, bool) {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("result has no content: %v", result)
	}
	first, _ := content[0].(map[string]any)
	isErr, _ := result["isError"].(bool)
	return fmt.Sprint(first["text"]), isErr
}

func toolNames(result map[string]any) []string {
	var names []string
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		m, _ := tool.(map[string]any)
		names = append(names, fmt.Sprint(m["name"]))
	}
	slices.Sort(names)
	return names
}

// TestTasks_ControlToolsHidden checks that a client running background
// commands as tasks is offered only bash, and cannot call the control tools,
// while any other client keeps them.
func TestTasks_ControlToolsHidden(t *testing.T) {
	s := newTaskTestServer(t)
	if got := toolNames(s.call("tools/list", nil, true)); !slices.Equal(got, []string{"bash"}) {
		t.Errorf("tasks client: tools = %v, want only bash", got)
	}
	if got := toolNames(s.call("tools/list", nil, false)); !slices.Equal(got, []string{"bash", "kill_shell", "list_shells"}) {
		t.Errorf("plain client: tools = %v, want bash, kill_shell, list_shells", got)
	}

	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_shells","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}}}`
	reply, _ := json.Marshal(s.srv.HandleMessage(t.Context(), []byte(raw)))
	if !strings.Contains(string(reply), `"error"`) {
		t.Errorf("tasks client could call list_shells: %s", reply)
	}
}

// TestTasks_BackgroundRunsAsTask checks that a background command from a
// tasks client is answered with a task whose result, once the command exits,
// carries its exit code, output file, and output.
func TestTasks_BackgroundRunsAsTask(t *testing.T) {
	s := newTaskTestServer(t)
	created := s.bash("echo task-hello; exit 3", true, true)
	if created["resultType"] != "task" || created["status"] != "working" {
		t.Fatalf("expected a working task handle, got %v", created)
	}
	taskID := fmt.Sprint(created["taskId"])

	final := s.awaitTask(taskID)
	if final["status"] != "completed" {
		t.Fatalf("task status = %v, want completed: %v", final["status"], final)
	}
	result, _ := final["result"].(map[string]any)
	text, isErr := resultText(t, result)
	for _, want := range []string{"exited with code 3", "task-hello", "Output file: "} {
		if !strings.Contains(text, want) {
			t.Errorf("task result missing %q: %q", want, text)
		}
	}
	if !isErr {
		t.Errorf("a non-zero exit should be reported as an error result: %q", text)
	}

	procs := s.sandbox.ListBackground()
	if len(procs) != 1 || procs[0].Status != "failed" && procs[0].Status != "completed" {
		t.Errorf("expected the task's process to be tracked as finished, got %+v", procs)
	}
}

// TestTasks_ForegroundStaysSynchronous checks that only background commands
// become tasks: a plain bash call from a tasks client is answered directly.
func TestTasks_ForegroundStaysSynchronous(t *testing.T) {
	s := newTaskTestServer(t)
	result := s.bash("echo direct", false, true)
	if result["resultType"] == "task" {
		t.Fatalf("foreground call became a task: %v", result)
	}
	if text, isErr := resultText(t, result); isErr || text != "direct\n" {
		t.Fatalf("got %q (error %v), want direct output", text, isErr)
	}
}

// TestTasks_PlainClientGetsShellID checks that a client without the tasks
// extension keeps the shell id reply for background commands.
func TestTasks_PlainClientGetsShellID(t *testing.T) {
	s := newTaskTestServer(t)
	result := s.bash("echo plain", true, false)
	if result["resultType"] == "task" {
		t.Fatalf("background call from a plain client became a task: %v", result)
	}
	if text, _ := resultText(t, result); !strings.Contains(text, "shell id") {
		t.Fatalf("expected a shell id reply, got %q", text)
	}
}

// TestTasks_CancelKillsCommand checks that cancelling the task stops the
// background command.
func TestTasks_CancelKillsCommand(t *testing.T) {
	s := newTaskTestServer(t)
	created := s.bash("sleep 30", true, true)
	taskID := fmt.Sprint(created["taskId"])

	s.call("tasks/cancel", map[string]any{"taskId": taskID}, true)
	final := s.awaitTask(taskID)
	if final["status"] != "cancelled" {
		t.Errorf("task status = %v, want cancelled: %v", final["status"], final)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		procs := s.sandbox.ListBackground()
		if len(procs) == 1 && procs[0].Status == "killed" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background command not killed after cancel: %+v", s.sandbox.ListBackground())
}
