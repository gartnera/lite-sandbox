package mockopenai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func post(t *testing.T, url string, body map[string]any) (*http.Response, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url+"/chat/completions", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp, out.String()
}

var bashTool = []any{map[string]any{
	"type":     "function",
	"function": map[string]any{"name": "mcp_x_bash", "parameters": map[string]any{}},
}}

// TestScriptedConversation walks a full conversation: a side request, two
// scripted tool calls, and the final answer — over both the streaming and
// non-streaming wire formats.
func TestScriptedConversation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[stream], func(t *testing.T) {
			srv := Start(Script{
				ToolCalls: []ToolCall{
					{Name: "mcp_x_bash", Arguments: map[string]string{"command": "false"}},
					{Name: "mcp_x_bash", Arguments: map[string]string{"command": "echo hi"}},
				},
				FinalText: func(results []string) string { return "done: " + strings.Join(results, "|") },
				SideText:  "Title",
			})
			defer srv.Close()

			// Side request (no tools) gets the canned text and consumes no tool call.
			_, body := post(t, srv.BaseURL, map[string]any{"stream": stream, "messages": []any{}})
			if !strings.Contains(body, "Title") || strings.Contains(body, "tool_calls\":[") {
				t.Errorf("side request got wrong reply: %s", body)
			}

			// Turn 1: first tool call.
			msgs := []any{map[string]any{"role": "user", "content": "go"}}
			_, body = post(t, srv.BaseURL, map[string]any{"stream": stream, "tools": bashTool, "messages": msgs})
			if !strings.Contains(body, `\"command\":\"false\"`) || !strings.Contains(body, "tool_calls") {
				t.Errorf("turn 1 should issue the first tool call: %s", body)
			}
			if stream && (!strings.HasPrefix(body, "data: ") || !strings.Contains(body, "data: [DONE]")) {
				t.Errorf("streaming reply is not SSE: %s", body)
			}

			// Turn 2: one result present → second tool call.
			msgs = append(msgs, map[string]any{"role": "tool", "tool_call_id": "call_1", "content": "error"})
			_, body = post(t, srv.BaseURL, map[string]any{"stream": stream, "tools": bashTool, "messages": msgs})
			if !strings.Contains(body, `echo hi`) {
				t.Errorf("turn 2 should issue the second tool call: %s", body)
			}

			// Turn 3: both results present (one as content parts) → final text.
			msgs = append(msgs, map[string]any{"role": "tool", "tool_call_id": "call_2",
				"content": []any{map[string]any{"type": "text", "text": "hi"}}})
			_, body = post(t, srv.BaseURL, map[string]any{"stream": stream, "tools": bashTool, "messages": msgs})
			if !strings.Contains(body, "done: error|hi") || strings.Contains(body, "tool_calls\":[") {
				t.Errorf("turn 3 should be the final answer: %s", body)
			}

			if got := len(srv.Requests()); got != 4 {
				t.Errorf("expected 4 recorded requests, got %d", got)
			}
			agent := srv.AgentRequests()
			if len(agent) != 3 {
				t.Fatalf("expected 3 agent turns, got %d", len(agent))
			}
			if !agent[0].ToolNames()["mcp_x_bash"] {
				t.Errorf("ToolNames missing offered tool: %v", agent[0].ToolNames())
			}
			if got := agent[2].ToolResults(); strings.Join(got, ",") != "error,hi" {
				t.Errorf("ToolResults = %v", got)
			}
		})
	}
}

func TestUnknownPathIs404(t *testing.T) {
	srv := Start(Script{})
	defer srv.Close()
	resp, err := http.Get(srv.BaseURL + "/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}
