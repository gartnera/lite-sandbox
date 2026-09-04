// Package mockopenai provides a scripted, in-process mock of the OpenAI
// chat-completions API for end-to-end tests of agent harnesses (Crush,
// opencode, ...) that can talk to any OpenAI-compatible endpoint.
//
// Point a harness at Server.BaseURL with a dummy API key and it will, on each
// agent turn (a request that carries a tools list), receive the next scripted
// tool call; once every scripted call has a tool result in the transcript it
// receives a final text answer. Requests without a tools list — side requests
// such as session-title generation — get a short canned reply so they never
// consume a scripted tool call. Both streaming (SSE) and non-streaming
// responses are supported.
//
// Every request body is recorded so a test can assert on what the harness
// actually sent: which tools it offered, and what tool results it fed back.
package mockopenai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// ToolCall is one scripted function call the mock model issues.
type ToolCall struct {
	// Name is the tool (function) name as the harness exposes it to the model,
	// e.g. "mcp_lite-sandbox_bash".
	Name string
	// Arguments is JSON-marshalled into the call's arguments string.
	Arguments any
}

// Script describes the mock model's behavior for one conversation.
type Script struct {
	// ToolCalls are issued one per agent turn, in order.
	ToolCalls []ToolCall
	// FinalText produces the model's answer once every ToolCall has a result in
	// the transcript. results holds the tool-role message contents in order.
	// When nil, the answer is DefaultFinalText(results).
	FinalText func(results []string) string
	// SideText is the reply to requests without a tools list (e.g. title
	// generation). Defaults to "mock".
	SideText string
}

// DefaultFinalText is the FinalText used when Script.FinalText is nil: it
// quotes the last tool result.
func DefaultFinalText(results []string) string {
	if len(results) == 0 {
		return "No tool results."
	}
	return "Last tool result: " + strings.TrimSpace(results[len(results)-1])
}

// Server is a running mock chat-completions endpoint.
type Server struct {
	// BaseURL is the API base to configure in the harness (ends in /v1).
	BaseURL string
	// ModelID is the model name to configure in the harness. Any model name is
	// accepted; this is just a convenient default.
	ModelID string

	script Script
	srv    *httptest.Server

	mu       sync.Mutex
	requests []Request
}

// Request is one recorded chat-completions request body.
type Request map[string]any

// Start launches a mock server for script. Call Close when done.
func Start(script Script) *Server {
	if script.SideText == "" {
		script.SideText = "mock"
	}
	if script.FinalText == nil {
		script.FinalText = DefaultFinalText
	}
	s := &Server{script: script, ModelID: "mock-model"}
	s.srv = httptest.NewServer(s)
	s.BaseURL = s.srv.URL + "/v1"
	return s
}

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Requests returns every recorded request, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// AgentRequests returns the recorded requests that carried a tools list — the
// agent's own turns, as opposed to side requests like title generation.
func (s *Server) AgentRequests() []Request {
	var out []Request
	for _, req := range s.Requests() {
		if _, ok := req["tools"]; ok {
			out = append(out, req)
		}
	}
	return out
}

// ToolNames returns the set of function names offered in the request's tools
// list.
func (r Request) ToolNames() map[string]bool {
	names := map[string]bool{}
	tools, _ := r["tools"].([]any)
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		fn, _ := tool["function"].(map[string]any)
		if name, ok := fn["name"].(string); ok {
			names[name] = true
		}
	}
	return names
}

// ToolResults returns the contents of the tool-role messages in the request's
// transcript, in order — i.e. what the harness fed back for each tool call.
func (r Request) ToolResults() []string {
	var results []string
	msgs, _ := r["messages"].([]any)
	for _, raw := range msgs {
		msg, _ := raw.(map[string]any)
		if msg["role"] == "tool" {
			results = append(results, flattenContent(msg["content"]))
		}
	}
	return results
}

// ServeHTTP implements the chat-completions endpoint. Only
// POST .../chat/completions is served; everything else is 404.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()

	_, isAgentTurn := req["tools"]
	results := req.ToolResults()

	var delta map[string]any
	finish := "stop"
	switch {
	case !isAgentTurn:
		delta = map[string]any{"role": "assistant", "content": s.script.SideText}
	case len(results) < len(s.script.ToolCalls):
		call := s.script.ToolCalls[len(results)]
		args, err := json.Marshal(call.Arguments)
		if err != nil {
			http.Error(w, fmt.Sprintf("bad scripted arguments: %v", err), http.StatusInternalServerError)
			return
		}
		delta = map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"index": 0, "id": fmt.Sprintf("call_%d", len(results)+1), "type": "function",
				"function": map[string]any{"name": call.Name, "arguments": string(args)},
			}},
		}
		finish = "tool_calls"
	default:
		delta = map[string]any{"role": "assistant", "content": s.script.FinalText(results)}
	}
	usage := map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}

	if stream, _ := req["stream"].(bool); !stream {
		msg := map[string]any{"role": "assistant", "content": delta["content"], "tool_calls": delta["tool_calls"]}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion", "created": 1, "model": s.ModelID,
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   usage,
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	chunk := func(d map[string]any, fin any, u any) {
		c := map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 1, "model": s.ModelID,
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

// flattenContent renders a message content field — a plain string or an array
// of {"type":"text","text":...} parts — as text.
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
