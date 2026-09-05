// Package mockmodel is a scripted, in-process stand-in for the LLM behind an
// agent harness, for end-to-end tests that drive real agent binaries (Crush,
// Codex, Claude Code, ...) without an API key.
//
// One server speaks the three wire protocols those harnesses use, the same way
// Ollama does:
//
//   - POST /v1/chat/completions — OpenAI chat completions (Crush's openai-compat
//     providers and most OpenAI-compatible clients)
//   - POST /v1/responses        — OpenAI Responses API (Codex)
//   - POST /v1/messages         — Anthropic Messages API (Claude Code)
//
// The protocol is an implementation detail of the harness under test, so the
// test-facing API hides it: every request is normalized into a Turn — the tool
// names the harness offered and the tool results it fed back — and the scripted
// behavior is the same on every endpoint. On each agent turn (a request that
// offers tools) the model issues the next scripted tool call; once every
// scripted call has a result in the transcript it answers with FinalText.
// Requests without tools — side requests such as session-title generation — get
// SideText and never consume a scripted call. Streaming (SSE) and plain JSON
// responses are both supported on every endpoint.
package mockmodel

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
	// e.g. "mcp_lite-sandbox_bash" (Crush) or "mcp__lite-sandbox__bash" (Claude
	// Code).
	Name string
	// Arguments is JSON-marshalled into the call's arguments.
	Arguments any
}

// Script describes the mock model's behavior for one conversation.
type Script struct {
	// ToolCalls are issued one per agent turn, in order.
	ToolCalls []ToolCall
	// FinalText produces the model's answer once every ToolCall has a result in
	// the transcript. results holds the tool results in transcript order. When
	// nil, the answer is DefaultFinalText(results).
	FinalText func(results []string) string
	// SideText is the reply to requests that offer no tools (e.g. title
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

// Turn is one recorded model request, normalized across wire protocols.
type Turn struct {
	// Protocol names the endpoint the harness used: "chat", "responses", or
	// "messages".
	Protocol string
	// Tools is the set of function names the harness offered. Empty for side
	// requests.
	Tools map[string]bool
	// ToolResults holds the tool results present in the transcript, in order —
	// i.e. what the harness fed back for each tool call so far.
	ToolResults []string
	// Raw is the decoded request body, for protocol-specific assertions and
	// debugging.
	Raw map[string]any
}

// IsAgentTurn reports whether the request offered tools, i.e. was the agent's
// own turn rather than a side request.
func (t Turn) IsAgentTurn() bool { return len(t.Tools) > 0 }

// Server is a running mock model endpoint.
type Server struct {
	// URL is the server root, for harnesses that append /v1 themselves (Claude
	// Code's ANTHROPIC_BASE_URL).
	URL string
	// BaseURL is URL + "/v1", for harnesses configured with a versioned API base
	// (Crush's --base-url, Codex's base_url). The three endpoints hang off it.
	BaseURL string
	// ModelID is the model name to configure in the harness. Any model name is
	// accepted; this is just a convenient default.
	ModelID string

	script Script
	srv    *httptest.Server

	mu    sync.Mutex
	turns []Turn
}

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
	s.URL = s.srv.URL
	s.BaseURL = s.srv.URL + "/v1"
	return s
}

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Turns returns every recorded request, in order.
func (s *Server) Turns() []Turn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Turn(nil), s.turns...)
}

// AgentTurns returns the recorded requests that offered tools — the agent's own
// turns, as opposed to side requests like title generation.
func (s *Server) AgentTurns() []Turn {
	var out []Turn
	for _, t := range s.Turns() {
		if t.IsAgentTurn() {
			out = append(out, t)
		}
	}
	return out
}

// reply is what the scripted model decided to say on one turn: exactly one of
// call or text is set. callIndex numbers the tool call within the conversation
// (0-based) so adapters can mint stable per-call IDs.
type reply struct {
	call      *ToolCall
	callIndex int
	text      string
}

// protocol is one wire-format adapter.
type protocol interface {
	// name identifies the protocol in Turn.Protocol.
	name() string
	// parse extracts the offered tools and the tool results from a request.
	parse(req map[string]any) (tools map[string]bool, results []string)
	// respond writes r in this protocol's response format, streaming if the
	// request asked for it.
	respond(w http.ResponseWriter, req map[string]any, r reply, modelID string) error
}

// protocolFor picks the adapter for a request path, or nil when the path is not
// one of the served endpoints.
func protocolFor(path string) protocol {
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return chatProtocol{}
	case strings.HasSuffix(path, "/responses"):
		return responsesProtocol{}
	case strings.HasSuffix(path, "/messages"):
		return messagesProtocol{}
	}
	return nil
}

// ServeHTTP routes the three POST endpoints; everything else is 404.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := protocolFor(r.URL.Path)
	if r.Method != http.MethodPost || p == nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tools, results := p.parse(req)
	turn := Turn{Protocol: p.name(), Tools: tools, ToolResults: results, Raw: req}
	s.mu.Lock()
	s.turns = append(s.turns, turn)
	s.mu.Unlock()

	var rep reply
	switch {
	case !turn.IsAgentTurn():
		rep.text = s.script.SideText
	case len(results) < len(s.script.ToolCalls):
		rep.call = &s.script.ToolCalls[len(results)]
		rep.callIndex = len(results)
	default:
		rep.text = s.script.FinalText(results)
	}
	if err := p.respond(w, req, rep, s.ModelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// marshalArgs renders a scripted call's arguments as the JSON string every
// protocol carries them in.
func marshalArgs(call *ToolCall) (string, error) {
	args, err := json.Marshal(call.Arguments)
	if err != nil {
		return "", fmt.Errorf("bad scripted arguments for %s: %w", call.Name, err)
	}
	return string(args), nil
}

// wantsStream reports whether the request asked for a streamed response.
func wantsStream(req map[string]any) bool {
	stream, _ := req["stream"].(bool)
	return stream
}

// sseWriter emits server-sent events.
type sseWriter struct{ w http.ResponseWriter }

func newSSE(w http.ResponseWriter) sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	return sseWriter{w}
}

// event writes one event. name may be empty for data-only events (the chat
// completions style); v is JSON-encoded as the data payload.
func (s sseWriter) event(name string, v any) {
	b, _ := json.Marshal(v)
	if name != "" {
		fmt.Fprintf(s.w, "event: %s\n", name)
	}
	fmt.Fprintf(s.w, "data: %s\n\n", b)
}

// raw writes a literal data line (e.g. "[DONE]").
func (s sseWriter) raw(data string) {
	fmt.Fprintf(s.w, "data: %s\n\n", data)
}

// writeJSON writes v as an application/json response.
func writeJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

// textOf renders a content field — a plain string or an array of parts with a
// "text" key (OpenAI {"type":"text"|"input_text"|"output_text"}, Anthropic
// {"type":"text"}) — as text.
func textOf(v any) string {
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

// asMaps returns the elements of a JSON array that are objects.
func asMaps(v any) []map[string]any {
	arr, _ := v.([]any)
	var out []map[string]any
	for _, raw := range arr {
		if m, ok := raw.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
