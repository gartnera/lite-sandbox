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
	// Text is all the text the model was shown on this request — system or
	// developer instructions, every message, and tool results — so tests can
	// check that something reached the model (e.g. the installer's directive
	// from CLAUDE.md / AGENTS.md / CRUSH.md) without knowing where the harness
	// put it.
	Text string
	// Final reports that the mock answered this turn with FinalText, i.e. every
	// scripted call had a result in the transcript.
	Final bool
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

// parsed is what an adapter extracts from a request body: the normalized Turn
// fields plus what respond needs to answer in kind.
type parsed struct {
	tools   map[string]bool
	results []string
	text    string
	// stream reports whether the client asked for a streamed reply.
	stream bool
	// namespaces maps an offered function name to its namespace, for protocols
	// that group tools (Responses); "" for top-level functions.
	namespaces map[string]string
}

// protocol is one wire-format adapter. Each decodes its request into typed
// structs (see chat.go, responses.go, messages.go) and encodes typed responses.
type protocol interface {
	// name identifies the protocol in Turn.Protocol.
	name() string
	// parse decodes a request body.
	parse(body []byte) (parsed, error)
	// respond writes r in this protocol's response format, streaming if req
	// asked for it.
	respond(w http.ResponseWriter, req parsed, r reply, modelID string) error
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
	req, err := p.parse(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("mock: bad %s request: %v", p.name(), err), http.StatusBadRequest)
		return
	}
	turn := Turn{Protocol: p.name(), Tools: req.tools, ToolResults: req.results, Text: req.text}
	results := req.results

	var rep reply
	switch {
	case !turn.IsAgentTurn():
		rep.text = s.script.SideText
	case len(results) < len(s.script.ToolCalls) && s.agentTurnCount() < s.maxAgentTurns():
		rep.call = &s.script.ToolCalls[len(results)]
		rep.callIndex = len(results)
	case len(results) < len(s.script.ToolCalls):
		// The harness keeps asking without ever feeding back a result for the
		// pending call (its result shape may be one parse() does not recognize).
		// Answer with a self-describing text so the run ends now and the test
		// fails on its assertions, instead of looping until a timeout.
		rep.text = fmt.Sprintf("mock: giving up after %d agent turns: the harness never returned a result for scripted call %d (%s); results so far: %q",
			s.agentTurnCount(), len(results)+1, s.script.ToolCalls[len(results)].Name, results)
	default:
		rep.text = s.script.FinalText(results)
		turn.Final = true
	}

	s.mu.Lock()
	s.turns = append(s.turns, turn)
	s.mu.Unlock()

	// respond only fails before writing anything (bad scripted arguments), so a
	// plain error response is still possible here.
	if err := p.respond(w, req, rep, s.ModelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// agentTurnCount is the number of agent turns recorded so far.
func (s *Server) agentTurnCount() int { return len(s.AgentTurns()) }

// maxAgentTurns bounds a conversation: a few retries per scripted call plus
// slack for the answer. Beyond it the mock stops issuing calls (see ServeHTTP).
func (s *Server) maxAgentTurns() int { return 3*len(s.script.ToolCalls) + 5 }

// AnswerTurn returns the agent turn the mock answered with FinalText — the
// request carrying the complete transcript — or the last agent turn if it
// never answered.
func (s *Server) AnswerTurn() (Turn, bool) {
	turns := s.AgentTurns()
	for i := len(turns) - 1; i >= 0; i-- {
		if turns[i].Final {
			return turns[i], true
		}
	}
	if len(turns) == 0 {
		return Turn{}, false
	}
	return turns[len(turns)-1], false
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

// text is a content field that the wire may carry either as a plain string or
// as an array of typed parts — {"type":"text"|"input_text"|"output_text",
// "text":...} (OpenAI) or {"type":"text","text":...} (Anthropic) — and that
// the mock only ever needs as text. It decodes to the parts' text joined with
// newlines; parts without text (images, nested tool_use blocks, ...) are
// skipped.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*t = text(str)
		return nil
	}
	if string(b) == "null" {
		*t = ""
		return nil
	}
	var parts []struct {
		Text *string `json:"text"`
	}
	if err := json.Unmarshal(b, &parts); err != nil {
		return fmt.Errorf("content is neither a string nor an array of parts: %w", err)
	}
	var texts []string
	for _, p := range parts {
		if p.Text != nil {
			texts = append(texts, *p.Text)
		}
	}
	*t = text(strings.Join(texts, "\n"))
	return nil
}

// sseWriter emits server-sent events.
type sseWriter struct{ w http.ResponseWriter }

func newSSE(w http.ResponseWriter) sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	return sseWriter{w}
}

// event writes one event and flushes it, so clients see events arrive
// incrementally as they would from a real streaming endpoint. name may be
// empty for data-only events (the chat completions style); v is JSON-encoded
// as the data payload.
func (s sseWriter) event(name string, v any) {
	b, _ := json.Marshal(v)
	if name != "" {
		fmt.Fprintf(s.w, "event: %s\n", name)
	}
	fmt.Fprintf(s.w, "data: %s\n\n", b)
	s.flush()
}

// raw writes a literal data line (e.g. "[DONE]") and flushes it.
func (s sseWriter) raw(data string) {
	fmt.Fprintf(s.w, "data: %s\n\n", data)
	s.flush()
}

func (s sseWriter) flush() {
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

// writeJSON writes v as an application/json response.
func writeJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}
