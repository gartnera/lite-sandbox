package mockmodel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func post(t *testing.T, url string, body map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d: %s", url, resp.StatusCode, out.String())
	}
	return out.String()
}

// client models how one harness family speaks to the mock: how it declares a
// tool, how it appends a tool result to the transcript, and how it reads a tool
// call / text out of the reply.
type client struct {
	path       string
	tool       func(name string) any
	request    func(stream bool, tools []any, transcript []any) map[string]any
	result     func(callIdx int, content any) any
	hasCall    func(body, name, args string) bool
	hasText    func(body, text string) bool
	sseMarkers []string
}

var clients = map[string]client{
	"chat": {
		path: "/chat/completions",
		tool: func(name string) any {
			return map[string]any{"type": "function", "function": map[string]any{"name": name, "parameters": map[string]any{}}}
		},
		request: func(stream bool, tools []any, transcript []any) map[string]any {
			req := map[string]any{"stream": stream, "messages": transcript}
			if tools != nil {
				req["tools"] = tools
			}
			return req
		},
		result: func(i int, content any) any {
			return map[string]any{"role": "tool", "tool_call_id": chatCallID(i), "content": content}
		},
		hasCall: func(body, name, args string) bool {
			return strings.Contains(body, `"tool_calls"`) && strings.Contains(body, `"name":"`+name+`"`) && strings.Contains(body, jsonEscape(args))
		},
		hasText: func(body, text string) bool {
			return strings.Contains(body, `"content":`+quote(text)) && !strings.Contains(body, `"tool_calls":[`)
		},
		sseMarkers: []string{"data: {", "data: [DONE]"},
	},
	"responses": {
		path: "/responses",
		tool: func(name string) any {
			return map[string]any{"type": "function", "name": name, "parameters": map[string]any{}}
		},
		request: func(stream bool, tools []any, transcript []any) map[string]any {
			req := map[string]any{"stream": stream, "input": transcript, "store": false}
			if tools != nil {
				req["tools"] = tools
			}
			return req
		},
		result: func(i int, content any) any {
			return map[string]any{"type": "function_call_output", "call_id": chatCallID(i), "output": content}
		},
		hasCall: func(body, name, args string) bool {
			return strings.Contains(body, `"type":"function_call"`) && strings.Contains(body, `"name":"`+name+`"`) && strings.Contains(body, jsonEscape(args))
		},
		hasText: func(body, text string) bool {
			return strings.Contains(body, `"type":"output_text"`) && strings.Contains(body, quote(text)) && !strings.Contains(body, `"function_call"`)
		},
		sseMarkers: []string{"event: response.created", "event: response.output_item.done", "event: response.completed"},
	},
	"messages": {
		path: "/messages",
		tool: func(name string) any {
			return map[string]any{"name": name, "input_schema": map[string]any{"type": "object"}}
		},
		request: func(stream bool, tools []any, transcript []any) map[string]any {
			req := map[string]any{"stream": stream, "messages": transcript, "max_tokens": 100}
			if tools != nil {
				req["tools"] = tools
			}
			return req
		},
		result: func(i int, content any) any {
			return map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": content},
			}}
		},
		hasCall: func(body, name, args string) bool {
			return strings.Contains(body, `"type":"tool_use"`) && strings.Contains(body, `"name":"`+name+`"`) && (strings.Contains(body, args) || strings.Contains(body, jsonEscape(args)))
		},
		hasText: func(body, text string) bool {
			return strings.Contains(body, quote(text)) && !strings.Contains(body, `"tool_use"`)
		},
		sseMarkers: []string{"event: message_start", "event: content_block_delta", "event: message_stop"},
	},
}

func quote(s string) string      { b, _ := json.Marshal(s); return string(b) }
func jsonEscape(s string) string { q := quote(s); return q[1 : len(q)-1] }

// TestScriptedConversation walks a full conversation — a side request, two
// scripted tool calls, and the final answer — on every protocol, streaming and
// not, and checks the normalized Turn records come out identical.
func TestScriptedConversation(t *testing.T) {
	for proto, c := range clients {
		for _, stream := range []bool{false, true} {
			t.Run(proto+"/"+map[bool]string{false: "json", true: "sse"}[stream], func(t *testing.T) {
				srv := Start(Script{
					ToolCalls: []ToolCall{
						{Name: "x_bash", Arguments: map[string]string{"command": "false"}},
						{Name: "x_bash", Arguments: map[string]string{"command": "echo hi"}},
					},
					FinalText: func(results []string) string { return "done: " + strings.Join(results, "|") },
					SideText:  "Title",
				})
				defer srv.Close()
				url := srv.BaseURL + c.path
				tools := []any{c.tool("x_bash")}

				// Side request (no tools) gets the canned text and consumes no tool call.
				body := post(t, url, c.request(stream, nil, []any{}))
				if !c.hasText(body, "Title") {
					t.Errorf("side request got wrong reply: %s", body)
				}

				// Turn 1: first tool call.
				transcript := []any{map[string]any{"role": "user", "content": "go"}}
				body = post(t, url, c.request(stream, tools, transcript))
				if !c.hasCall(body, "x_bash", `{"command":"false"}`) {
					t.Errorf("turn 1 should issue the first tool call: %s", body)
				}
				if stream {
					for _, m := range c.sseMarkers {
						if !strings.Contains(body, m) {
							t.Errorf("streaming reply missing %q: %s", m, body)
						}
					}
				} else if !strings.HasPrefix(strings.TrimSpace(body), "{") {
					t.Errorf("non-streaming reply is not a JSON object: %s", body)
				}

				// Turn 2: one result present → second tool call.
				transcript = append(transcript, c.result(0, "error"))
				body = post(t, url, c.request(stream, tools, transcript))
				if !c.hasCall(body, "x_bash", `{"command":"echo hi"}`) {
					t.Errorf("turn 2 should issue the second tool call: %s", body)
				}

				// Turn 3: both results present (one as content parts) → final text.
				transcript = append(transcript, c.result(1, []any{map[string]any{"type": "text", "text": "hi"}}))
				body = post(t, url, c.request(stream, tools, transcript))
				if !c.hasText(body, "done: error|hi") {
					t.Errorf("turn 3 should be the final answer: %s", body)
				}

				if got := len(srv.Turns()); got != 4 {
					t.Errorf("expected 4 recorded turns, got %d", got)
				}
				agent := srv.AgentTurns()
				if len(agent) != 3 {
					t.Fatalf("expected 3 agent turns, got %d", len(agent))
				}
				if agent[0].Protocol != proto {
					t.Errorf("Protocol = %q, want %q", agent[0].Protocol, proto)
				}
				if !agent[0].Tools["x_bash"] {
					t.Errorf("Tools missing offered tool: %v", agent[0].Tools)
				}
				if got := agent[2].ToolResults; strings.Join(got, ",") != "error,hi" {
					t.Errorf("ToolResults = %v", got)
				}
			})
		}
	}
}

// TestStreamsDecode checks each streamed reply is well-formed SSE whose data
// payloads are valid JSON.
func TestStreamsDecode(t *testing.T) {
	for proto, c := range clients {
		t.Run(proto, func(t *testing.T) {
			srv := Start(Script{ToolCalls: []ToolCall{{Name: "x", Arguments: map[string]any{"a": 1}}}})
			defer srv.Close()
			body := post(t, srv.BaseURL+c.path, c.request(true, []any{c.tool("x")}, []any{}))
			n := 0
			for _, line := range strings.Split(body, "\n") {
				if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
					continue
				}
				var v map[string]any
				if err := json.Unmarshal([]byte(line[len("data: "):]), &v); err != nil {
					t.Errorf("bad data payload %q: %v", line, err)
				}
				n++
			}
			if n == 0 {
				t.Errorf("no data events in %s", body)
			}
		})
	}
}

func TestUnknownPathIs404(t *testing.T) {
	srv := Start(Script{})
	defer srv.Close()
	for _, req := range []struct{ method, path string }{{"GET", "/models"}, {"GET", "/messages"}, {"POST", "/embeddings"}} {
		r, _ := http.NewRequest(req.method, srv.BaseURL+req.path, nil)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: expected 404, got %d", req.method, req.path, resp.StatusCode)
		}
	}
}
