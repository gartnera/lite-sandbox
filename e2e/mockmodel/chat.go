package mockmodel

import (
	"net/http"
	"strconv"
	"strings"
)

// chatProtocol is the OpenAI chat-completions wire format
// (POST /v1/chat/completions): tools are {"type":"function","function":{...}},
// tool results are messages with role "tool".
type chatProtocol struct{}

func (chatProtocol) name() string { return "chat" }

func (chatProtocol) parse(req map[string]any) (map[string]bool, []string, string) {
	tools := map[string]bool{}
	for _, tool := range asMaps(req["tools"]) {
		fn, _ := tool["function"].(map[string]any)
		if name, ok := fn["name"].(string); ok {
			tools[name] = true
		}
	}
	var results, text []string
	for _, msg := range asMaps(req["messages"]) {
		content := textOf(msg["content"])
		text = append(text, content)
		if msg["role"] == "tool" {
			results = append(results, content)
		}
	}
	return tools, results, strings.Join(text, "\n")
}

func (chatProtocol) respond(w http.ResponseWriter, req map[string]any, r reply, modelID string) error {
	var delta map[string]any
	finish := "stop"
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		delta = map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"index": 0, "id": chatCallID(r.callIndex), "type": "function",
				"function": map[string]any{"name": r.call.Name, "arguments": args},
			}},
		}
		finish = "tool_calls"
	} else {
		delta = map[string]any{"role": "assistant", "content": r.text}
	}
	usage := map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}

	if !wantsStream(req) {
		msg := map[string]any{"role": "assistant", "content": delta["content"], "tool_calls": delta["tool_calls"]}
		return writeJSON(w, map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion", "created": 1, "model": modelID,
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   usage,
		})
	}

	sse := newSSE(w)
	chunk := func(d map[string]any, fin any, u any) {
		c := map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 1, "model": modelID,
			"choices": []any{map[string]any{"index": 0, "delta": d, "finish_reason": fin}},
		}
		if u != nil {
			c["usage"] = u
		}
		sse.event("", c)
	}
	chunk(delta, nil, nil)
	chunk(map[string]any{}, finish, usage)
	sse.raw("[DONE]")
	return nil
}

// chatCallID mints the call ID shared by the chat and responses adapters for
// the i-th scripted call.
func chatCallID(i int) string { return "call_" + strconv.Itoa(i+1) }
