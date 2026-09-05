package mockmodel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// messagesProtocol is the Anthropic Messages API wire format (POST /v1/messages),
// which Claude Code speaks. Tools are {"name":...,"input_schema":...}; tool
// results are {"type":"tool_result"} blocks inside user messages.
type messagesProtocol struct{}

func (messagesProtocol) name() string { return "messages" }

func (messagesProtocol) parse(req map[string]any) (map[string]bool, []string, string) {
	tools := map[string]bool{}
	for _, tool := range asMaps(req["tools"]) {
		if name, ok := tool["name"].(string); ok {
			tools[name] = true
		}
	}
	var results []string
	text := []string{textOf(req["system"])}
	for _, msg := range asMaps(req["messages"]) {
		if str, ok := msg["content"].(string); ok {
			text = append(text, str)
			continue
		}
		for _, block := range asMaps(msg["content"]) {
			switch block["type"] {
			case "tool_result":
				content := textOf(block["content"])
				text = append(text, content)
				if msg["role"] == "user" {
					results = append(results, content)
				}
			default:
				if str, ok := block["text"].(string); ok {
					text = append(text, str)
				}
			}
		}
	}
	return tools, results, strings.Join(text, "\n")
}

func (messagesProtocol) respond(w http.ResponseWriter, req map[string]any, r reply, modelID string) error {
	var block map[string]any
	stop := "end_turn"
	var partialJSON string
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		partialJSON = args
		block = map[string]any{"type": "tool_use", "id": "toolu_" + strconv.Itoa(r.callIndex+1), "name": r.call.Name, "input": json.RawMessage(args)}
		stop = "tool_use"
	} else {
		block = map[string]any{"type": "text", "text": r.text}
	}
	usage := map[string]any{"input_tokens": 1, "output_tokens": 1}

	if !wantsStream(req) {
		return writeJSON(w, map[string]any{
			"id": "msg_mock", "type": "message", "role": "assistant", "model": modelID,
			"content": []any{block}, "stop_reason": stop, "stop_sequence": nil, "usage": usage,
		})
	}

	sse := newSSE(w)
	sse.event("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": "msg_mock", "type": "message", "role": "assistant", "model": modelID,
		"content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": usage,
	}})
	if r.call != nil {
		start := cloneMap(block)
		start["input"] = map[string]any{}
		sse.event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": start})
		sse.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": partialJSON}})
	} else {
		sse.event("content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""}})
		sse.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "text_delta", "text": r.text}})
	}
	sse.event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	sse.event("message_delta", map[string]any{"type": "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": 1}})
	sse.event("message_stop", map[string]any{"type": "message_stop"})
	return nil
}
