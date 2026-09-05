package mockmodel

import (
	"net/http"
	"strconv"
	"strings"
)

// responsesProtocol is the OpenAI Responses API wire format (POST /v1/responses),
// the only protocol Codex speaks. Tools are {"type":"function","name":...} at
// the top level, or grouped under {"type":"namespace","name":ns,"tools":[...]}
// — which is how Codex exposes an MCP server's tools, under a namespace named
// mcp__<server> (non-alphanumerics replaced by "_"). A namespaced function is
// recorded in Turn.Tools as "<namespace>__<name>" — the canonical name Codex
// itself uses for it (e.g. in hook payloads: mcp__lite_sandbox__bash) — and a
// scripted call to that name is emitted as a function_call item carrying the
// namespace and the bare function name, which is how the API addresses it.
//
// The transcript is the flat "input" list, where tool results are
// {"type":"function_call_output","call_id":...,"output":...} items. Only the
// stateless flavor is served — every request must carry the whole transcript,
// which is how Codex uses it (store=false).
//
// Streaming follows the documented event sequence; Codex's parser requires
// response.created and response.completed (the latter carrying a response
// object with an id) and reads function calls from response.output_item.done.
type responsesProtocol struct{}

func (responsesProtocol) name() string { return "responses" }

func (responsesProtocol) parse(req map[string]any) (map[string]bool, []string, string) {
	tools := map[string]bool{}
	for name := range responsesTools(req) {
		tools[name] = true
	}

	var results, text []string
	if instructions, ok := req["instructions"].(string); ok && instructions != "" {
		text = append(text, instructions)
	}
	for _, item := range asMaps(req["input"]) {
		typ, _ := item["type"].(string)
		if typ == "" && item["role"] != nil {
			typ = "message" // the API lets plain {"role","content"} messages omit type
		}
		switch typ {
		case "function_call_output":
			output := textOf(item["output"])
			results = append(results, output)
			text = append(text, output)
		case "message":
			text = append(text, textOf(item["content"]))
		}
	}
	return tools, results, strings.Join(text, "\n")
}

func (responsesProtocol) respond(w http.ResponseWriter, req map[string]any, r reply, modelID string) error {
	var item map[string]any // the single output item
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		item = map[string]any{
			"type": "function_call", "id": "fc_" + strconv.Itoa(r.callIndex+1), "call_id": chatCallID(r.callIndex),
			"name": r.call.Name, "arguments": args, "status": "completed",
		}
		if ns, ok := responsesTools(req)[r.call.Name]; ok && ns != "" {
			item["namespace"] = ns
			item["name"] = strings.TrimPrefix(r.call.Name, ns+"__")
		}
	} else {
		item = map[string]any{
			"type": "message", "id": "msg_mock", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": r.text, "annotations": []any{}}},
		}
	}
	usage := map[string]any{
		"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
		"input_tokens_details":  map[string]any{"cached_tokens": 0},
		"output_tokens_details": map[string]any{"reasoning_tokens": 0},
	}
	response := func(status string, output []any) map[string]any {
		resp := map[string]any{
			"id": "resp_mock", "object": "response", "created_at": 1, "status": status,
			"model": modelID, "output": output,
		}
		if status == "completed" {
			resp["usage"] = usage
		}
		return resp
	}

	if !wantsStream(req) {
		return writeJSON(w, response("completed", []any{item}))
	}

	sse := newSSE(w)
	seq := 0
	emit := func(typ string, fields map[string]any) {
		ev := map[string]any{"type": typ, "sequence_number": seq}
		seq++
		for k, v := range fields {
			ev[k] = v
		}
		sse.event(typ, ev)
	}
	emit("response.created", map[string]any{"response": response("in_progress", []any{})})
	emit("response.in_progress", map[string]any{"response": response("in_progress", []any{})})

	itemID := item["id"]
	if r.call != nil {
		added := cloneMap(item)
		added["arguments"] = ""
		added["status"] = "in_progress"
		emit("response.output_item.added", map[string]any{"output_index": 0, "item": added})
		emit("response.function_call_arguments.delta", map[string]any{"item_id": itemID, "output_index": 0, "delta": item["arguments"]})
		emit("response.function_call_arguments.done", map[string]any{"item_id": itemID, "output_index": 0, "arguments": item["arguments"]})
	} else {
		added := cloneMap(item)
		added["content"] = []any{}
		added["status"] = "in_progress"
		part := map[string]any{"type": "output_text", "text": "", "annotations": []any{}}
		emit("response.output_item.added", map[string]any{"output_index": 0, "item": added})
		emit("response.content_part.added", map[string]any{"item_id": itemID, "output_index": 0, "content_index": 0, "part": part})
		emit("response.output_text.delta", map[string]any{"item_id": itemID, "output_index": 0, "content_index": 0, "delta": r.text})
		emit("response.output_text.done", map[string]any{"item_id": itemID, "output_index": 0, "content_index": 0, "text": r.text})
		done := cloneMap(part)
		done["text"] = r.text
		emit("response.content_part.done", map[string]any{"item_id": itemID, "output_index": 0, "content_index": 0, "part": done})
	}
	emit("response.output_item.done", map[string]any{"output_index": 0, "item": item})
	emit("response.completed", map[string]any{"response": response("completed", []any{item})})
	return nil
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// responsesTools maps every function name offered in the request to its
// namespace ("" for top-level functions). Namespaced functions are keyed by
// their canonical "<namespace>__<name>" form.
func responsesTools(req map[string]any) map[string]string {
	tools := map[string]string{}
	for _, tool := range asMaps(req["tools"]) {
		switch tool["type"] {
		case "function":
			if name, ok := tool["name"].(string); ok {
				tools[name] = ""
			}
		case "namespace":
			ns, _ := tool["name"].(string)
			for _, fn := range asMaps(tool["tools"]) {
				if name, ok := fn["name"].(string); ok && fn["type"] == "function" {
					tools[ns+"__"+name] = ns
				}
			}
		}
	}
	return tools
}
