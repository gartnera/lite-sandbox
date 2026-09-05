package mockmodel

import (
	"encoding/json"
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

// noAnnotations is the empty annotations list every output_text part carries.
var noAnnotations = []json.RawMessage{}

// responsesRequest is the decoded request body.
type responsesRequest struct {
	Model        string               `json:"model"`
	Stream       bool                 `json:"stream"`
	Instructions string               `json:"instructions"`
	Input        []responsesInputItem `json:"input"`
	Tools        []responsesTool      `json:"tools"`
}

// responsesTool is one entry of the tools list: a function, or a namespace
// grouping functions (Tools). Other tool types (web_search, ...) decode too and
// are ignored.
type responsesTool struct {
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Tools []responsesTool `json:"tools"`
}

// responsesInputItem is one transcript item. The API's item types share a flat
// shape here: Type "message" (or omitted, for plain {"role","content"} items)
// with Role and Content; Type "function_call_output" with CallID and Output;
// other types (function_call, reasoning, ...) decode but carry nothing the mock
// reads.
type responsesInputItem struct {
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content text   `json:"content"`
	CallID  string `json:"call_id"`
	Output  text   `json:"output"`
}

// responsesOutputItem is an output item: responsesFunctionCall or
// responsesMessage. The marker method keeps the union closed at compile time;
// values marshal as their concrete type.
type responsesOutputItem interface{ isResponsesOutputItem() }

func (responsesFunctionCall) isResponsesOutputItem() {}
func (responsesMessage) isResponsesOutputItem()      {}

// responsesFunctionCall is a function_call output item.
type responsesFunctionCall struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Arguments string `json:"arguments"`
	Status    string `json:"status"`
}

// responsesMessage is an assistant message output item.
type responsesMessage struct {
	Type    string                `json:"type"`
	ID      string                `json:"id"`
	Role    string                `json:"role"`
	Status  string                `json:"status"`
	Content []responsesOutputText `json:"content"`
}

type responsesOutputText struct {
	Type        string            `json:"type"`
	Text        string            `json:"text"`
	Annotations []json.RawMessage `json:"annotations"`
}

type responsesUsage struct {
	InputTokens        int `json:"input_tokens"`
	OutputTokens       int `json:"output_tokens"`
	TotalTokens        int `json:"total_tokens"`
	InputTokensDetails struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

// responsesResponse is the response object: the non-streaming body, and the
// payload of the response.created / response.completed events.
type responsesResponse struct {
	ID        string                `json:"id"`
	Object    string                `json:"object"`
	CreatedAt int64                 `json:"created_at"`
	Status    string                `json:"status"`
	Model     string                `json:"model"`
	Output    []responsesOutputItem `json:"output"`
	Usage     *responsesUsage       `json:"usage,omitempty"`
}

// responsesEvent is one streamed event; which fields are set depends on Type.
type responsesEvent struct {
	Type           string               `json:"type"`
	SequenceNumber int                  `json:"sequence_number"`
	Response       *responsesResponse   `json:"response,omitempty"`
	OutputIndex    *int                 `json:"output_index,omitempty"`
	Item           responsesOutputItem  `json:"item,omitempty"`
	ItemID         string               `json:"item_id,omitempty"`
	ContentIndex   *int                 `json:"content_index,omitempty"`
	Part           *responsesOutputText `json:"part,omitempty"`
	Delta          string               `json:"delta,omitempty"`
	Text           string               `json:"text,omitempty"`
	Arguments      string               `json:"arguments,omitempty"`
}

func (responsesProtocol) name() string { return "responses" }

func (responsesProtocol) parse(body []byte) (parsed, error) {
	var req responsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return parsed{}, err
	}
	out := parsed{tools: map[string]bool{}, stream: req.Stream, namespaces: req.namespaces()}
	for name := range out.namespaces {
		out.tools[name] = true
	}
	var texts []string
	if req.Instructions != "" {
		texts = append(texts, req.Instructions)
	}
	for _, item := range req.Input {
		switch {
		case item.Type == "function_call_output":
			out.results = append(out.results, string(item.Output))
			texts = append(texts, string(item.Output))
		case item.Type == "message" || (item.Type == "" && item.Role != ""):
			texts = append(texts, string(item.Content))
		}
	}
	out.text = strings.Join(texts, "\n")
	return out, nil
}

// namespaces maps every function name offered in the request to its namespace
// ("" for top-level functions). Namespaced functions are keyed by their
// canonical "<namespace>__<name>" form.
func (req *responsesRequest) namespaces() map[string]string {
	tools := map[string]string{}
	for _, tool := range req.Tools {
		switch tool.Type {
		case "function":
			tools[tool.Name] = ""
		case "namespace":
			for _, fn := range tool.Tools {
				if fn.Type == "function" {
					tools[tool.Name+"__"+fn.Name] = tool.Name
				}
			}
		}
	}
	return tools
}

func (responsesProtocol) respond(w http.ResponseWriter, req parsed, r reply, modelID string) error {
	// The one output item of this turn, plus its in-progress form for the
	// output_item.added event.
	var item, added responsesOutputItem
	var itemID string
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		fc := responsesFunctionCall{
			Type: "function_call", ID: "fc_" + strconv.Itoa(r.callIndex+1), CallID: chatCallID(r.callIndex),
			Name: r.call.Name, Arguments: args, Status: "completed",
		}
		if ns, name, ok := splitNamespace(r.call.Name, req.namespaces); ok {
			fc.Namespace, fc.Name = ns, name
		}
		started := fc
		started.Arguments, started.Status = "", "in_progress"
		item, added, itemID = fc, started, fc.ID
	} else {
		msg := responsesMessage{
			Type: "message", ID: "msg_mock", Role: "assistant", Status: "completed",
			Content: []responsesOutputText{{Type: "output_text", Text: r.text, Annotations: noAnnotations}},
		}
		started := msg
		started.Content, started.Status = []responsesOutputText{}, "in_progress"
		item, added, itemID = msg, started, msg.ID
	}
	response := func(status string, output []responsesOutputItem) *responsesResponse {
		resp := &responsesResponse{ID: "resp_mock", Object: "response", CreatedAt: 1, Status: status, Model: modelID, Output: output}
		if status == "completed" {
			resp.Usage = &responsesUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}
		}
		return resp
	}

	if !req.stream {
		return writeJSON(w, response("completed", []responsesOutputItem{item}))
	}

	sse := newSSE(w)
	seq := 0
	emit := func(ev responsesEvent) {
		ev.SequenceNumber = seq
		seq++
		sse.event(ev.Type, ev)
	}
	zero := 0
	emit(responsesEvent{Type: "response.created", Response: response("in_progress", []responsesOutputItem{})})
	emit(responsesEvent{Type: "response.in_progress", Response: response("in_progress", []responsesOutputItem{})})
	emit(responsesEvent{Type: "response.output_item.added", OutputIndex: &zero, Item: added})
	if fc, ok := item.(responsesFunctionCall); ok {
		emit(responsesEvent{Type: "response.function_call_arguments.delta", ItemID: itemID, OutputIndex: &zero, Delta: fc.Arguments})
		emit(responsesEvent{Type: "response.function_call_arguments.done", ItemID: itemID, OutputIndex: &zero, Arguments: fc.Arguments})
	} else {
		part := responsesOutputText{Type: "output_text", Text: "", Annotations: noAnnotations}
		emit(responsesEvent{Type: "response.content_part.added", ItemID: itemID, OutputIndex: &zero, ContentIndex: &zero, Part: &part})
		emit(responsesEvent{Type: "response.output_text.delta", ItemID: itemID, OutputIndex: &zero, ContentIndex: &zero, Delta: r.text})
		emit(responsesEvent{Type: "response.output_text.done", ItemID: itemID, OutputIndex: &zero, ContentIndex: &zero, Text: r.text})
		done := part
		done.Text = r.text
		emit(responsesEvent{Type: "response.content_part.done", ItemID: itemID, OutputIndex: &zero, ContentIndex: &zero, Part: &done})
	}
	emit(responsesEvent{Type: "response.output_item.done", OutputIndex: &zero, Item: item})
	emit(responsesEvent{Type: "response.completed", Response: response("completed", []responsesOutputItem{item})})
	return nil
}

// splitNamespace resolves a scripted call name against the request's tools:
// when it names a namespaced function ("<namespace>__<name>"), it returns the
// namespace and bare name the function_call item must carry.
func splitNamespace(callName string, namespaces map[string]string) (ns, name string, ok bool) {
	ns, ok = namespaces[callName]
	if !ok || ns == "" {
		return "", "", false
	}
	return ns, strings.TrimPrefix(callName, ns+"__"), true
}
