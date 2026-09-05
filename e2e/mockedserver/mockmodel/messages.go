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

// messagesRequest is the decoded request body.
type messagesRequest struct {
	Model    string             `json:"model"`
	Stream   bool               `json:"stream"`
	System   text               `json:"system"`
	Messages []anthropicMessage `json:"messages"`
	Tools    []anthropicTool    `json:"tools"`
}

type anthropicTool struct {
	Name string `json:"name"`
}

// anthropicMessage is one transcript message. Content is a string or an array
// of blocks on the wire; anthropicBlocks normalizes both.
type anthropicMessage struct {
	Role    string          `json:"role"`
	Content anthropicBlocks `json:"content"`
}

// anthropicBlocks decodes message content that is either a plain string (one
// text block) or an array of content blocks.
type anthropicBlocks []anthropicInputBlock

func (b *anthropicBlocks) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*b = anthropicBlocks{{Type: "text", Text: str}}
		return nil
	}
	var blocks []anthropicInputBlock
	if err := json.Unmarshal(data, &blocks); err != nil {
		return err
	}
	*b = blocks
	return nil
}

// anthropicInputBlock is one content block as sent by the client: Type "text"
// with Text, "tool_result" with ToolUseID and Content (string or blocks), or
// others (tool_use, image, ...) that decode but carry nothing the mock reads.
type anthropicInputBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	ToolUseID string `json:"tool_use_id"`
	Content   text   `json:"content"`
}

// anthropicBlock is a content block the mock emits: anthropicTextBlock or
// anthropicToolUseBlock. The marker method keeps the union closed at compile
// time; values marshal as their concrete type.
type anthropicBlock interface{ isAnthropicBlock() }

func (anthropicTextBlock) isAnthropicBlock()    {}
func (anthropicToolUseBlock) isAnthropicBlock() {}

// anthropicDelta is the payload of a streamed delta event:
// anthropicContentDelta (content_block_delta) or anthropicMessageDelta
// (message_delta).
type anthropicDelta interface{ isAnthropicDelta() }

func (anthropicContentDelta) isAnthropicDelta() {}
func (anthropicMessageDelta) isAnthropicDelta() {}

type anthropicTextBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicToolUseBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens"`
}

// anthropicResponse is the message object: the non-streaming body, and the
// payload of the message_start event.
type anthropicResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Model        string           `json:"model"`
	Content      []anthropicBlock `json:"content"`
	StopReason   *string          `json:"stop_reason"`
	StopSequence *string          `json:"stop_sequence"`
	Usage        *anthropicUsage  `json:"usage,omitempty"`
}

// anthropicEvent is one streamed event; which fields are set depends on Type.
type anthropicEvent struct {
	Type         string             `json:"type"`
	Message      *anthropicResponse `json:"message,omitempty"`
	Index        *int               `json:"index,omitempty"`
	ContentBlock anthropicBlock     `json:"content_block,omitempty"`
	Delta        anthropicDelta     `json:"delta,omitempty"`
	Usage        *anthropicUsage    `json:"usage,omitempty"`
}

type anthropicContentDelta struct {
	Type        string `json:"type"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
}

type anthropicMessageDelta struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

func (messagesProtocol) name() string { return "messages" }

func (messagesProtocol) parse(body []byte) (parsed, error) {
	var req messagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return parsed{}, err
	}
	out := parsed{tools: map[string]bool{}, stream: req.Stream}
	for _, tool := range req.Tools {
		if tool.Name != "" {
			out.tools[tool.Name] = true
		}
	}
	texts := []string{string(req.System)}
	for _, msg := range req.Messages {
		for _, block := range msg.Content {
			switch block.Type {
			case "tool_result":
				texts = append(texts, string(block.Content))
				if msg.Role == "user" {
					out.results = append(out.results, string(block.Content))
				}
			case "text":
				texts = append(texts, block.Text)
			}
		}
	}
	out.text = strings.Join(texts, "\n")
	return out, nil
}

func (messagesProtocol) respond(w http.ResponseWriter, req parsed, r reply, modelID string) error {
	// The one content block of this turn, plus its empty form for the
	// content_block_start event and the delta that fills it.
	var block, started anthropicBlock
	var delta anthropicContentDelta
	stop := "end_turn"
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		id := "toolu_" + strconv.Itoa(r.callIndex+1)
		block = anthropicToolUseBlock{Type: "tool_use", ID: id, Name: r.call.Name, Input: json.RawMessage(args)}
		started = anthropicToolUseBlock{Type: "tool_use", ID: id, Name: r.call.Name, Input: json.RawMessage("{}")}
		delta = anthropicContentDelta{Type: "input_json_delta", PartialJSON: args}
		stop = "tool_use"
	} else {
		block = anthropicTextBlock{Type: "text", Text: r.text}
		started = anthropicTextBlock{Type: "text", Text: ""}
		delta = anthropicContentDelta{Type: "text_delta", Text: r.text}
	}
	usage := &anthropicUsage{InputTokens: 1, OutputTokens: 1}

	if !req.stream {
		return writeJSON(w, anthropicResponse{
			ID: "msg_mock", Type: "message", Role: "assistant", Model: modelID,
			Content: []anthropicBlock{block}, StopReason: &stop, Usage: usage,
		})
	}

	sse := newSSE(w)
	emit := func(ev anthropicEvent) { sse.event(ev.Type, ev) }
	zero := 0
	emit(anthropicEvent{Type: "message_start", Message: &anthropicResponse{
		ID: "msg_mock", Type: "message", Role: "assistant", Model: modelID, Content: []anthropicBlock{}, Usage: usage,
	}})
	emit(anthropicEvent{Type: "content_block_start", Index: &zero, ContentBlock: started})
	emit(anthropicEvent{Type: "content_block_delta", Index: &zero, Delta: delta})
	emit(anthropicEvent{Type: "content_block_stop", Index: &zero})
	emit(anthropicEvent{Type: "message_delta", Delta: anthropicMessageDelta{StopReason: stop}, Usage: &anthropicUsage{OutputTokens: 1}})
	emit(anthropicEvent{Type: "message_stop"})
	return nil
}
