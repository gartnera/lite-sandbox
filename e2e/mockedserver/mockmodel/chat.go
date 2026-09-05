package mockmodel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// chatProtocol is the OpenAI chat-completions wire format
// (POST /v1/chat/completions): tools are {"type":"function","function":{...}},
// tool results are messages with role "tool". Field names follow the API
// reference; only the fields the mock reads or must emit are modelled.
type chatProtocol struct{}

// chatRequest is the decoded request body.
type chatRequest struct {
	Model    string        `json:"model"`
	Stream   bool          `json:"stream"`
	Messages []chatMessage `json:"messages"`
	Tools    []chatTool    `json:"tools"`
}

type chatTool struct {
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

// chatMessage is one transcript message as sent by the client.
type chatMessage struct {
	Role       string `json:"role"`
	Content    text   `json:"content"`
	ToolCallID string `json:"tool_call_id"`
}

// chatAssistantMessage is the assistant message (or streamed delta) the mock
// emits: exactly one of Content or ToolCalls is set.
type chatAssistantMessage struct {
	Role      string         `json:"role,omitempty"`
	Content   *string        `json:"content"`
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
}

type chatToolCall struct {
	Index    int              `json:"index"`
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function chatFunctionCall `json:"function"`
}

type chatFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// chatCompletion is both the non-streaming response body (Object
// "chat.completion", choices carry Message) and a streamed chunk (Object
// "chat.completion.chunk", choices carry Delta).
type chatCompletion struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   *chatUsage   `json:"usage,omitempty"`
}

type chatChoice struct {
	Index        int                   `json:"index"`
	Message      *chatAssistantMessage `json:"message,omitempty"`
	Delta        *chatAssistantMessage `json:"delta,omitempty"`
	FinishReason *string               `json:"finish_reason"`
}

func (chatProtocol) name() string { return "chat" }

func (chatProtocol) parse(body []byte) (parsed, error) {
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return parsed{}, err
	}
	out := parsed{tools: map[string]bool{}, stream: req.Stream}
	for _, tool := range req.Tools {
		if tool.Function.Name != "" {
			out.tools[tool.Function.Name] = true
		}
	}
	var texts []string
	for _, msg := range req.Messages {
		texts = append(texts, string(msg.Content))
		if msg.Role == "tool" {
			out.results = append(out.results, string(msg.Content))
		}
	}
	out.text = strings.Join(texts, "\n")
	return out, nil
}

func (chatProtocol) respond(w http.ResponseWriter, req parsed, r reply, modelID string) error {
	msg := chatAssistantMessage{Role: "assistant"}
	finish := "stop"
	if r.call != nil {
		args, err := marshalArgs(r.call)
		if err != nil {
			return err
		}
		msg.ToolCalls = []chatToolCall{{
			Index: 0, ID: chatCallID(r.callIndex), Type: "function",
			Function: chatFunctionCall{Name: r.call.Name, Arguments: args},
		}}
		finish = "tool_calls"
	} else {
		msg.Content = &r.text
	}
	usage := &chatUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}

	if !req.stream {
		return writeJSON(w, chatCompletion{
			ID: "chatcmpl-mock", Object: "chat.completion", Created: 1, Model: modelID,
			Choices: []chatChoice{{Index: 0, Message: &msg, FinishReason: &finish}},
			Usage:   usage,
		})
	}

	sse := newSSE(w)
	chunk := func(delta *chatAssistantMessage, finish *string, usage *chatUsage) {
		sse.event("", chatCompletion{
			ID: "chatcmpl-mock", Object: "chat.completion.chunk", Created: 1, Model: modelID,
			Choices: []chatChoice{{Index: 0, Delta: delta, FinishReason: finish}},
			Usage:   usage,
		})
	}
	chunk(&msg, nil, nil)
	chunk(&chatAssistantMessage{}, &finish, usage)
	sse.raw("[DONE]")
	return nil
}

// chatCallID mints the call ID shared by the chat and responses adapters for
// the i-th scripted call.
func chatCallID(i int) string { return "call_" + strconv.Itoa(i+1) }
