// Package hook models the Claude Code PreToolUse hook protocol: the JSON
// event delivered on stdin and the decision document written to stdout.
//
// The event is fully parsed into typed structs so callers can reason about
// exactly what a tool is being asked to do without poking at untyped maps.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
)

// EventName identifies which lifecycle hook fired. We only handle PreToolUse,
// but the field is modeled so unexpected events are reported clearly.
type EventName string

const (
	EventPreToolUse EventName = "PreToolUse"
)

// PermissionMode is the session's current permission posture.
type PermissionMode string

const (
	PermissionModeDefault           PermissionMode = "default"
	PermissionModePlan              PermissionMode = "plan"
	PermissionModeAcceptEdits       PermissionMode = "acceptEdits"
	PermissionModeBypassPermissions PermissionMode = "bypassPermissions"
)

// Event is the fully parsed PreToolUse payload Claude Code sends on stdin.
//
// RawToolInput holds the original JSON for the tool arguments; ToolInput is the
// decoded, tool-specific view. RawToolInput is always populated; ToolInput is
// populated when the tool is one we model.
type Event struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path"`
	CWD            string         `json:"cwd"`
	PermissionMode PermissionMode `json:"permission_mode"`
	HookEventName  EventName      `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`

	// AgentID and AgentType are set when the call originates from a subagent.
	AgentID   string `json:"agent_id,omitempty"`
	AgentType string `json:"agent_type,omitempty"`

	// RawToolInput is the verbatim tool_input object, retained so callers can
	// inspect fields we do not explicitly model.
	RawToolInput json.RawMessage `json:"tool_input"`

	// ToolInput is the typed decoding of RawToolInput. Its concrete type is
	// determined by ToolName (see parseToolInput). nil for unmodeled tools.
	ToolInput ToolInput `json:"-"`
}

// ToolInput is implemented by every typed tool argument struct. Tool reports
// the canonical tool name and Describe returns a short human/AI readable
// summary of the requested action (used in deny messages and logs).
type ToolInput interface {
	Tool() string
	Describe() string
}

// ParseEvent reads and decodes a PreToolUse event from r, including the
// tool-specific input. A decode error on the outer envelope is fatal; a decode
// error on the tool input is returned but the Event is still usable via
// RawToolInput.
func ParseEvent(r io.Reader) (*Event, error) {
	var e Event
	dec := json.NewDecoder(r)
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("decode hook event: %w", err)
	}
	if err := e.parseToolInput(); err != nil {
		// Non-fatal: callers can still match on tool name / raw input.
		return &e, fmt.Errorf("decode tool_input for %q: %w", e.ToolName, err)
	}
	return &e, nil
}

// parseToolInput decodes RawToolInput into the concrete type for ToolName.
func (e *Event) parseToolInput() error {
	factory, ok := toolInputFactories[e.ToolName]
	if !ok {
		// Unmodeled tool (e.g. an MCP tool). Leave ToolInput nil; callers fall
		// back to RawToolInput.
		return nil
	}
	in := factory()
	if len(e.RawToolInput) > 0 {
		if err := json.Unmarshal(e.RawToolInput, in); err != nil {
			return err
		}
	}
	e.ToolInput = in
	return nil
}
