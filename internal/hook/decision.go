package hook

import (
	"encoding/json"
	"io"
)

// PermissionDecision is the verdict a PreToolUse hook returns.
type PermissionDecision string

const (
	// DecisionAllow permits the tool call and skips the permission prompt.
	DecisionAllow PermissionDecision = "allow"
	// DecisionDeny blocks the tool call; the reason is shown to the model.
	DecisionDeny PermissionDecision = "deny"
	// DecisionAsk forces the interactive permission prompt for the user.
	DecisionAsk PermissionDecision = "ask"
)

// hookSpecificOutput is the PreToolUse-specific payload nested in the response.
type hookSpecificOutput struct {
	HookEventName            EventName          `json:"hookEventName"`
	PermissionDecision       PermissionDecision `json:"permissionDecision"`
	PermissionDecisionReason string             `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string             `json:"additionalContext,omitempty"`
}

// Decision is the document a PreToolUse hook writes to stdout (exit 0).
type Decision struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// NewDecision builds a PreToolUse decision with the given verdict and reason.
// The reason is what the model reads when a call is denied, so it should
// explain what was wrong and what to do instead.
func NewDecision(d PermissionDecision, reason string) *Decision {
	return &Decision{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            EventPreToolUse,
			PermissionDecision:       d,
			PermissionDecisionReason: reason,
		},
	}
}

// WithContext attaches additional context injected into the model's transcript.
func (d *Decision) WithContext(ctx string) *Decision {
	d.HookSpecificOutput.AdditionalContext = ctx
	return d
}

// Write emits the decision as JSON to w.
func (d *Decision) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
