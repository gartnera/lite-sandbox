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
	return writeJSON(w, d)
}

// PermissionBehavior is the verdict a PermissionRequest hook returns.
type PermissionBehavior string

const (
	// BehaviorAllow grants the permission the user was about to be asked for.
	// Claude Code still applies matching deny and ask rules.
	BehaviorAllow PermissionBehavior = "allow"
)

// permissionRequestDecision is the decision object nested in a
// PermissionRequest response.
type permissionRequestDecision struct {
	Behavior PermissionBehavior `json:"behavior"`
}

// permissionRequestOutput is the PermissionRequest-specific payload.
type permissionRequestOutput struct {
	HookEventName EventName                 `json:"hookEventName"`
	Decision      permissionRequestDecision `json:"decision"`
}

// PermissionRequestDecision is the document a PermissionRequest hook writes
// to stdout (exit 0) to answer the prompt on the user's behalf.
type PermissionRequestDecision struct {
	HookSpecificOutput permissionRequestOutput `json:"hookSpecificOutput"`
}

// NewPermissionRequestDecision builds a PermissionRequest decision.
func NewPermissionRequestDecision(b PermissionBehavior) *PermissionRequestDecision {
	return &PermissionRequestDecision{
		HookSpecificOutput: permissionRequestOutput{
			HookEventName: EventPermissionRequest,
			Decision:      permissionRequestDecision{Behavior: b},
		},
	}
}

// Write emits the decision as JSON to w.
func (d *PermissionRequestDecision) Write(w io.Writer) error {
	return writeJSON(w, d)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
