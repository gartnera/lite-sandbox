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

// grokOutput is the hook output document Grok CLI parses from stdout:
// {"decision": "approve"|"block", "reason": "..."}. Grok has no
// hookSpecificOutput/permissionDecision envelope.
type grokOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// WriteGrok emits the decision in Grok CLI's hook output format. Allow maps to
// "approve" and deny to "block". Ask has no Grok equivalent, so nothing is
// written (Grok treats no output as deferring to its normal flow).
//
// Note Grok ignores the JSON reason field when blocking: only stderr from a
// hook exiting with code 2 is surfaced to the model. Callers that deny must
// therefore also write the reason to stderr and exit 2 (see Reason).
func (d *Decision) WriteGrok(w io.Writer) error {
	out := grokOutput{Reason: d.HookSpecificOutput.PermissionDecisionReason}
	switch d.HookSpecificOutput.PermissionDecision {
	case DecisionAllow:
		out.Decision = "approve"
	case DecisionDeny:
		out.Decision = "block"
	default:
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Verdict reports the decision's verdict.
func (d *Decision) Verdict() PermissionDecision {
	return d.HookSpecificOutput.PermissionDecision
}

// Reason reports the human/model-readable explanation for the verdict.
func (d *Decision) Reason() string {
	return d.HookSpecificOutput.PermissionDecisionReason
}
