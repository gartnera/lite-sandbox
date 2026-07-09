package hook

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteGrok(t *testing.T) {
	tests := []struct {
		name         string
		verdict      PermissionDecision
		wantDecision string // "" means no output at all
	}{
		{"deny maps to block", DecisionDeny, "block"},
		{"allow maps to approve", DecisionAllow, "approve"},
		{"ask has no grok equivalent", DecisionAsk, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			d := NewDecision(tt.verdict, "the reason")
			if err := d.WriteGrok(&buf); err != nil {
				t.Fatalf("WriteGrok failed: %v", err)
			}
			if tt.wantDecision == "" {
				if buf.Len() != 0 {
					t.Fatalf("expected no output, got %s", buf.String())
				}
				return
			}
			var doc map[string]any
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
			}
			if doc["decision"] != tt.wantDecision {
				t.Errorf("expected decision %q, got %s", tt.wantDecision, buf.String())
			}
			if doc["reason"] != "the reason" {
				t.Errorf("reason not carried through, got %s", buf.String())
			}
			if _, ok := doc["hookSpecificOutput"]; ok {
				t.Errorf("grok format must not nest Claude's envelope: %s", buf.String())
			}
		})
	}
}
