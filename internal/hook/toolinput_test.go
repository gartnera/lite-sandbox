package hook

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseApplyPatchPaths(t *testing.T) {
	patch := `*** Begin Patch
*** Add File: src/new.go
+package main
*** Update File: pkg/existing.go
@@
-old
+new
*** Delete File: obsolete/gone.txt
*** Move to: pkg/renamed.go
*** End Patch`

	got := parseApplyPatchPaths(patch)
	want := []string{
		"src/new.go",
		"pkg/existing.go",
		"obsolete/gone.txt",
		"pkg/renamed.go",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseApplyPatchPaths() = %v, want %v", got, want)
	}
}

func TestParseApplyPatchPathsDeduplicates(t *testing.T) {
	patch := "*** Update File: a.go\n*** Update File: a.go\n*** Update File: b.go"
	got := parseApplyPatchPaths(patch)
	want := []string{"a.go", "b.go"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseApplyPatchPaths() = %v, want %v", got, want)
	}
}

func TestParseApplyPatchPathsNoMarkers(t *testing.T) {
	if got := parseApplyPatchPaths("just some text\nno markers here"); len(got) != 0 {
		t.Errorf("expected no paths, got %v", got)
	}
}

func TestApplyPatchInputViaFactory(t *testing.T) {
	// Codex delivers apply_patch input as an object with a command field.
	raw := `{"command":"*** Begin Patch\n*** Update File: main.go\n*** End Patch"}`
	e := &Event{ToolName: ToolApplyPatch, RawToolInput: json.RawMessage(raw)}
	if err := e.parseToolInput(); err != nil {
		t.Fatalf("parseToolInput: %v", err)
	}
	ap, ok := e.ToolInput.(*ApplyPatchInput)
	if !ok {
		t.Fatalf("expected *ApplyPatchInput, got %T", e.ToolInput)
	}
	if paths := ap.Paths(); len(paths) != 1 || paths[0] != "main.go" {
		t.Errorf("Paths() = %v, want [main.go]", paths)
	}
	if ap.Describe() != "apply patch to: main.go" {
		t.Errorf("Describe() = %q", ap.Describe())
	}
}

func TestApplyPatchInputFallbackFields(t *testing.T) {
	// Tolerant of alternate keys carrying the patch body.
	in := &ApplyPatchInput{Patch: "*** Delete File: x.txt"}
	if paths := in.Paths(); len(paths) != 1 || paths[0] != "x.txt" {
		t.Errorf("Paths() = %v, want [x.txt]", paths)
	}
	if (&ApplyPatchInput{}).Describe() != "apply patch" {
		t.Errorf("empty Describe() = %q, want %q", (&ApplyPatchInput{}).Describe(), "apply patch")
	}
}
