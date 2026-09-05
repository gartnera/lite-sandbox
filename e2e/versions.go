// Package e2e drives real agent binaries (Crush, Codex, Claude Code) through
// `lite-sandbox install` and a non-interactive run, with e2e/mockmodel standing
// in for the LLM. See the *_test.go files; this file pins the agent versions
// the suite provisions.
package e2e

// Pinned agent releases. TestMain downloads exactly these into e2e/.bin/agents
// (locally and in CI, which caches that directory keyed on this file), so a
// run is reproducible on any machine. Bump deliberately, and re-run the suite.
const (
	// CrushVersion is a charmbracelet/crush GitHub release (without the "v").
	CrushVersion = "0.92.0"
	// CodexVersion is the @openai/codex npm package version.
	CodexVersion = "0.153.4"
	// ClaudeCodeVersion is the @anthropic-ai/claude-code npm package version.
	ClaudeCodeVersion = "2.1.261"
)
