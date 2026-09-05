// Package mockedserver drives real agent binaries (Crush, Codex, Claude Code,
// opencode) through
// `lite-sandbox install` and a non-interactive run against a mocked model
// server (the mockmodel package), so it needs no API key. The sibling
// e2e/claude suite uses a real model instead. See the *_test.go files; this file pins the agent
// versions the suite provisions.
package mockedserver

// Pinned agent releases. TestMain downloads exactly these into e2e/mockedserver/.bin/agents
// (locally and in CI, which caches that directory keyed on this file), so a
// run is reproducible on any machine. Bump deliberately, and re-run the suite.
const (
	// CrushVersion is a charmbracelet/crush GitHub release (without the "v").
	CrushVersion = "0.92.0"
	// CodexVersion is an openai/codex GitHub release (tag rust-v<version>).
	CodexVersion = "0.153.4"
	// ClaudeCodeVersion is a Claude Code release, fetched from the native
	// distribution that https://claude.ai/install.sh uses.
	ClaudeCodeVersion = "2.1.261"
	// OpencodeVersion is an anomalyco/opencode GitHub release (without the "v").
	OpencodeVersion = "1.18.29"
)
