// Package mockedserver drives real agent binaries (Crush, Codex, Claude Code,
// opencode, Grok Build) through
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
	// GrokVersion is a Grok Build release, fetched from the distribution that
	// https://x.ai/cli/install.sh uses.
	GrokVersion = "1.0.41"
)

// grokSHA256 pins the SHA-256 of the (decompressed) GrokVersion binary per
// <os>-<arch>, since Grok's distribution publishes no checksum. Update it
// with GrokVersion; an E2E_GROK_VERSION override runs unverified.
var grokSHA256 = map[string]string{
	"linux-x86_64":  "9ce03ed23e16ea01072b4496263d6213a27899e1e3e107f008d36edf82e70407",
	"linux-aarch64": "7c0b8c973af6a78e2037f19ed93033471b8c5e722f9ff04b86b092e066e60d74",
	"macos-aarch64": "9c844eb13365180787d9ad22b2b3748a024be8e1ed845253cc114781b31c591d",
	"macos-x86_64":  "8fce04ab8f33a0f604e405a64b3ec28cf92aa600ca6b80106e4b14e8bf80d95b",
}
