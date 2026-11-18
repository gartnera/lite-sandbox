// Package mockedserver drives real agent binaries (Crush, Codex, Claude Code,
// opencode v1 and v2, Grok Build, pi) through
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
	CrushVersion = "0.101.0"
	// CodexVersion is an openai/codex GitHub release (tag rust-v<version>).
	CodexVersion = "0.170.0"
	// ClaudeCodeVersion is a Claude Code release, fetched from the native
	// distribution that https://claude.ai/install.sh uses.
	ClaudeCodeVersion = "2.1.327"
	// OpencodeVersion is an anomalyco/opencode v1 GitHub release (without the "v").
	OpencodeVersion = "1.19.6"
	// OpencodeV2Version is an anomalyco/opencode v2 GitHub release (without
	// the "v"). v2 changed the config format, so both majors are tested.
	OpencodeV2Version = "2.3.2"
	// GrokVersion is a Grok Build release, fetched from the distribution that
	// https://x.ai/cli/install.sh uses.
	GrokVersion = "1.0.89"
	// PiVersion is an earendil-works/pi GitHub release (without the "v").
	PiVersion = "1.5.2"
)

// grokSHA256 pins the SHA-256 of the (decompressed) GrokVersion binary per
// <os>-<arch>, since Grok's distribution publishes no checksum. Update it
// with GrokVersion; an E2E_GROK_VERSION override runs unverified.
var grokSHA256 = map[string]string{
	"linux-x86_64":  "a3dface51d9bdc71fd121e0481dd02d9b46a721f7a6b892f756480e9666eba1f",
	"linux-aarch64": "641b3e500d6420d3b07117a2c857cceeb82b33f4b53d23a95895bd76a4773f96",
	"macos-aarch64": "f149e6ad81339491f8d6e0c5fd712f2813042c0dfbb595c28d5767e4567c17a1",
	"macos-x86_64":  "3103ba39e3bd7f9c6f55e1b4a61219e7d49736f334e97527a49f73aaf5743d8d",
}
