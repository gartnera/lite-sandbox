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
	// Held at 0.99.0: from 0.100.0 (charmbracelet/crush 2000857d, the
	// coalescing pubsub broker) `crush run` can return when the agent finishes
	// before printing the final message's last update, so the answer is
	// intermittently missing from its output.
	CrushVersion = "0.99.0"
	// CodexVersion is an openai/codex GitHub release (tag rust-v<version>).
	CodexVersion = "0.172.0"
	// ClaudeCodeVersion is a Claude Code release, fetched from the native
	// distribution that https://claude.ai/install.sh uses.
	ClaudeCodeVersion = "2.1.332"
	// OpencodeVersion is an anomalyco/opencode v1 GitHub release (without the "v").
	OpencodeVersion = "1.19.6"
	// OpencodeV2Version is an anomalyco/opencode v2 GitHub release (without
	// the "v"). v2 changed the config format, so both majors are tested.
	OpencodeV2Version = "2.4.1"
	// GrokVersion is a Grok Build release, fetched from the distribution that
	// https://x.ai/cli/install.sh uses.
	GrokVersion = "1.0.92"
	// PiVersion is an earendil-works/pi GitHub release (without the "v").
	PiVersion = "1.6.0"
)

// grokSHA256 pins the SHA-256 of the (decompressed) GrokVersion binary per
// <os>-<arch>, since Grok's distribution publishes no checksum. Update it
// with GrokVersion; an E2E_GROK_VERSION override runs unverified.
var grokSHA256 = map[string]string{
	"linux-x86_64":  "add4d201dbf2c0bd6077a36feb55a76939de30bae48dbb06f16b2307d38ceacb",
	"linux-aarch64": "8c74f1dc6cdc1befff6b9faada06bec4cf6759d04f2a60cdc28ece5ff696b44f",
	"macos-aarch64": "8b5f67b24f2cc9a4341d8e2eb7f67e3228d7d647ed04752a4f932f7133e5ab08",
	"macos-x86_64":  "66b7a3ef1d647280ac649b68d89b5a3d4800b1ae9df76707c011e2d400858ea9",
}
