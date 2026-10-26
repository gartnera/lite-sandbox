package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// The OS sandbox worker confines what the code a command runs can touch on
// disk, but not what it inherits: the MCP server's environment is the
// agent's, and carries the agent's own credentials (ANTHROPIC_AUTH_TOKEN,
// CLAUDE_CODE_OAUTH_TOKEN) next to whatever the user exported (GITHUB_TOKEN,
// AWS_SECRET_ACCESS_KEY, NPM_TOKEN). A dependency's install script or a test
// could read them and send them off. So the environment commands get in the
// worker leaves out every variable named like a credential (CredentialEnvVar),
// unless the config passes it through (os_sandbox_env_passthrough).

// credentialEnvWords are the words of a variable name (split at "_") that
// mark it as holding a credential.
var credentialEnvWords = []string{
	"TOKEN", "TOKENS", "SECRET", "SECRETS", "PASSWORD", "PASSWORDS", "PASSWD",
	"CREDENTIAL", "CREDENTIALS", "APIKEY", "PAT",
}

// credentialEnvPairs are adjacent word pairs that mark a credential.
var credentialEnvPairs = [][2]string{{"API", "KEY"}, {"ACCESS", "KEY"}, {"PRIVATE", "KEY"}, {"AUTH", "KEY"}}

// agentEnvVars are the agents' own variables that are not named like a
// credential but give access to the agent: Claude Code's messaging socket,
// through which another session can be driven.
var agentEnvVars = []string{"CLAUDE_CODE_MESSAGING_SOCKET"}

// agentEnvPrefixes are the prefixes of the agents' own variables.
var agentEnvPrefixes = []string{"ANTHROPIC_", "CLAUDE_", "OPENAI_", "CODEX_", "XAI_", "GROK_", "OPENCODE_", "CRUSH_"}

// CredentialEnvVar reports whether the variable name looks like it holds a
// credential: a word of it (split at "_", case-insensitive) is TOKEN, SECRET,
// PASSWORD, ... (GITHUB_TOKEN, AWS_SESSION_TOKEN), it has API_KEY,
// ACCESS_KEY or PRIVATE_KEY in it (AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID),
// or it ends in _KEY (OPENAI_API_KEY, STRIPE_KEY). Matching whole words keeps
// TOKENIZERS_PARALLELISM and KEYCHAIN_PATH out. An agent variable that grants
// access without looking like one (AgentEnvVar) counts too.
func CredentialEnvVar(name string) bool {
	if slices.Contains(agentEnvVars, name) {
		return true
	}
	words := strings.Split(strings.ToUpper(name), "_")
	for i, w := range words {
		if slices.Contains(credentialEnvWords, w) {
			return true
		}
		if i > 0 {
			for _, p := range credentialEnvPairs {
				if words[i-1] == p[0] && w == p[1] {
					return true
				}
			}
		}
	}
	return len(words) > 1 && words[len(words)-1] == "KEY"
}

// AgentEnvVar reports whether the variable is one of the coding agents' own
// credentials (ANTHROPIC_AUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN, OPENAI_API_KEY,
// the Claude Code messaging socket): what even a scoped worker, which runs a
// named CLI with the user's environment, must not get.
func AgentEnvVar(name string) bool {
	if slices.Contains(agentEnvVars, name) {
		return true
	}
	upper := strings.ToUpper(name)
	for _, p := range agentEnvPrefixes {
		if strings.HasPrefix(upper, p) {
			return CredentialEnvVar(name)
		}
	}
	return false
}

// ScrubsEnv reports whether commands get the environment SandboxEnv returns:
// the OS sandbox is on and the mode enforces anything (open mode only
// audits).
func (c *Config) ScrubsEnv() bool {
	return c.OSSandboxEnabled() && c.EffectiveMode() != ModeOpen
}

// SandboxEnv returns env ("KEY=VALUE" entries) without the variables named
// like credentials (CredentialEnvVar), except those os_sandbox_env_passthrough
// names. Callers use it for what the OS sandbox worker and the commands it
// runs inherit when ScrubsEnv.
func (c *Config) SandboxEnv(env []string) []string {
	var passthrough []string
	if c != nil {
		passthrough = c.OSSandboxEnvPassthrough
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if CredentialEnvVar(name) && !slices.Contains(passthrough, name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// WithoutAgentEnv returns env without the agents' own credentials
// (AgentEnvVar).
func WithoutAgentEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !AgentEnvVar(name) {
			out = append(out, kv)
		}
	}
	return out
}

// AgentSocketDirs returns the directories holding the coding agents' control
// sockets, which the OS sandbox worker makes unreachable: Claude Code binds
// one socket per session in /tmp/cc-socks (CLAUDE_CODE_MESSAGING_SOCKET names
// this session's), and any process that connects can drive that session. The
// directory is denied whole, so that neither another session's socket can be
// reached nor this one's be unlinked and replaced with an impostor. On Linux
// the worker's /tmp is its own tmpfs already; the directory only matters
// there when the variable points elsewhere.
func AgentSocketDirs() []string {
	var out []string
	add := func(dir string) {
		if dir != "" && filepath.IsAbs(dir) && !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	add("/tmp/cc-socks")
	if runtime.GOOS == "darwin" {
		add("/private/tmp/cc-socks")
	}
	if sock := os.Getenv("CLAUDE_CODE_MESSAGING_SOCKET"); filepath.IsAbs(sock) {
		// Only a directory of its own: the variable could name a socket
		// directly in $TMPDIR, which must stay usable.
		if dir := filepath.Dir(filepath.Clean(sock)); strings.HasPrefix(filepath.Base(dir), "cc-socks") {
			add(dir)
		}
	}
	return out
}

// AgentSocketPaths returns the agents' control sockets the worker masks one
// by one (see AgentSocketDirs for the directories): this session's Claude
// Code messaging socket, wherever it lives.
func AgentSocketPaths() []string {
	if sock := os.Getenv("CLAUDE_CODE_MESSAGING_SOCKET"); filepath.IsAbs(sock) {
		return []string{filepath.Clean(sock)}
	}
	return nil
}
