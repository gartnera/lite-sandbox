package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCredentialEnvVar(t *testing.T) {
	for name, want := range map[string]bool{
		"ANTHROPIC_AUTH_TOKEN":           true,
		"ANTHROPIC_API_KEY":              true,
		"CLAUDE_CODE_OAUTH_TOKEN":        true,
		"CLAUDE_CODE_MESSAGING_TOKEN":    true,
		"CLAUDE_CODE_MESSAGING_SOCKET":   true,
		"GITHUB_TOKEN":                   true,
		"gh_token":                       true,
		"AWS_SECRET_ACCESS_KEY":          true,
		"AWS_ACCESS_KEY_ID":              true,
		"AWS_SESSION_TOKEN":              true,
		"NPM_TOKEN":                      true,
		"DB_PASSWORD":                    true,
		"STRIPE_KEY":                     true,
		"GH_PAT":                         true,
		"GOOGLE_APPLICATION_CREDENTIALS": true,
		"PATH":                           false,
		"HOME":                           false,
		"TOKENIZERS_PARALLELISM":         false,
		"KEYCHAIN_PATH":                  false,
		"SSH_AUTH_SOCK":                  false,
		"ANTHROPIC_BASE_URL":             false,
		"CLAUDE_CODE_ENTRYPOINT":         false,
		"KEY":                            false,
	} {
		if got := CredentialEnvVar(name); got != want {
			t.Errorf("CredentialEnvVar(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAgentEnvVar(t *testing.T) {
	for name, want := range map[string]bool{
		"ANTHROPIC_AUTH_TOKEN":         true,
		"CLAUDE_CODE_OAUTH_TOKEN":      true,
		"CLAUDE_CODE_MESSAGING_SOCKET": true,
		"OPENAI_API_KEY":               true,
		"XAI_API_KEY":                  true,
		"GH_TOKEN":                     false,
		"AWS_SECRET_ACCESS_KEY":        false,
		"ANTHROPIC_BASE_URL":           false,
	} {
		if got := AgentEnvVar(name); got != want {
			t.Errorf("AgentEnvVar(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSandboxEnv(t *testing.T) {
	cfg := &Config{OSSandboxEnvPassthrough: []string{"NPM_TOKEN"}}
	got := cfg.SandboxEnv([]string{
		"PATH=/usr/bin",
		"ANTHROPIC_AUTH_TOKEN=sk-secret",
		"NPM_TOKEN=npm",
		"GITHUB_TOKEN=gh",
		"HOME=/home/u",
	})
	want := []string{"PATH=/usr/bin", "NPM_TOKEN=npm", "HOME=/home/u"}
	if !slices.Equal(got, want) {
		t.Errorf("SandboxEnv = %v, want %v", got, want)
	}

	scoped := WithoutAgentEnv([]string{"ANTHROPIC_AUTH_TOKEN=x", "GH_TOKEN=y", "PATH=/bin"})
	if !slices.Equal(scoped, []string{"GH_TOKEN=y", "PATH=/bin"}) {
		t.Errorf("WithoutAgentEnv = %v", scoped)
	}
}

func TestScrubsEnv(t *testing.T) {
	on, off := true, false
	if (&Config{OSSandbox: &off}).ScrubsEnv() {
		t.Error("scrubs without the OS sandbox")
	}
	if !(&Config{OSSandbox: &on}).ScrubsEnv() {
		t.Error("does not scrub with the OS sandbox on")
	}
	if (&Config{OSSandbox: &on, Mode: string(ModeOpen)}).ScrubsEnv() {
		t.Error("scrubs in open mode")
	}
}

func TestAgentSocketDirs(t *testing.T) {
	t.Setenv("CLAUDE_CODE_MESSAGING_SOCKET", "/var/tmp/cc-socks-501/123.sock")
	dirs := AgentSocketDirs()
	if !slices.Contains(dirs, "/tmp/cc-socks") || !slices.Contains(dirs, "/var/tmp/cc-socks-501") {
		t.Errorf("AgentSocketDirs = %v", dirs)
	}
	if got := AgentSocketPaths(); !slices.Equal(got, []string{"/var/tmp/cc-socks-501/123.sock"}) {
		t.Errorf("AgentSocketPaths = %v", got)
	}

	// A socket directly in a shared temp dir masks only itself.
	t.Setenv("CLAUDE_CODE_MESSAGING_SOCKET", "/var/folders/xy/T/123.sock")
	if dirs := AgentSocketDirs(); slices.Contains(dirs, "/var/folders/xy/T") {
		t.Errorf("AgentSocketDirs masks the temp dir: %v", dirs)
	}
}

// TestHostProgramDirs checks that the PATH directories up to and including
// lite-sandbox's are returned (relative and empty entries skipped, duplicates
// collapsed), the ones after it are not, and none are without lite-sandbox on
// PATH.
func TestHostProgramDirs(t *testing.T) {
	root := t.TempDir()
	early := filepath.Join(root, "early")
	gobin := filepath.Join(root, "go", "bin")
	fvm := filepath.Join(root, "fvm", "default", "bin")
	for _, d := range []string{early, gobin, fvm} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A directory or a non-executable file by the name does not count.
	if err := os.Mkdir(filepath.Join(early, appName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fvm, appName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gobin, appName), nil, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	sep := string(filepath.ListSeparator)
	pathEnv := strings.Join([]string{early, "relative/bin", "", early, gobin + "/", fvm, "/usr/bin"}, sep)
	if got := cfg.HostProgramDirs(pathEnv); !slices.Equal(got, []string{early, gobin}) {
		t.Errorf("HostProgramDirs = %v, want %v", got, []string{early, gobin})
	}
	if got := cfg.HostProgramDirs(strings.Join([]string{early, fvm, "/usr/bin"}, sep)); len(got) != 0 {
		t.Errorf("HostProgramDirs without lite-sandbox on PATH = %v, want none", got)
	}
}
