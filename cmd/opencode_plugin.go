package cmd

// lite-sandbox's opencode v2 plugin (opencode_plugin.ts): it forwards
// opencode's built-in shell, file, patch and media tool calls, and the
// sandbox's own bash tool calls, to `lite-sandbox hook` from v2's tool
// execute.before hook, and puts the hook's "ask" decisions to the user through
// opencode's permission prompt. `install opencode` writes it to v2's plugins
// directory, which v2 loads every plugin from; `launch opencode` keeps it in
// lite-sandbox's cache and names it in the inline config's plugins list.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// opencodePluginSource is the plugin, with opencodePluginPlaceholder standing
// in for its configuration (see renderOpencodePlugin).
//
//go:embed opencode_plugin.ts
var opencodePluginSource string

const opencodePluginPlaceholder = "__LITE_SANDBOX_CONFIG__"

// opencodePluginDir is the plugin's directory name under v2's plugins
// directory. v2 loads a directory there through its server.ts; v1 loads only
// the .ts and .js files directly in its plugin directories, so it never
// tries to load this v2 plugin.
const opencodePluginDir = "lite-sandbox"

// opencodePluginEntry is the plugin's entry point inside its directory.
const opencodePluginEntry = "server.ts"

// opencodeHookTimeoutSec bounds how long the plugin waits for the hook, as
// piHookTimeoutSec does for pi's extension.
const opencodeHookTimeoutSec = 30

// opencodeServeArgs are the MCP server's arguments for opencode v2: the
// plugin puts config requests and commands with ask: true to the user, so the
// server runs those the user approved.
var opencodeServeArgs = []string{"serve-mcp", "--config-requests"}

// opencodePluginConfig is the configuration rendered into the plugin. Keep
// the field names in sync with LiteSandboxConfig in opencode_plugin.ts.
type opencodePluginConfig struct {
	Bin                string   `json:"bin"`
	HookArgs           []string `json:"hookArgs"`
	Tools              []string `json:"tools"`
	SandboxBash        string   `json:"sandboxBash"`
	SandboxBashAliases []string `json:"sandboxBashAliases"`
	HookTimeoutSec     int      `json:"hookTimeoutSec"`
}

func newOpencodePluginConfig(binPath string) opencodePluginConfig {
	return opencodePluginConfig{
		Bin:      binPath,
		HookArgs: []string{"hook", "--config-requests"},
		Tools:    slices.Clone(hook.OpencodeHookTools),
		// opencode names the tool lite-sandbox_bash; a top-level call may use
		// the Code Mode name, which opencode then runs as a Code Mode call
		// without calling the hook again.
		SandboxBash:        opencodeMCPToolPrefix + "bash",
		SandboxBashAliases: []string{"lite-sandbox.bash"},
		HookTimeoutSec:     opencodeHookTimeoutSec,
	}
}

// renderOpencodePlugin returns the plugin's source with its configuration
// filled in.
func renderOpencodePlugin(binPath string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(newOpencodePluginConfig(binPath)); err != nil {
		return "", err
	}
	if strings.Count(opencodePluginSource, opencodePluginPlaceholder) != 1 {
		return "", fmt.Errorf("opencode plugin template has no single %s placeholder", opencodePluginPlaceholder)
	}
	return strings.Replace(opencodePluginSource, opencodePluginPlaceholder, strings.TrimSpace(buf.String()), 1), nil
}

// opencodeInstalledPluginDir returns where `install opencode` puts the v2
// plugin: <config dir>/plugins/lite-sandbox.
func opencodeInstalledPluginDir(configDir string) string {
	return filepath.Join(configDir, "plugins", opencodePluginDir)
}

// writeOpencodePlugin writes the plugin's entry point into dir, creating it,
// atomically so an opencode loading or reloading it meanwhile never reads a
// partial file. It returns the entry point's path.
func writeOpencodePlugin(dir, binPath string) (string, error) {
	src, err := renderOpencodePlugin(binPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", dir, err)
	}
	path := filepath.Join(dir, opencodePluginEntry)
	if err := writeFileAtomic(path, []byte(src)); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", path, err)
	}
	return path, nil
}

// opencodeLaunchPlugin writes the plugin for `launch opencode` to a directory
// in lite-sandbox's cache named by its content, so repeated launches reuse it
// and a concurrent launch never replaces the file a running opencode loaded,
// and returns the directory (v2 loads a configured local plugin only from a
// directory).
func opencodeLaunchPlugin(binPath string) (string, error) {
	src, err := renderOpencodePlugin(binPath)
	if err != nil {
		return "", err
	}
	cache, err := launchCacheDir("opencode")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(src))
	dir := filepath.Join(cache, "plugin-"+hex.EncodeToString(sum[:8]))
	if _, err := writeOpencodePlugin(dir, binPath); err != nil {
		return "", err
	}
	return dir, nil
}
