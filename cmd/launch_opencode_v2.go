package cmd

// lite-sandbox launch opencode for opencode v2.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// opencodeV2LaunchSpec sets OPENCODE_CONFIG_CONTENT to v2's native format:
//
//   - mcp.servers.lite-sandbox, the MCP server (reached through Code Mode, as
//     with install), run with --config-requests;
//   - opencodeV2Rules in permissions. The inline config ranks above the
//     global and project configs, and arrays are appended to the user's own
//     OPENCODE_CONFIG_CONTENT, so they are the last rules opencode reads;
//   - plugins naming lite-sandbox's plugin (opencode_plugin.go), kept in
//     lite-sandbox's cache, which confines the built-in file tools and puts
//     config requests to the user. When `install opencode` already put the
//     plugin in v2's plugins directory, opencode loads that one, and a second
//     copy is not added;
//   - instructions naming the directive file.
//
// It also runs opencode with --standalone (see opencodeV2LaunchArgs).
func opencodeV2LaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	args, err := opencodeV2LaunchArgs(agentArgs)
	if err != nil {
		return launchSpec{}, err
	}
	directivePath, err := opencodeLaunchDirective("lite-sandbox-v2.md", opencodeV2Directive)
	if err != nil {
		return launchSpec{}, err
	}
	pluginDir := ""
	if !opencodePluginInstalled() {
		if pluginDir, err = opencodeLaunchPlugin(binPath); err != nil {
			return launchSpec{}, err
		}
	}
	content, err := opencodeV2LaunchConfig(binPath, directivePath, pluginDir, os.Getenv("OPENCODE_CONFIG_CONTENT"))
	if err != nil {
		return launchSpec{}, err
	}
	return launchSpec{
		args: args,
		env:  []string{"OPENCODE_CONFIG_CONTENT=" + content},
		notes: []string{"opencode v2: running with --standalone, a private server for this session, " +
			"since opencode's shared background service would not see the sandbox configuration"},
	}, nil
}

// opencodePluginInstalled reports whether `install opencode` put the plugin
// in v2's global plugins directory, which v2 loads on its own.
func opencodePluginInstalled() bool {
	dir, err := opencodeV2ConfigDir()
	if err != nil {
		return false
	}
	return fileExists(filepath.Join(opencodeInstalledPluginDir(dir), opencodePluginEntry))
}

// opencodeV2LaunchConfig renders v2's inline config, merged over existing (the
// user's own OPENCODE_CONFIG_CONTENT, or ""). pluginDir is the plugin's
// directory, or "" to name none.
func opencodeV2LaunchConfig(binPath, directivePath, pluginDir, existing string) (string, error) {
	ours := map[string]any{
		"mcp": map[string]any{
			"servers": map[string]any{
				"lite-sandbox": opencodeV2MCPLocal{Type: "local", Command: append([]string{binPath}, opencodeServeArgs...)},
			},
		},
		"permissions":  opencodeV2Rules,
		"instructions": []any{directivePath},
	}
	if pluginDir != "" {
		ours["plugins"] = []any{pluginDir}
	}
	return opencodeLaunchContent(ours, existing)
}

// opencodeV2LaunchArgs adds --standalone to the agent's arguments. By default
// v2's TUI and `run` hand the session to a background service shared by every
// opencode client, started with whatever environment its first client had,
// and reused while healthy, so OPENCODE_CONFIG_CONTENT would never reach it
// and the session would run with the built-in shell and without the sandbox.
// --standalone runs a private server that inherits this environment.
// --server (an existing server) is refused for the same reason.
func opencodeV2LaunchArgs(agentArgs []string) ([]string, error) {
	for _, a := range agentArgs {
		if a == "--" {
			break
		}
		if a == "--server" || strings.HasPrefix(a, "--server=") {
			return nil, fmt.Errorf("opencode v2's --server connects to a server started without the sandbox configuration; drop it to run a private sandboxed server")
		}
		if a == "--standalone" || a == "--standalone=true" {
			return agentArgs, nil
		}
		if strings.HasPrefix(a, "--standalone=") {
			return nil, fmt.Errorf("opencode v2 needs --standalone under lite-sandbox launch: the shared background service would not see the sandbox configuration")
		}
	}
	return append([]string{"--standalone"}, agentArgs...), nil
}
