package cmd

// lite-sandbox launch opencode for opencode v2.

import (
	"fmt"
	"os"
	"strings"
)

// opencodeV2LaunchSpec sets OPENCODE_CONFIG_CONTENT to v2's native format:
//
//   - mcp.servers.lite-sandbox, the MCP server (reached through Code Mode, as
//     with install);
//   - opencodeV2Rules in permissions. The inline config ranks above the
//     global and project configs, and arrays are appended to the user's own
//     OPENCODE_CONFIG_CONTENT, so they are the last rules opencode reads;
//   - instructions naming the directive file.
//
// It also runs opencode with --standalone (see opencodeV2LaunchArgs).
func opencodeV2LaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	args, err := opencodeV2LaunchArgs(agentArgs)
	if err != nil {
		return launchSpec{}, err
	}
	directivePath, err := opencodeLaunchDirective()
	if err != nil {
		return launchSpec{}, err
	}
	content, err := opencodeV2LaunchConfig(binPath, directivePath, os.Getenv("OPENCODE_CONFIG_CONTENT"))
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

// opencodeV2LaunchConfig renders v2's inline config, merged over existing (the
// user's own OPENCODE_CONFIG_CONTENT, or "").
func opencodeV2LaunchConfig(binPath, directivePath, existing string) (string, error) {
	return opencodeLaunchContent(map[string]any{
		"mcp": map[string]any{
			"servers": map[string]any{
				"lite-sandbox": opencodeV2MCPLocal{Type: "local", Command: []string{binPath, "serve-mcp"}},
			},
		},
		"permissions":  opencodeV2Rules,
		"instructions": []any{directivePath},
	}, existing)
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
