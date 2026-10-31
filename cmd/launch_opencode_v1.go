package cmd

// lite-sandbox launch opencode for opencode v1 (and an opencode whose version
// is unknown: v2 reads this format too).

import "os"

// opencodeV1LaunchSpec sets OPENCODE_CONFIG_CONTENT to:
//
//   - mcp.lite-sandbox, the MCP server;
//   - permission.bash = "deny" and permission."lite-sandbox*" = "allow";
//   - instructions naming the directive file.
func opencodeV1LaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	directivePath, err := opencodeLaunchDirective()
	if err != nil {
		return launchSpec{}, err
	}
	content, err := opencodeLaunchConfig(binPath, directivePath, os.Getenv("OPENCODE_CONFIG_CONTENT"))
	if err != nil {
		return launchSpec{}, err
	}
	return launchSpec{
		args: agentArgs,
		env:  []string{"OPENCODE_CONFIG_CONTENT=" + content},
	}, nil
}

// opencodeLaunchConfig renders v1's inline config, merged over existing (the
// user's own OPENCODE_CONFIG_CONTENT, or "").
func opencodeLaunchConfig(binPath, directivePath, existing string) (string, error) {
	return opencodeLaunchContent(map[string]any{
		"mcp": map[string]any{
			"lite-sandbox": opencodeMCPLocal{Type: "local", Command: []string{binPath, "serve-mcp"}, Enabled: true},
		},
		"permission": map[string]any{
			"bash":          "deny",
			"lite-sandbox*": "allow",
		},
		"instructions": []any{directivePath},
	}, existing)
}
