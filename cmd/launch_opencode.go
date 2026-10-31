package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// opencodeLaunchSpec builds opencode's environment for a sandboxed run. What
// `install opencode` writes to the global opencode.json goes in
// OPENCODE_CONFIG_CONTENT, opencode's inline config, which it merges over the
// global and project configs (only managed config ranks higher):
//
//   - mcp.lite-sandbox, the MCP server;
//   - permission.bash = "deny" and permission."lite-sandbox*" = "allow";
//   - instructions naming a file with the usage directive. opencode only takes
//     instructions from files, so the directive is kept in lite-sandbox's
//     cache (launchCacheDir) rather than in opencode's config directory. The
//     user's own AGENTS.md and instructions still load.
//
// An OPENCODE_CONFIG_CONTENT the user already set is kept: ours is merged
// over it.
func opencodeLaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	dir, err := launchCacheDir("opencode")
	if err != nil {
		return launchSpec{}, err
	}
	directivePath := filepath.Join(dir, "lite-sandbox.md")
	if err := writeFileAtomic(directivePath, []byte(opencodeDirective+"\n")); err != nil {
		return launchSpec{}, fmt.Errorf("failed to write %s: %w", directivePath, err)
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

// opencodeLaunchConfig renders the inline config, merged over existing (the
// user's own OPENCODE_CONFIG_CONTENT, or "").
func opencodeLaunchConfig(binPath, directivePath, existing string) (string, error) {
	ours := map[string]any{
		"mcp": map[string]any{
			"lite-sandbox": opencodeMCPLocal{Type: "local", Command: []string{binPath, "serve-mcp"}, Enabled: true},
		},
		"permission": map[string]any{
			"bash":          "deny",
			"lite-sandbox*": "allow",
		},
		"instructions": []any{directivePath},
	}
	// Round-trip through JSON so ours holds only plain maps and slices.
	data, err := json.Marshal(ours)
	if err != nil {
		return "", err
	}
	var merged map[string]any
	if err := json.Unmarshal(data, &merged); err != nil {
		return "", err
	}
	if existing != "" {
		var theirs map[string]any
		if err := json.Unmarshal([]byte(existing), &theirs); err != nil {
			return "", fmt.Errorf("OPENCODE_CONFIG_CONTENT is set but is not a JSON object: %w", err)
		}
		merged = mergeJSON(theirs, merged)
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// mergeJSON merges over into base: objects recursively, arrays concatenated,
// anything else replaced by over's value. A permission given as a bare action
// string in base is kept as the catch-all "*" rule when over sets an object,
// as the installer does.
func mergeJSON(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, ov := range over {
		bv, ok := out[k]
		if !ok {
			out[k] = ov
			continue
		}
		switch o := ov.(type) {
		case map[string]any:
			switch b := bv.(type) {
			case map[string]any:
				out[k] = mergeJSON(b, o)
			case string:
				out[k] = mergeJSON(map[string]any{"*": b}, o)
			default:
				out[k] = o
			}
		case []any:
			if b, ok := bv.([]any); ok {
				out[k] = append(append([]any{}, b...), o...)
			} else {
				out[k] = o
			}
		default:
			out[k] = ov
		}
	}
	return out
}
