package cmd

// lite-sandbox launch opencode: dispatches on the installed opencode's major
// version to the v1 spec (launch_opencode_v1.go) or the v2 spec
// (launch_opencode_v2.go). Both pass what `install opencode` would write in
// OPENCODE_CONFIG_CONTENT, opencode's inline config, which it merges over the
// global and project configs (only managed config ranks higher), plus an
// instructions file holding the usage directive. opencode only takes
// instructions from files, so the directive is kept in lite-sandbox's cache
// (launchCacheDir) rather than in opencode's config directory; the user's own
// AGENTS.md and instructions still load. An OPENCODE_CONFIG_CONTENT the user
// already set is kept, with ours merged over it.

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
)

func opencodeLaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	if out, err := opencodeVersionOutput(); err == nil && opencodeMajorVersion(out) >= 2 {
		return opencodeV2LaunchSpec(binPath, agentArgs)
	}
	return opencodeV1LaunchSpec(binPath, agentArgs)
}

// opencodeLaunchDirective writes the usage directive to lite-sandbox's cache
// and returns its path, for the inline config's instructions.
func opencodeLaunchDirective() (string, error) {
	dir, err := launchCacheDir("opencode")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "lite-sandbox.md")
	if err := writeFileAtomic(path, []byte(opencodeDirective+"\n")); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", path, err)
	}
	return path, nil
}

// opencodeLaunchContent renders ours as the inline config, merged over
// existing (the user's own OPENCODE_CONFIG_CONTENT, or "").
func opencodeLaunchContent(ours map[string]any, existing string) (string, error) {
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
// anything else replaced by over's value. A top-level permission given as a
// bare action string in base is kept as the catch-all "*" rule when over sets
// an object, as the installer does.
func mergeJSON(base, over map[string]any) map[string]any {
	if action, ok := base["permission"].(string); ok {
		if _, ok := over["permission"].(map[string]any); ok {
			base = maps.Clone(base)
			base["permission"] = map[string]any{"*": action}
		}
	}
	out := maps.Clone(base)
	for k, ov := range over {
		bv, ok := out[k]
		if !ok {
			out[k] = ov
			continue
		}
		switch o := ov.(type) {
		case map[string]any:
			if b, ok := bv.(map[string]any); ok {
				out[k] = mergeJSON(b, o)
			} else {
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
