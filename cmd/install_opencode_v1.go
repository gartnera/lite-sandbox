package cmd

// opencode v1's config format: the MCP server under mcp.<name>, and the
// permission map (permission.bash = "deny", permission."lite-sandbox*" =
// "allow"). opencode v2 also reads it, normalizing it in memory, which is why
// it is the fallback when the installed major is unknown.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

// opencodeMCPLocal is the McpLocalConfig shape from opencode's config schema
// (https://opencode.ai/config.json).
type opencodeMCPLocal struct {
	Type    string   `json:"type"`
	Command []string `json:"command"`
	Enabled bool     `json:"enabled"`
}

// configureOpencodeConfig registers the lite-sandbox MCP server and the bash
// permission rules in opencode's global opencode.json, creating the file if
// needed. All other keys — and unknown fields inside mcp/permission — are
// preserved by round-tripping them as raw JSON. Idempotent: re-running rewrites
// the same entries in place.
func configureOpencodeConfig(configPath, binPath string) error {
	cfg := make(map[string]json.RawMessage)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse %s (note lite-sandbox can only edit plain JSON, not JSONC comments): %w", configPath, err)
	}

	if _, ok := cfg["$schema"]; !ok {
		cfg["$schema"] = json.RawMessage(`"https://opencode.ai/config.json"`)
	}

	// mcp.lite-sandbox — a local server launched via `lite-sandbox serve-mcp`.
	mcp := make(map[string]json.RawMessage)
	if raw, ok := cfg["mcp"]; ok {
		if err := json.Unmarshal(raw, &mcp); err != nil {
			return fmt.Errorf("failed to parse mcp in %s: %w", configPath, err)
		}
	}
	serverRaw, err := json.Marshal(opencodeMCPLocal{
		Type:    "local",
		Command: []string{binPath, "serve-mcp"},
		Enabled: true,
	})
	if err != nil {
		return err
	}
	mcp["lite-sandbox"] = serverRaw
	mcpRaw, err := json.Marshal(mcp)
	if err != nil {
		return err
	}
	cfg["mcp"] = mcpRaw

	// permission.bash = "deny" blocks the built-in shell so opencode must use
	// the sandbox (any existing bash rule object is intentionally replaced —
	// granular allows would defeat the deny). lite-sandbox* auto-allows the
	// sandbox's own tools (lite-sandbox_bash, lite-sandbox_list_shells, ...) so
	// they never prompt, mirroring the Claude installer's allow entries.
	perm := make(map[string]json.RawMessage)
	if raw, ok := cfg["permission"]; ok {
		if err := json.Unmarshal(raw, &perm); err != nil {
			// permission may also be a bare action string ("allow"/"ask"/"deny")
			// applying to everything; preserve that as the catch-all "*" rule.
			var action string
			if err2 := json.Unmarshal(raw, &action); err2 != nil {
				return fmt.Errorf("failed to parse permission in %s: %w", configPath, err)
			}
			perm["*"] = raw
		}
	}
	perm["bash"] = json.RawMessage(`"deny"`)
	perm["lite-sandbox*"] = json.RawMessage(`"allow"`)
	permRaw, err := json.Marshal(perm)
	if err != nil {
		return err
	}
	cfg["permission"] = permRaw

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, append(out, '\n'), 0644)
}

// configureOpencodeJSONC applies the same edits as configureOpencodeConfig to a
// JSONC (opencode.jsonc) global config, but parses and re-serializes it as a
// JWCC syntax tree (via hujson) so the user's comments, trailing commas, and
// formatting survive the round trip — encoding/json would reject them on read
// and drop them on write. Idempotent: re-running replaces the same entries in
// place. Only the lite-sandbox MCP server and the bash / lite-sandbox*
// permission rules are overwritten; every other key and its comments are kept.
func configureOpencodeJSONC(configPath, binPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	v, root, err := opencodeParseTree(configPath, data)
	if err != nil {
		return err
	}

	// mcp.lite-sandbox — a local server launched via `lite-sandbox serve-mcp`.
	mcp, err := hujsonEnsureObject(root, "mcp")
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	serverVal, err := hujsonMarshal(opencodeMCPLocal{
		Type:    "local",
		Command: []string{binPath, "serve-mcp"},
		Enabled: true,
	})
	if err != nil {
		return err
	}
	hujsonSetMember(mcp, "lite-sandbox", serverVal)

	// permission.bash = "deny" and permission."lite-sandbox*" = "allow", matching
	// the plain-JSON path. A bare-string permission ("allow"/"ask"/"deny")
	// applying to everything is preserved as the catch-all "*" rule.
	perm, err := hujsonEnsurePermissionObject(root, configPath)
	if err != nil {
		return err
	}
	hujsonSetMember(perm, "bash", hujsonString("deny"))
	hujsonSetMember(perm, "lite-sandbox*", hujsonString("allow"))

	v.Format()
	return os.WriteFile(configPath, v.Pack(), 0644)
}

// hujsonEnsurePermissionObject returns the "permission" object, creating it if
// absent and, mirroring the plain-JSON path, converting a bare-string
// permission action into a catch-all "*" rule so it is preserved.
func hujsonEnsurePermissionObject(root *hujson.Object, configPath string) (*hujson.Object, error) {
	mv := hujsonFindMember(root, "permission")
	if mv == nil {
		perm := &hujson.Object{}
		hujsonSetMember(root, "permission", hujson.Value{Value: perm})
		return perm, nil
	}
	switch pv := mv.Value.(type) {
	case *hujson.Object:
		return pv, nil
	case hujson.Literal:
		var action string
		if err := json.Unmarshal([]byte(pv), &action); err != nil {
			return nil, fmt.Errorf("failed to parse permission in %s", configPath)
		}
		perm := &hujson.Object{}
		hujsonSetMember(perm, "*", hujson.Value{Value: pv})
		mv.Value = perm
		return perm, nil
	default:
		return nil, fmt.Errorf("failed to parse permission in %s", configPath)
	}
}
