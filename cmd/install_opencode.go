package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tailscale/hujson"
)

// opencodeDirective is appended to the global AGENTS.md so opencode prefers the
// sandboxed bash tool. opencode namespaces MCP tools as <server>_<tool>, so the
// sandbox's shell surfaces as lite-sandbox_bash.
const opencodeDirective = "ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands. The built-in bash tool is denied by the permission config and will not run. The sandboxed " +
	"tool runs commands through lite-sandbox's AST validation and filesystem path boundaries."

// opencodeConfigDir returns opencode's global configuration directory:
// $XDG_CONFIG_HOME/opencode when set, otherwise ~/.config/opencode. opencode
// uses the XDG layout on every platform (including macOS).
func opencodeConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "opencode"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".config", "opencode"), nil
}

// runInstallOpencode configures opencode to use lite-sandbox. Unlike Claude
// Code and Codex, opencode has no PreToolUse hook protocol (its plugins are
// JavaScript), so there is a single install mode:
//
//   - register the MCP server under mcp.lite-sandbox in the global
//     opencode.json;
//   - deny the built-in bash tool via permission.bash = "deny" (the analogue of
//     the Claude installer's Bash permission deny) and auto-allow the sandbox's
//     tools via the lite-sandbox* permission pattern;
//   - append a usage directive to the global AGENTS.md.
//
// --with-tool-hook therefore has nothing to attach to (a note is printed), and
// --bash-ast-hook-mode — which exists to keep using the built-in shell behind a
// validating hook — skips opencode entirely.
func runInstallOpencode(binPath string) error {
	if installBashASTHookMode {
		fmt.Println("⚠ opencode has no PreToolUse hook protocol, so --bash-ast-hook-mode cannot govern its built-in bash tool — skipping opencode.")
		fmt.Println("  Run `lite-sandbox install opencode` (without the flag) for the standard opencode setup.")
		return nil
	}

	opencodeDir, err := opencodeConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opencodeDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", opencodeDir, err)
	}

	// opencode accepts either opencode.json (plain JSON) or opencode.jsonc
	// (JSONC, with comments and trailing commas). Edit whichever exists in
	// place — creating a sibling of the other name would be ignored or
	// confusing — preferring opencode.json when both are present. When neither
	// exists, create a plain opencode.json.
	jsonPath := filepath.Join(opencodeDir, "opencode.json")
	jsoncPath := filepath.Join(opencodeDir, "opencode.jsonc")
	configPath := jsonPath
	editErr := error(nil)
	switch {
	case fileExists(jsonPath):
		configPath = jsonPath
		editErr = configureOpencodeConfig(jsonPath, binPath)
	case fileExists(jsoncPath):
		configPath = jsoncPath
		editErr = configureOpencodeJSONC(jsoncPath, binPath)
	default:
		editErr = configureOpencodeConfig(jsonPath, binPath)
	}
	if editErr != nil {
		return fmt.Errorf("failed to configure opencode: %w", editErr)
	}
	fmt.Printf("✓ Added MCP server, denied the built-in bash tool, and auto-allowed the sandbox tools in %s\n", configPath)

	if err := configureOpencodeAGENTSMD(opencodeDir); err != nil {
		return fmt.Errorf("failed to configure AGENTS.md: %w", err)
	}
	fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(opencodeDir, "AGENTS.md"))

	fmt.Println("\n✓ opencode installation complete!")
	if installWithToolHook {
		fmt.Println("(--with-tool-hook: opencode has no PreToolUse hook protocol, so the flag does not apply to it;")
		fmt.Println(" use opencode's own permission config — e.g. permission.edit / permission.external_directory — to confine its file tools)")
	}
	fmt.Println("Restart opencode for the changes to take effect.")
	return nil
}

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
	// sandbox's own tools (lite-sandbox_bash, lite-sandbox_bash_output, ...) so
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

// fileExists reports whether path exists (as any file type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
	v, err := hujson.Parse(data)
	if err != nil {
		return fmt.Errorf("failed to parse %s as JSONC: %w", configPath, err)
	}
	root, ok := v.Value.(*hujson.Object)
	if !ok {
		return fmt.Errorf("%s: expected a JSON object at the top level", configPath)
	}

	if hujsonFindMember(root, "$schema") == nil {
		hujsonSetMember(root, "$schema", hujsonString("https://opencode.ai/config.json"))
	}

	// mcp.lite-sandbox — a local server launched via `lite-sandbox serve-mcp`.
	mcp, err := hujsonEnsureObject(root, "mcp")
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	serverRaw, err := json.Marshal(opencodeMCPLocal{
		Type:    "local",
		Command: []string{binPath, "serve-mcp"},
		Enabled: true,
	})
	if err != nil {
		return err
	}
	serverVal, err := hujson.Parse(serverRaw)
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

// hujsonString wraps a Go string as a hujson JSON-string Value.
func hujsonString(s string) hujson.Value {
	return hujson.Value{Value: hujson.String(s)}
}

// hujsonMemberName returns the decoded string name of an object member, or ""
// if the name is not a JSON string literal.
func hujsonMemberName(name hujson.Value) string {
	lit, ok := name.Value.(hujson.Literal)
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal([]byte(lit), &s); err != nil {
		return ""
	}
	return s
}

// hujsonFindMember returns a pointer to the value of the member named key, or
// nil if absent. The pointer aliases into obj.Members, so mutating *result
// mutates the tree.
func hujsonFindMember(obj *hujson.Object, key string) *hujson.Value {
	for i := range obj.Members {
		if hujsonMemberName(obj.Members[i].Name) == key {
			return &obj.Members[i].Value
		}
	}
	return nil
}

// hujsonSetMember sets obj[key] = val, replacing the existing member's value
// (preserving its name and comments) or appending a new member.
func hujsonSetMember(obj *hujson.Object, key string, val hujson.Value) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		mv.Value = val.Value
		mv.BeforeExtra, mv.AfterExtra = val.BeforeExtra, val.AfterExtra
		return
	}
	obj.Members = append(obj.Members, hujson.ObjectMember{
		Name:  hujsonString(key),
		Value: val,
	})
}

// hujsonEnsureObject returns obj[key] as an *Object, creating an empty one if
// the member is absent. It errors if the member exists but is not an object.
func hujsonEnsureObject(obj *hujson.Object, key string) (*hujson.Object, error) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		sub, ok := mv.Value.(*hujson.Object)
		if !ok {
			return nil, fmt.Errorf("%q is not a JSON object", key)
		}
		return sub, nil
	}
	sub := &hujson.Object{}
	hujsonSetMember(obj, key, hujson.Value{Value: sub})
	return sub, nil
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

// configureOpencodeAGENTSMD appends the usage directive to the global
// AGENTS.md, creating the file if needed. Idempotent; existing content is
// preserved.
func configureOpencodeAGENTSMD(opencodeDir string) error {
	return appendDirectiveOnce(filepath.Join(opencodeDir, "AGENTS.md"), opencodeDirective)
}
