package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/tailscale/hujson"
)

// opencodeDirective is appended to the global AGENTS.md so opencode prefers the
// sandboxed bash tool. opencode v1 offers it as lite-sandbox_bash (MCP tools
// are named <server>_<tool>); v2 by default only through Code Mode, as
// tools["lite-sandbox"].bash in an execute program, so the directive names
// both. The built-in shell tool is named bash in v1 and shell in v2, so the
// directive names neither.
const opencodeDirective = "ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands (in Code Mode, call `tools[\"lite-sandbox\"].bash({ command })` from `execute`). The built-in " +
	"shell tool is denied by the permission config and will not run. The sandboxed tool runs commands through " +
	"lite-sandbox's AST validation and filesystem path boundaries."

// opencodeLegacyDirectives are directives earlier releases wrote to AGENTS.md;
// a re-install replaces them with opencodeDirective instead of appending a
// near-duplicate.
var opencodeLegacyDirectives = []string{
	"ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell " +
		"commands. The built-in bash tool is denied by the permission config and will not run. The sandboxed " +
		"tool runs commands through lite-sandbox's AST validation and filesystem path boundaries.",
}

// opencodeConfigVersion is which opencode config format the installer writes.
type opencodeConfigVersion int

const (
	// opencodeConfigV1 is opencode v1's format: mcp.<name> servers and the
	// permission map. opencode v2 still reads it (normalizing it in memory),
	// so it is the fallback when the version is unknown.
	opencodeConfigV1 opencodeConfigVersion = 1
	// opencodeConfigV2 is opencode v2's native format: mcp.servers.<name> and
	// the ordered permissions rule array.
	opencodeConfigV2 opencodeConfigVersion = 2
)

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

// opencodeV2ConfigDir returns opencode v2's global configuration directory:
// $OPENCODE_CONFIG_DIR when set (v2 reads it in place of the XDG directory),
// otherwise the XDG directory v1 also uses.
func opencodeV2ConfigDir() (string, error) {
	if d := os.Getenv("OPENCODE_CONFIG_DIR"); d != "" {
		return d, nil
	}
	return opencodeConfigDir()
}

// opencodeVersionOutput returns the output of `opencode --version` for the
// opencode on PATH. A variable so tests can stub it.
var opencodeVersionOutput = func() (string, error) {
	// v2 boots its whole runtime before printing the version; don't let a
	// wedged opencode hang the install.
	ctx, cancel := context.WithTimeout(context.Background(), opencodeVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "opencode", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// opencodeVersionTimeout bounds `opencode --version`.
const opencodeVersionTimeout = 15 * time.Second

// opencodeMajorVersion returns the major version named in `opencode --version`
// output, or 0 when it names none (a dev build, or no opencode on PATH).
func opencodeMajorVersion(versionOutput string) int {
	m := semverRe.FindStringSubmatch(versionOutput)
	if m == nil {
		return 0
	}
	major, _ := strconv.Atoi(m[1])
	return major
}

// detectOpencodeConfigVersion picks the config format to write. The opencode
// on PATH decides when its version is known. Otherwise the existing config
// decides: one already using v2-native keys (permissions, mcp.servers) is
// for v2, since v1 cannot read those; anything else gets the v1 format,
// which v2 reads too.
func detectOpencodeConfigVersion(configPaths ...string) opencodeConfigVersion {
	if out, err := opencodeVersionOutput(); err == nil {
		switch major := opencodeMajorVersion(out); {
		case major >= 2:
			return opencodeConfigV2
		case major == 1:
			return opencodeConfigV1
		}
	}
	for _, p := range configPaths {
		if opencodeConfigUsesV2Keys(p) {
			return opencodeConfigV2
		}
	}
	return opencodeConfigV1
}

// opencodeConfigUsesV2Keys reports whether the (JSON or JSONC) config at path
// has a top-level permissions array or an mcp.servers object that is not
// itself a v1 server entry.
func opencodeConfigUsesV2Keys(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	v, err := hujson.Parse(data)
	if err != nil {
		return false
	}
	root, ok := v.Value.(*hujson.Object)
	if !ok {
		return false
	}
	if pv := hujsonFindMember(root, "permissions"); pv != nil {
		if _, ok := pv.Value.(*hujson.Array); ok {
			return true
		}
	}
	if mv := hujsonFindMember(root, "mcp"); mv != nil {
		if mcp, ok := mv.Value.(*hujson.Object); ok {
			if sv := hujsonFindMember(mcp, "servers"); sv != nil {
				servers, ok := sv.Value.(*hujson.Object)
				return ok && !isV1ServerEntry(servers)
			}
		}
	}
	return false
}

// isV1ServerEntry reports whether an mcp.servers object is really a v1 MCP
// server that happens to be named "servers" (v1 servers carry a type); v2
// reads it that way too.
func isV1ServerEntry(servers *hujson.Object) bool {
	return hujsonFindMember(servers, "type") != nil
}

// runInstallOpencode configures opencode to use lite-sandbox. Unlike Claude
// Code and Codex, opencode has no PreToolUse hook protocol (its plugins are
// JavaScript), so there is a single install mode:
//
//   - register the MCP server in the global opencode.json;
//   - deny the built-in shell tool (the analogue of the Claude installer's
//     Bash permission deny) and auto-allow the sandbox's tools;
//   - append a usage directive to the global AGENTS.md.
//
// opencode v1 and v2 differ in config format (v2 moved servers under
// mcp.servers and replaced the permission map with an ordered permissions
// array), so the installed opencode's version picks which one is written; see
// detectOpencodeConfigVersion.
//
// --with-tool-hook therefore has nothing to attach to (a note is printed), and
// --bash-ast-hook-mode — which exists to keep using the built-in shell behind a
// validating hook — skips opencode entirely.
func runInstallOpencode(binPath string) error {
	if installBashASTHookMode {
		fmt.Println("⚠ opencode has no PreToolUse hook protocol, so --bash-ast-hook-mode cannot govern its built-in shell tool — skipping opencode.")
		fmt.Println("  Run `lite-sandbox install opencode` (without the flag) for the standard opencode setup.")
		return nil
	}

	// v2 may read a different global directory (OPENCODE_CONFIG_DIR), so the
	// configs in both candidates inform the version detection.
	v1Dir, err := opencodeConfigDir()
	if err != nil {
		return err
	}
	v2Dir, err := opencodeV2ConfigDir()
	if err != nil {
		return err
	}
	version := detectOpencodeConfigVersion(
		filepath.Join(v2Dir, "opencode.json"), filepath.Join(v2Dir, "opencode.jsonc"),
		filepath.Join(v1Dir, "opencode.json"), filepath.Join(v1Dir, "opencode.jsonc"),
	)
	opencodeDir := v1Dir
	if version == opencodeConfigV2 {
		opencodeDir = v2Dir
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
	configPath, jsonc := jsonPath, false
	if !fileExists(jsonPath) && fileExists(jsoncPath) {
		configPath, jsonc = jsoncPath, true
	}
	var editErr error
	switch {
	case version == opencodeConfigV2:
		editErr = configureOpencodeV2(configPath, binPath, jsonc)
	case jsonc:
		editErr = configureOpencodeJSONC(configPath, binPath)
	default:
		editErr = configureOpencodeConfig(configPath, binPath)
	}
	if editErr != nil {
		return fmt.Errorf("failed to configure opencode: %w", editErr)
	}
	if version == opencodeConfigV2 {
		fmt.Printf("✓ Added MCP server, denied the built-in shell tool, and auto-allowed the sandbox tools in %s (opencode v2 format)\n", configPath)
	} else {
		fmt.Printf("✓ Added MCP server, denied the built-in bash tool, and auto-allowed the sandbox tools in %s (opencode v1 format)\n", configPath)
	}

	if err := configureOpencodeAGENTSMD(opencodeDir); err != nil {
		return fmt.Errorf("failed to configure AGENTS.md: %w", err)
	}
	fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(opencodeDir, "AGENTS.md"))

	fmt.Println("\n✓ opencode installation complete!")
	if installWithToolHook {
		fmt.Println("(--with-tool-hook: opencode has no PreToolUse hook protocol, so the flag does not apply to it;")
		fmt.Println(" use opencode's own permission config — e.g. edit / external_directory rules — to confine its file tools)")
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

// fileExists reports whether path exists (as any file type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// opencodeParseTree parses an opencode config as a JWCC syntax tree and returns
// it with its top-level object, adding $schema if it is missing.
func opencodeParseTree(configPath string, data []byte) (hujson.Value, *hujson.Object, error) {
	v, err := hujson.Parse(data)
	if err != nil {
		return v, nil, fmt.Errorf("failed to parse %s as JSONC: %w", configPath, err)
	}
	root, ok := v.Value.(*hujson.Object)
	if !ok {
		return v, nil, fmt.Errorf("%s: expected a JSON object at the top level", configPath)
	}
	if hujsonFindMember(root, "$schema") == nil {
		hujsonSetMember(root, "$schema", hujsonString("https://opencode.ai/config.json"))
	}
	return v, root, nil
}

// hujsonMarshal JSON-encodes x as a hujson Value.
func hujsonMarshal(x any) (hujson.Value, error) {
	raw, err := json.Marshal(x)
	if err != nil {
		return hujson.Value{}, err
	}
	return hujson.Parse(raw)
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

// opencodeV2Rule is one entry of opencode v2's ordered permissions array.
type opencodeV2Rule struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Effect   string `json:"effect"`
}

// opencodeV2Rules are the permission rules the v2 install appends. v2 applies
// the last matching rule, and hides a tool from the model entirely when the
// last rule matching its action is a deny on resource "*", so these go at the
// end of the array, after any rule of the user's that would re-allow the
// shell. Global rules are applied after the built-in agents' own, so the deny
// also covers the explore subagent (which allows shell itself), and the allow
// lets it use the sandbox (which it would otherwise deny with its "*" rule).
//
//   - shell / * / deny blocks the built-in shell tool (v1's bash). It also
//     covers the shell checks of v2's experimental schedules.
//   - lite-sandbox_* / * / allow auto-allows the sandbox's own tools
//     (lite-sandbox_bash, lite-sandbox_list_shells, ...): v2 names MCP tools
//     <server>_<tool>, and their permission resource is always "*".
var opencodeV2Rules = []opencodeV2Rule{
	{Action: "shell", Resource: "*", Effect: "deny"},
	{Action: "lite-sandbox_*", Resource: "*", Effect: "allow"},
}

// opencodeV2MCPLocal is the Mcp.LocalConfig shape from opencode v2's config
// schema. codemode is left unset (unless the user set it), so v2's default
// applies: the sandbox's tools
// are reached through Code Mode, as tools["lite-sandbox"].bash(...) in a
// program the model passes to the execute tool. Code Mode is an interpreter
// with no filesystem, network, or process access of its own; it can only call
// the tools opencode offers, so the sandbox stays the only way to run a
// command.
type opencodeV2MCPLocal struct {
	Type    string   `json:"type"`
	Command []string `json:"command"`
}

// configureOpencodeV2 registers the lite-sandbox MCP server and its permission
// rules in an opencode v2 config, creating the file if needed:
//
//   - mcp.servers.lite-sandbox, a local server launched via `lite-sandbox
//     serve-mcp` (replacing any earlier entry, except for a codemode setting
//     the user added to it);
//   - opencodeV2Rules, appended to the permissions array.
//
// It also removes what a v1 install left in the same file: the mcp.lite-sandbox
// entry (v2 reports a server defined in both places as a conflict) and the
// permission.bash / permission."lite-sandbox*" rules (v2 still honors them,
// but the native rules supersede them).
//
// The file is edited as a JWCC syntax tree (via hujson), so a .jsonc keeps
// its comments and formatting; for a .json (jsonc false) the content must be
// plain JSON and is written back as plain JSON. Idempotent: re-running
// replaces the server entry and moves the rules back to the end.
func configureOpencodeV2(configPath, binPath string, jsonc bool) error {
	data, err := os.ReadFile(configPath)
	switch {
	case os.IsNotExist(err):
		data = []byte("{}")
	case err != nil:
		return err
	case !jsonc && !json.Valid(data):
		return fmt.Errorf("failed to parse %s (note lite-sandbox can only edit plain JSON in opencode.json; use opencode.jsonc for comments)", configPath)
	}
	v, root, err := opencodeParseTree(configPath, data)
	if err != nil {
		return err
	}

	mcp, err := hujsonEnsureObject(root, "mcp")
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	hujsonDeleteMember(mcp, "lite-sandbox")
	servers, err := hujsonEnsureObject(mcp, "servers")
	if err != nil {
		return fmt.Errorf("%s: mcp.%w", configPath, err)
	}
	if isV1ServerEntry(servers) {
		return fmt.Errorf("%s: mcp.servers is a v1 MCP server named \"servers\"; rename it before installing", configPath)
	}
	serverVal, err := hujsonMarshal(opencodeV2MCPLocal{Type: "local", Command: []string{binPath, "serve-mcp"}})
	if err != nil {
		return err
	}
	// Keep a codemode choice the user made on an earlier entry.
	if prev := hujsonFindMember(servers, "lite-sandbox"); prev != nil {
		if prevObj, ok := prev.Value.(*hujson.Object); ok {
			if cm := hujsonFindMember(prevObj, "codemode"); cm != nil {
				hujsonSetMember(serverVal.Value.(*hujson.Object), "codemode", cm.Clone())
			}
		}
	}
	hujsonSetMember(servers, "lite-sandbox", serverVal)

	if pv := hujsonFindMember(root, "permission"); pv != nil {
		if perm, ok := pv.Value.(*hujson.Object); ok {
			hujsonDeleteMemberIf(perm, "bash", "deny")
			hujsonDeleteMemberIf(perm, "lite-sandbox*", "allow")
			if len(perm.Members) == 0 {
				hujsonDeleteMember(root, "permission")
			}
		}
	}

	rules, err := hujsonEnsureArray(root, "permissions")
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	kept := rules.Elements[:0]
	for _, el := range rules.Elements {
		if !isOpencodeV2Rule(el) {
			kept = append(kept, el)
		}
	}
	rules.Elements = kept
	for _, r := range opencodeV2Rules {
		rv, err := hujsonMarshal(r)
		if err != nil {
			return err
		}
		rules.Elements = append(rules.Elements, rv)
	}

	if jsonc {
		v.Format()
		return os.WriteFile(configPath, v.Pack(), 0644)
	}
	// Plain JSON has no comments to keep, so it is written in the same
	// indented layout as the v1 path, with key order preserved.
	var out bytes.Buffer
	if err := json.Indent(&out, v.Pack(), "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	return os.WriteFile(configPath, out.Bytes(), 0644)
}

// isOpencodeV2Rule reports whether the array element el is one of
// opencodeV2Rules.
func isOpencodeV2Rule(el hujson.Value) bool {
	c := el.Clone()
	c.Standardize()
	var r opencodeV2Rule
	if err := json.Unmarshal(c.Pack(), &r); err != nil {
		return false
	}
	for _, ours := range opencodeV2Rules {
		if r == ours {
			return true
		}
	}
	return false
}

// hujsonDeleteMember removes obj[key], if present.
func hujsonDeleteMember(obj *hujson.Object, key string) {
	obj.Members = slices.DeleteFunc(obj.Members, func(m hujson.ObjectMember) bool {
		return hujsonMemberName(m.Name) == key
	})
}

// hujsonDeleteMemberIf removes obj[key] if it is the JSON string want.
func hujsonDeleteMemberIf(obj *hujson.Object, key, want string) {
	mv := hujsonFindMember(obj, key)
	if mv == nil {
		return
	}
	lit, ok := mv.Value.(hujson.Literal)
	if ok && lit.Kind() == '"' && lit.String() == want {
		hujsonDeleteMember(obj, key)
	}
}

// hujsonEnsureArray returns obj[key] as an *Array, creating an empty one if
// the member is absent. It errors if the member exists but is not an array.
func hujsonEnsureArray(obj *hujson.Object, key string) (*hujson.Array, error) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		arr, ok := mv.Value.(*hujson.Array)
		if !ok {
			return nil, fmt.Errorf("%q is not a JSON array", key)
		}
		return arr, nil
	}
	arr := &hujson.Array{}
	hujsonSetMember(obj, key, hujson.Value{Value: arr})
	return arr, nil
}

// configureOpencodeAGENTSMD appends the usage directive to the global
// AGENTS.md, creating the file if needed, or swaps it in for a directive an
// earlier release wrote. Idempotent; other content is preserved.
func configureOpencodeAGENTSMD(opencodeDir string) error {
	path := filepath.Join(opencodeDir, "AGENTS.md")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !bytes.Contains(data, []byte(opencodeDirective)) {
		for _, legacy := range opencodeLegacyDirectives {
			if bytes.Contains(data, []byte(legacy)) {
				return os.WriteFile(path, bytes.Replace(data, []byte(legacy), []byte(opencodeDirective), 1), 0644)
			}
		}
	}
	return appendDirectiveOnce(path, opencodeDirective)
}
