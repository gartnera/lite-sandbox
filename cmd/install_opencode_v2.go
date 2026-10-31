package cmd

// opencode v2's config format: the MCP server under mcp.servers.<name>, and
// rules appended to the ordered permissions array.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

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
