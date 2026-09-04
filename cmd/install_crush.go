package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// crushServerName is the name lite-sandbox is registered under in Crush's MCP
// config. Crush namespaces MCP tools as mcp_<server>_<tool>.
const crushServerName = "lite-sandbox"

// crushToolPermissions are the Crush tool names of the sandbox's MCP tools —
// the bash tool and its background-process companions — as they appear in
// permissions.allowed_tools. Keep in sync with the tools registered in
// newMCPServer.
var crushToolPermissions = []string{
	"mcp_" + crushServerName + "_bash",
	"mcp_" + crushServerName + "_bash_output",
	"mcp_" + crushServerName + "_kill_shell",
	"mcp_" + crushServerName + "_list_shells",
}

// crushDirective is appended to the global CRUSH.md so Crush prefers the
// sandboxed bash tool. It names the tool the way Crush exposes it.
const crushDirective = "ALWAYS use the `mcp_lite-sandbox_bash` tool for running shell commands. The built-in " +
	"`bash` tool is disabled and not available. The sandboxed tool is pre-approved and requires no " +
	"permission prompts; it runs commands through lite-sandbox's AST validation and filesystem path boundaries."

// Crush's current config format is crushrc — a Bash script of Crush builtins
// (mcp add, permissions allow/deny, ...) — which is awkward to update in place
// with a parser. Instead we own a single marker-delimited block appended to the
// file: reconciling means removing the old block and appending a fresh one,
// leaving all other content untouched. Because the builtins are additive
// (`mcp add` updates the entry with the same name, `permissions` appends
// without duplicating), appending the block last is also what lets it win over
// any earlier user definition of the same server.
const (
	crushBlockStart = "# >>> lite-sandbox (managed by `lite-sandbox install crush`) — do not edit inside >>>"
	crushBlockEnd   = "# <<< lite-sandbox (managed by `lite-sandbox install crush`) <<<"
)

// crushSchemaURL is Crush's published JSON schema for crush.json.
const crushSchemaURL = "https://charm.land/crush.json"

// crushConfigDir returns Crush's global configuration directory, resolved the
// way Crush itself does: $CRUSH_GLOBAL_CONFIG when set, otherwise
// $XDG_CONFIG_HOME/crush, otherwise ~/.config/crush. Crush uses the XDG layout
// on every platform (including macOS and Windows).
func crushConfigDir() (string, error) {
	if d := os.Getenv("CRUSH_GLOBAL_CONFIG"); d != "" {
		return d, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "crush"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".config", "crush"), nil
}

func detectCrush() bool {
	if cliOnPath("crush") {
		return true
	}
	dir, err := crushConfigDir()
	return err == nil && dirExists(dir)
}

// runInstallCrush configures Crush (charmbracelet/crush) to use lite-sandbox.
// Like the opencode install there is a single mode:
//
//   - register the MCP server (`lite-sandbox serve-mcp`, stdio) under the
//     name lite-sandbox;
//   - hide the built-in bash tool from the agent (Crush's `permissions deny
//     bash`, i.e. options.disabled_tools — the analogue of the Claude
//     installer's Bash permission deny) and auto-allow the sandbox's tools via
//     permissions.allowed_tools so they never prompt;
//   - append a usage directive to the global CRUSH.md, which Crush loads into
//     every session.
//
// Crush reads two global config files from its config directory: crushrc (the
// current Bash-based format) and crush.json (the legacy JSON format, still
// loaded but deprecated), merging both with crushrc taking precedence. We edit
// whichever exists — crushrc when both do — and when neither exists create a
// crushrc, unless the installed crush predates the format (v0.88.0), in which
// case a crush.json is created so the install still takes effect.
//
// Crush's hooks are Claude Code-compatible in protocol, but its built-in tools
// are named differently (bash, view, edit, ...) from what `lite-sandbox hook`
// governs, so the hook-based modes don't apply: --with-tool-hook is a no-op
// here and --bash-ast-hook-mode skips Crush entirely.
func runInstallCrush(binPath string) error {
	if installBashASTHookMode {
		fmt.Println("⚠ lite-sandbox's hook does not govern Crush's built-in tools, so --bash-ast-hook-mode cannot AST-check its bash tool — skipping Crush.")
		fmt.Println("  Run `lite-sandbox install crush` (without the flag) for the standard Crush setup.")
		return nil
	}

	crushDir, err := crushConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(crushDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", crushDir, err)
	}

	rcPath := filepath.Join(crushDir, "crushrc")
	jsonPath := filepath.Join(crushDir, "crush.json")

	useRC := true
	created := false
	switch {
	case fileExists(rcPath):
	case fileExists(jsonPath):
		useRC = false
	default:
		created = true
		// Nothing to edit: pick the format the installed crush understands.
		if out, err := crushVersionOutput(); err == nil && !crushVersionSupportsRC(out) {
			useRC = false
			fmt.Printf("ℹ Installed crush (%s) predates the crushrc config format; writing crush.json instead.\n", strings.TrimSpace(out))
		}
	}

	configPath := rcPath
	if useRC {
		err = configureCrushRC(rcPath, binPath)
	} else {
		configPath = jsonPath
		err = configureCrushJSON(jsonPath, binPath)
	}
	if err != nil {
		return fmt.Errorf("failed to configure Crush: %w", err)
	}
	fmt.Printf("✓ Added MCP server, disabled the built-in bash tool, and auto-allowed the sandbox tools in %s\n", configPath)

	if err := configureCrushCRUSHMD(crushDir); err != nil {
		return fmt.Errorf("failed to configure CRUSH.md: %w", err)
	}
	fmt.Printf("✓ Added usage directive to %s\n", filepath.Join(crushDir, "CRUSH.md"))

	fmt.Println("\n✓ Crush installation complete!")
	if installWithToolHook {
		fmt.Println("(--with-tool-hook: lite-sandbox's hook does not govern Crush's built-in file tools, so the flag does not apply to it)")
	}
	if useRC && created {
		fmt.Println("(crushrc requires crush v0.88.0 or newer; see the docs for the equivalent crush.json on older versions)")
	}
	fmt.Println("Restart Crush for the changes to take effect.")
	return nil
}

// crushVersionOutput returns the output of `crush --version` for the crush on
// PATH. A variable so tests can stub it.
var crushVersionOutput = func() (string, error) {
	out, err := exec.Command("crush", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

var semverRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// crushVersionSupportsRC reports whether the `crush --version` output names a
// release that reads crushrc (v0.88.0 and later). Output without a parseable
// version (a dev/nightly build) is assumed current.
func crushVersionSupportsRC(versionOutput string) bool {
	m := semverRe.FindStringSubmatch(versionOutput)
	if m == nil {
		return true
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return slices.Compare(v[:], []int{0, 88, 0}) >= 0
}

// configureCrushRC registers the lite-sandbox MCP server and the tool
// permission rules in a crushrc, creating the file if needed. It owns one
// marker-delimited block at the end of the file: any prior block is removed
// and a fresh one appended, so re-running (or a changed binary path)
// converges to a single block and the user's own content is untouched.
func configureCrushRC(rcPath, binPath string) error {
	quoted, err := syntax.Quote(binPath, syntax.LangBash)
	if err != nil {
		return fmt.Errorf("cannot quote binary path %q for crushrc: %w", binPath, err)
	}
	block := crushBlockStart + "\n" +
		"mcp add " + crushServerName + " --type stdio --command " + quoted + " --args serve-mcp\n" +
		// Hide the built-in shell so Crush must use the sandbox (this is
		// options.disabled_tools; the tool disappears from the agent entirely).
		"permissions deny bash\n" +
		// Auto-allow the sandbox's own tools so they never prompt, mirroring
		// the Claude installer's allow entries.
		"permissions allow " + strings.Join(crushToolPermissions, " ") + "\n" +
		crushBlockEnd + "\n"

	data, err := os.ReadFile(rcPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		data = nil
	}
	content := stripManagedBlock(string(data), crushBlockStart, crushBlockEnd)
	return os.WriteFile(rcPath, []byte(appendConfigBlock(content, block)), 0644)
}

// crushMCPStdio is the stdio MCPConfig shape from Crush's config schema
// (https://charm.land/crush.json).
type crushMCPStdio struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// configureCrushJSON applies the same configuration as configureCrushRC to the
// legacy crush.json: mcp.lite-sandbox, "bash" in options.disabled_tools, and
// the sandbox tools in permissions.allowed_tools. All other keys — and unknown
// fields inside mcp/options/permissions — are preserved by round-tripping them
// as raw JSON. Idempotent: re-running rewrites the same entries in place. Crush
// requires strict JSON here (no comments), so encoding/json is sufficient.
func configureCrushJSON(configPath, binPath string) error {
	cfg := make(map[string]json.RawMessage)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	if _, ok := cfg["$schema"]; !ok {
		cfg["$schema"] = json.RawMessage(strconv.Quote(crushSchemaURL))
	}

	// mcp.lite-sandbox — a stdio server launched via `lite-sandbox serve-mcp`.
	mcp, err := rawObject(cfg, "mcp", configPath)
	if err != nil {
		return err
	}
	serverRaw, err := json.Marshal(crushMCPStdio{
		Type:    "stdio",
		Command: binPath,
		Args:    []string{"serve-mcp"},
	})
	if err != nil {
		return err
	}
	mcp[crushServerName] = serverRaw
	if cfg["mcp"], err = json.Marshal(mcp); err != nil {
		return err
	}

	// options.disabled_tools += "bash": hide the built-in shell from the agent.
	opts, err := rawObject(cfg, "options", configPath)
	if err != nil {
		return err
	}
	if err := appendRawStrings(opts, "disabled_tools", []string{"bash"}, configPath); err != nil {
		return err
	}
	if cfg["options"], err = json.Marshal(opts); err != nil {
		return err
	}

	// permissions.allowed_tools += the sandbox tools: never prompt for them.
	perms, err := rawObject(cfg, "permissions", configPath)
	if err != nil {
		return err
	}
	if err := appendRawStrings(perms, "allowed_tools", crushToolPermissions, configPath); err != nil {
		return err
	}
	if cfg["permissions"], err = json.Marshal(perms); err != nil {
		return err
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, append(out, '\n'), 0644)
}

// rawObject returns cfg[key] decoded as a JSON object (empty when absent),
// erroring if the key holds something other than an object.
func rawObject(cfg map[string]json.RawMessage, key, configPath string) (map[string]json.RawMessage, error) {
	obj := make(map[string]json.RawMessage)
	if raw, ok := cfg[key]; ok {
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("failed to parse %s in %s: %w", key, configPath, err)
		}
	}
	return obj, nil
}

// appendRawStrings adds each of values to the string array obj[key] (created if
// absent), skipping ones already present, and stores the result back.
func appendRawStrings(obj map[string]json.RawMessage, key string, values []string, configPath string) error {
	var list []string
	if raw, ok := obj[key]; ok {
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("failed to parse %s in %s: %w", key, configPath, err)
		}
	}
	for _, v := range values {
		if !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	obj[key] = raw
	return nil
}

// configureCrushCRUSHMD appends the usage directive to the global CRUSH.md,
// which Crush includes in every session's context. Idempotent; existing
// content is preserved.
func configureCrushCRUSHMD(crushDir string) error {
	return appendDirectiveOnce(filepath.Join(crushDir, "CRUSH.md"), crushDirective)
}
