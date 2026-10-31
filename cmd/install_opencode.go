package cmd

// opencode support shared by its two majors: where the global config lives,
// which major is installed, the install entry point (which dispatches to the
// v1 writer in install_opencode_v1.go or the v2 writer in
// install_opencode_v2.go), and the AGENTS.md usage directive.
//
// v1 and v2 differ enough to be treated as two agents that share a binary
// name: v2 moved MCP servers under mcp.servers, replaced the permission map
// with an ordered permissions array (last match wins), renamed the built-in
// bash tool to shell, reaches MCP tools through Code Mode by default, and runs
// sessions on a shared background service.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
