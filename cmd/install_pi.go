package cmd

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/hook"
)

// piExtensionSource is the pi extension lite-sandbox installs, with
// piExtensionPlaceholder standing in for its configuration (see
// renderPiExtension).
//
//go:embed pi_extension.ts
var piExtensionSource string

const piExtensionPlaceholder = "__LITE_SANDBOX_CONFIG__"

// piExtensionFile is the extension's file name in pi's extensions directory,
// which pi loads every extension from at startup.
const piExtensionFile = "lite-sandbox.ts"

// piMinVersion is the oldest pi release the extension works with: 1.0.0 is
// the first with built-in MCP support (pi.registerMcpServer and exposure).
var piMinVersion = []int{1, 0, 0}

// piBuiltinBash is pi's built-in shell tool, which the installer removes from
// pi's default tools so the model is offered only the sandbox's.
const piBuiltinBash = "bash"

// piHookTimeoutSec bounds how long the extension waits for the hook. A
// boundary check that runs git or runtime detection on a cold cache must not
// be cut short, and a hook that never answers blocks the call.
const piHookTimeoutSec = 30

// piDirective is the system prompt section the extension adds in every
// session (pi has no global instructions file lite-sandbox could own; the
// extension carries it instead).
const piDirective = "ALWAYS use the `" + piMCPToolPrefix + "bash` tool for running shell commands. " +
	"It runs commands through lite-sandbox's AST validation and filesystem path boundaries, " +
	"and takes `run_in_background: true` for long-running commands (its result names the file their " +
	"output is written to; `" + piMCPToolPrefix + "list_shells` and `" + piMCPToolPrefix + "kill_shell` " +
	"manage background shells). The built-in `bash` tool is disabled and blocked. The `read`, `write`, " +
	"`edit`, `grep`, `find` and `ls` tools are confined to the same paths: reads outside the sandbox's " +
	"readable paths and writes outside its writable paths are blocked, as are writes into `.git`, " +
	"`.pi` and `.claude` directories."

// piAgentDir returns pi's agent directory: $PI_CODING_AGENT_DIR when set,
// otherwise ~/.pi/agent (config.PiAgentDir, shared with the built-in deny
// lists).
func piAgentDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil && os.Getenv("PI_CODING_AGENT_DIR") == "" {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return config.PiAgentDir(home), nil
}

func detectPi() bool {
	if cliOnPath("pi") {
		return true
	}
	dir, err := piAgentDir()
	return err == nil && dirExists(dir)
}

// piVersionOutput returns the output of `pi --version` for the pi on PATH. A
// variable so tests can stub it.
var piVersionOutput = func() (string, error) {
	out, err := exec.Command("pi", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// piVersionSupported reports whether the `pi --version` output names a
// release the extension works with (piMinVersion or later). Output without a
// parseable version (a development build) is assumed current.
func piVersionSupported(versionOutput string) bool {
	return versionAtLeast(versionOutput, piMinVersion...)
}

// checkPiVersion refuses a pi on PATH that is too old for the extension. When
// pi is not on PATH (only its agent directory was found) there is nothing to
// check.
func checkPiVersion() error {
	if !cliOnPath("pi") {
		return nil
	}
	out, err := piVersionOutput()
	if err != nil {
		return nil
	}
	if !piVersionSupported(out) {
		return fmt.Errorf("pi %s is too old: lite-sandbox needs pi %d.%d.%d or later, for its built-in MCP support (install it with `npm install -g @earendil-works/pi-coding-agent`; the older @mariozechner/pi-coding-agent package stops at 0.x)",
			strings.TrimSpace(out), piMinVersion[0], piMinVersion[1], piMinVersion[2])
	}
	return nil
}

// piPlan is what the install (or launch) flags resolve to for pi.
type piPlan struct {
	// configMCP registers the MCP server and the system prompt directive, and
	// disables the built-in bash tool. Off in --bash-ast-hook-mode.
	configMCP bool
	// validateBash AST-checks the built-in bash tool in the hook instead of
	// redirecting it (--bash-ast-hook-mode).
	validateBash bool
}

func newPiPlan(bashASTHookMode bool) piPlan {
	return piPlan{configMCP: !bashASTHookMode, validateBash: bashASTHookMode}
}

// piExtensionConfig is the configuration rendered into the extension. Keep
// the field names in sync with LiteSandboxConfig in pi_extension.ts.
type piExtensionConfig struct {
	Bin            string   `json:"bin"`
	MCP            bool     `json:"mcp"`
	ServeArgs      []string `json:"serveArgs"`
	HookArgs       []string `json:"hookArgs"`
	Tools          []string `json:"tools"`
	Directive      string   `json:"directive"`
	HookTimeoutSec int      `json:"hookTimeoutSec"`
}

func (p piPlan) extensionConfig(binPath string) piExtensionConfig {
	c := piExtensionConfig{
		Bin:            binPath,
		MCP:            p.configMCP,
		ServeArgs:      []string{"serve-mcp", "--config-requests"},
		Tools:          slices.Clone(hook.PiHookTools),
		HookTimeoutSec: piHookTimeoutSec,
	}
	if p.validateBash {
		// No MCP server to make config requests through.
		c.ServeArgs = nil
		c.HookArgs = []string{"hook", "--validate-bash"}
		return c
	}
	c.HookArgs = []string{"hook", "--config-requests"}
	// The sandbox's bash tool goes through the hook too, which puts config
	// requests and commands with ask: true to the user.
	c.Tools = append(c.Tools, piMCPToolPrefix+"bash")
	c.Directive = piDirective
	return c
}

// renderPiExtension returns the extension's source with the plan's
// configuration filled in.
func renderPiExtension(binPath string, p piPlan) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	if err := enc.Encode(p.extensionConfig(binPath)); err != nil {
		return "", err
	}
	if strings.Count(piExtensionSource, piExtensionPlaceholder) != 1 {
		return "", fmt.Errorf("pi extension template has no single %s placeholder", piExtensionPlaceholder)
	}
	return strings.Replace(piExtensionSource, piExtensionPlaceholder, strings.TrimSpace(buf.String()), 1), nil
}

// runInstallPi configures pi:
//
//   - <agent-dir>/extensions/lite-sandbox.ts: the extension, which registers
//     the MCP server, forwards pi's shell and file tool calls to the hook
//     (confining the file tools to the sandbox's paths: --with-tool-hook is
//     implied, since pi never asks before a tool call), and adds the usage
//     directive to the system prompt.
//   - <agent-dir>/settings.json: "-bash" in defaultTools, so the model is not
//     offered the built-in shell, and has no shell at all if the extension
//     fails to load.
//
// The agent directory is $PI_CODING_AGENT_DIR, or ~/.pi/agent.
func runInstallPi(binPath string) error {
	if err := checkPiVersion(); err != nil {
		return err
	}
	agentDir, err := piAgentDir()
	if err != nil {
		return err
	}
	plan := newPiPlan(installBashASTHookMode)
	extPath := filepath.Join(agentDir, "extensions", piExtensionFile)
	settingsPath := filepath.Join(agentDir, "settings.json")

	src, err := renderPiExtension(binPath, plan)
	if err != nil {
		return err
	}
	// Atomically, so a pi starting or reloading meanwhile never loads a
	// partial extension.
	if err := os.MkdirAll(filepath.Dir(extPath), 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(extPath), err)
	}
	if err := writeFileAtomic(extPath, []byte(src)); err != nil {
		return fmt.Errorf("failed to write %s: %w", extPath, err)
	}
	if plan.configMCP {
		fmt.Printf("✓ Wrote the lite-sandbox extension to %s (MCP server, file tools confined to sandbox paths, usage directive)\n", extPath)
	} else {
		fmt.Printf("✓ Wrote the lite-sandbox extension to %s (AST-checks built-in bash, which runs unsandboxed; file tools confined to sandbox paths)\n", extPath)
	}

	mcpDisabled, err := configurePiSettings(settingsPath, plan)
	if err != nil {
		return fmt.Errorf("failed to configure %s: %w", settingsPath, err)
	}
	if plan.configMCP {
		fmt.Printf("✓ Disabled the built-in bash tool in %s\n", settingsPath)
	} else {
		fmt.Printf("✓ Ensured the built-in bash tool is enabled in %s (checked by the extension)\n", settingsPath)
	}
	if mcpDisabled && plan.configMCP {
		fmt.Printf("! %s disables pi's built-in MCP support (-builtin:mcp), so the sandbox's\n", settingsPath)
		fmt.Println("  bash tool will not connect and pi will have no shell. Remove that entry, or")
		fmt.Println("  use --bash-ast-hook-mode.")
	}

	fmt.Println("\n✓ pi installation complete!")
	if installBashASTHookMode {
		fmt.Println("(--bash-ast-hook-mode: MCP server not configured)")
	}
	fmt.Println("Restart pi (or run /reload) for the changes to take effect; /mcp lists the lite-sandbox server.")
	return nil
}

// configurePiSettings makes defaultTools in pi's settings.json match the
// plan, preserving every other setting. It reports whether the settings
// disable pi's built-in MCP extension.
//
// With the MCP server, "-bash" is appended to defaultTools after removing any
// other entry for bash. pi applies plain names as the selection and +/-
// entries after them, in order, so this removes bash from a list of plain
// names, a list of modifiers, or no list (the defaults) alike. An empty list
// already disables every built-in tool and is left alone, since "-bash" alone
// would turn it into "the defaults without bash". In --bash-ast-hook-mode a
// "-bash" entry is removed instead.
func configurePiSettings(settingsPath string, p piPlan) (mcpDisabled bool, err error) {
	cfg := map[string]json.RawMessage{}
	data, err := os.ReadFile(settingsPath)
	switch {
	case os.IsNotExist(err):
		data = nil
	case err != nil:
		return false, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return false, fmt.Errorf("failed to parse: %w", err)
		}
	}
	if cfg == nil {
		// The file held JSON null.
		cfg = map[string]json.RawMessage{}
	}

	var extensions []string
	if raw, ok := cfg["extensions"]; ok {
		if err := json.Unmarshal(raw, &extensions); err != nil {
			return false, fmt.Errorf("failed to parse extensions: %w", err)
		}
	}
	mcpDisabled = slices.Contains(extensions, "-builtin:mcp")

	var tools []string
	raw, hadTools := cfg["defaultTools"]
	if hadTools {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return false, fmt.Errorf("failed to parse defaultTools: %w", err)
		}
	}
	updated := slices.Clone(tools)
	if p.configMCP {
		if !hadTools || len(tools) > 0 {
			updated = slices.DeleteFunc(updated, func(s string) bool {
				return s == piBuiltinBash || s == "+"+piBuiltinBash || s == "-"+piBuiltinBash
			})
			updated = append(updated, "-"+piBuiltinBash)
		}
	} else {
		updated = slices.DeleteFunc(updated, func(s string) bool { return s == "-"+piBuiltinBash })
	}

	switch {
	case slices.Equal(tools, updated) && (hadTools || len(updated) == 0):
		// Unchanged: leave the file as it is (or absent).
		return mcpDisabled, nil
	case len(updated) == 0 && len(tools) > 0:
		// Removing our entry emptied the list; an empty list would disable
		// every built-in tool, so drop the key and get the defaults back.
		delete(cfg, "defaultTools")
	default:
		b, err := json.Marshal(updated)
		if err != nil {
			return false, err
		}
		cfg["defaultTools"] = b
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	return mcpDisabled, writeFileMkdir(settingsPath, append(out, '\n'))
}
