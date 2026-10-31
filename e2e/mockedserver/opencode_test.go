package mockedserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// opencodeSandboxTool is the sandbox bash tool under opencode's <server>_<tool>
// naming (the same in v1 and v2).
const opencodeSandboxTool = "lite-sandbox_bash"

// opencodeEnv returns the environment for an opencode run plus its config
// directory. opencode follows the XDG layout for config, data, cache, and
// state; each points at a temp directory so nothing of the real user's is read
// or written. PATH, when given, replaces env's.
func opencodeEnv(t *testing.T, path string) (environ []string, configDir string) {
	t.Helper()
	configDir = t.TempDir()
	environ = env(t.TempDir(),
		"XDG_CONFIG_HOME="+configDir,
		"XDG_DATA_HOME="+t.TempDir(),
		"XDG_CACHE_HOME="+t.TempDir(),
		"XDG_STATE_HOME="+t.TempDir(),
	)
	if path != "" {
		environ = slices.DeleteFunc(environ, func(kv string) bool { return strings.HasPrefix(kv, "PATH=") })
		environ = append(environ, "PATH="+path)
	}
	return environ, configDir
}

// writeOpencodeProviderConfig writes the provider half of opencode.json — what
// a user would already have: the mock as an OpenAI-compatible provider (that
// provider package is bundled, so no runtime install), with auto-update and
// sharing off. It is written in v1's format, which v2 also reads.
func writeOpencodeProviderConfig(t *testing.T, configDir string, model *mockmodel.Server) {
	t.Helper()
	cfg := map[string]any{
		"$schema":     "https://opencode.ai/config.json",
		"autoupdate":  false,
		"share":       "disabled",
		"model":       "mock/" + model.ModelID,
		"small_model": "mock/" + model.ModelID,
		"provider": map[string]any{
			"mock": map[string]any{
				"npm":     "@ai-sdk/openai-compatible",
				"name":    "Mock",
				"options": map[string]any{"baseURL": model.BaseURL, "apiKey": "dummy"},
				"models":  map[string]any{model.ModelID: map[string]any{"name": "Mock"}},
			},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(configDir, "opencode", "opencode.json"), string(b))
}

// TestOpencode drives opencode v1 through `lite-sandbox install opencode` and a
// non-interactive `opencode run`. It proves opencode loads the generated
// global config, launches `lite-sandbox serve-mcp` and offers its tools, no
// longer runs the built-in bash tool (permission deny), executes the sandboxed
// commands and feeds the results back, and saw the AGENTS.md directive.
// opencode has no hook protocol, so there is a single install mode.
func TestOpencode(t *testing.T) {
	requireE2E(t)

	calls := sandboxCalls(opencodeSandboxTool)
	model := startModel(t, calls)
	project := newProject(t)
	environ, configDir := opencodeEnv(t, "")
	writeOpencodeProviderConfig(t, configDir, model)

	installSandbox(t, "opencode", environ)
	assertOpencodeConfigFormat(t, configDir, false)

	output := runAgent(t, project, environ, bins.opencode, "run", "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	tools := assertConversation(t, output, model, calls, opencodeSandboxTool, true)
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model despite the permission deny")
	}
	if !tools["read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	assertDirective(t, model, "`bash` tool from the `lite-sandbox` MCP server")
}

// TestOpencodeV2 is TestOpencode against opencode v2, whose config format
// differs (mcp.servers, an ordered permissions array, the built-in shell named
// shell). With the v2 binary first on PATH, `lite-sandbox install opencode`
// must detect v2 from `opencode --version` and write v2's native format.
//
// v2 reaches MCP tools through Code Mode by default, so each scripted call is
// a program for the execute tool that calls tools["lite-sandbox"].bash. v2
// also connects MCP servers in the background and only offers a server's
// tools from the turn after it connects, which the instant mock would outrun,
// so the test starts `opencode serve`, waits for `opencode mcp list` to report
// the sandbox connected, and only then runs the prompt against that server
// (as the TUI does against v2's background service).
func TestOpencodeV2(t *testing.T) {
	requireE2E(t)

	var calls []mockmodel.ToolCall
	for _, c := range sandboxCalls(opencodeSandboxTool) {
		command, err := json.Marshal(c.Arguments.(map[string]string)["command"])
		if err != nil {
			t.Fatal(err)
		}
		code := fmt.Sprintf(`try { return await %s({ command: %s }) } catch (e) { return String(e) }`, opencodeV2CodeModeBash, command)
		calls = append(calls, mockmodel.ToolCall{Name: "execute", Arguments: map[string]string{"code": code}})
	}
	model := startModel(t, calls)
	project := newProject(t)
	path := strings.Join(append([]string{filepath.Dir(bins.opencodeV2)}, bins.pathDirs...), string(os.PathListSeparator)) +
		string(os.PathListSeparator) + os.Getenv("PATH")
	environ, configDir := opencodeEnv(t, path)
	writeOpencodeProviderConfig(t, configDir, model)

	installSandbox(t, "opencode", environ)
	assertOpencodeConfigFormat(t, configDir, true)

	// serve requires a password (it generates one when none is set); share
	// one with the clients.
	environ = append(environ, "OPENCODE_PASSWORD=e2e")
	server := startOpencodeServer(t, project, environ)
	output := runAgent(t, project, environ, bins.opencodeV2, "run", "--server", server, "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	tools := assertConversation(t, output, model, calls, "execute", true)
	if tools["shell"] || tools["bash"] {
		t.Errorf("built-in shell tool still offered to the model despite the permission deny")
	}
	if tools[opencodeSandboxTool] {
		t.Errorf("sandbox tool offered directly; want it only through Code Mode")
	}
	if !tools["read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	if turns := model.AgentTurns(); len(turns) == 0 || !strings.Contains(turns[0].Text, opencodeV2CodeModeBash) {
		t.Errorf("Code Mode catalog on the first turn does not list %s", opencodeV2CodeModeBash)
	}
	assertDirective(t, model, "`bash` tool from the `lite-sandbox` MCP server")
}

// opencodeV2CodeModeBash is how v2's Code Mode exposes the sandbox bash tool:
// the server name is not a JavaScript identifier, so it is bracketed.
const opencodeV2CodeModeBash = `tools["lite-sandbox"].bash`

// startOpencodeServer starts `opencode serve` (v2) in dir and returns its URL
// once `opencode mcp list` reports the lite-sandbox server connected. The
// server and its children (serve-mcp) are killed when the test ends.
func startOpencodeServer(t *testing.T, dir string, environ []string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	var logs bytes.Buffer
	cmd := exec.Command(bins.opencodeV2, "serve", "--hostname", "127.0.0.1", "--port", strconv.Itoa(port))
	cmd.Dir = dir
	cmd.Env = environ
	cmd.Stdout, cmd.Stderr = &logs, &logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Logf("opencode serve:\n%s", logs.String())
	})

	deadline := time.Now().Add(agentTimeout)
	var last string
	for time.Now().Before(deadline) {
		list := exec.Command(bins.opencodeV2, "mcp", "list", "--server", url)
		list.Dir = dir
		list.Env = environ
		out, _ := list.CombinedOutput()
		last = string(out)
		for _, line := range strings.Split(last, "\n") {
			if f := strings.Fields(line); len(f) >= 3 && f[1] == "lite-sandbox" && f[2] == "connected" {
				return url
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("lite-sandbox never connected to opencode serve; last `opencode mcp list`:\n%s", last)
	return ""
}

// assertOpencodeConfigFormat checks which config format the install wrote:
// v2's mcp.servers and permissions array, or v1's mcp.<name> and permission
// map.
func assertOpencodeConfigFormat(t *testing.T, configDir string, v2 bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(configDir, "opencode", "opencode.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCP         map[string]json.RawMessage `json:"mcp"`
		Permission  json.RawMessage            `json:"permission"`
		Permissions json.RawMessage            `json:"permissions"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("opencode.json: %v", err)
	}
	_, v1Server := cfg.MCP["lite-sandbox"]
	_, v2Servers := cfg.MCP["servers"]
	if got := v2Servers && cfg.Permissions != nil && !v1Server && cfg.Permission == nil; got != v2 {
		t.Errorf("install wrote the wrong opencode config format (want v2: %v):\n%s", v2, data)
	}
}
