package mockedserver

// opencode v2 differs from v1 in nearly every way the sandbox touches: its
// config format (mcp.servers, an ordered permissions array where the last
// matching rule wins), the built-in shell's name (shell), how MCP tools reach
// the model (through Code Mode: a program for the execute tool calls
// tools["lite-sandbox"].bash), when they arrive (MCP servers connect in the
// background, so a server's tools appear from the turn after it connects),
// and where sessions run (a shared background service by default). These
// tests drive the v2 binary, put first on PATH so `lite-sandbox install
// opencode` and `launch opencode` detect it.

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

// opencodeV2Calls scripts the sandbox commands as Code Mode programs.
func opencodeV2Calls(t *testing.T) []mockmodel.ToolCall {
	t.Helper()
	var calls []mockmodel.ToolCall
	for _, c := range sandboxCalls(opencodeSandboxTool) {
		command, err := json.Marshal(c.Arguments.(map[string]string)["command"])
		if err != nil {
			t.Fatal(err)
		}
		code := fmt.Sprintf(`try { return await %s({ command: %s }) } catch (e) { return String(e) }`, opencodeV2CodeModeBash, command)
		calls = append(calls, mockmodel.ToolCall{Name: "execute", Arguments: map[string]string{"code": code}})
	}
	return calls
}

// opencodeV2Env is opencodeEnv with the v2 binary first on PATH.
func opencodeV2Env(t *testing.T, model *mockmodel.Server, extra map[string]any) (configDir, project string, environ []string) {
	t.Helper()
	configDir, project, environ = opencodeEnv(t, model, extra)
	path := strings.Join(append([]string{filepath.Dir(bins.opencodeV2)}, bins.pathDirs...), string(os.PathListSeparator)) +
		string(os.PathListSeparator) + os.Getenv("PATH")
	environ = slices.DeleteFunc(environ, func(kv string) bool { return strings.HasPrefix(kv, "PATH=") })
	return configDir, project, append(environ, "PATH="+path)
}

// assertOpencodeV2Conversation checks what both v2 tests share: the sandbox's
// results made the round trip through Code Mode, the built-in shell is gone,
// the sandbox tool is only in the Code Mode catalog, and the directive arrived.
// turn is the (0-based) agent turn whose Code Mode catalog must list the tool.
func assertOpencodeV2Conversation(t *testing.T, output string, model *mockmodel.Server, calls []mockmodel.ToolCall, turn int) {
	t.Helper()
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
	if turns := model.AgentTurns(); len(turns) <= turn || !strings.Contains(turns[turn].Text, opencodeV2CodeModeBash) {
		t.Errorf("Code Mode catalog on agent turn %d does not list %s", turn+1, opencodeV2CodeModeBash)
	}
	assertDirective(t, model, "`bash` tool from the `lite-sandbox` MCP server")
}

// TestOpencodeV2 drives `lite-sandbox install opencode` against v2, which must
// write v2's native format, then a run. The instant mock would outrun the MCP
// server's background connect, so the test starts `opencode serve`, waits for
// `opencode mcp list` to report the sandbox connected, and only then runs the
// prompt against that server (as the TUI does against v2's background
// service).
func TestOpencodeV2(t *testing.T) {
	requireE2E(t)

	calls := opencodeV2Calls(t)
	model := startModel(t, calls)
	configDir, project, environ := opencodeV2Env(t, model, nil)

	installSandbox(t, "opencode", environ)
	assertOpencodeConfigFormat(t, configDir, true)

	// serve requires a password (it generates one when none is set); share
	// one with the clients.
	environ = append(environ, "OPENCODE_PASSWORD=e2e")
	server := startOpencodeServer(t, project, environ)
	output := runAgent(t, project, environ, bins.opencodeV2, "run", "--server", server, "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	assertOpencodeV2Conversation(t, output, model, calls, 0)
}

// TestOpencodeV2Launch drives `lite-sandbox launch opencode run ...` against
// v2: v2's native inline config, and --standalone, without which the session
// would go to v2's shared background service, which never sees the inline
// config. With no server to poll, the mock holds its first reply (a harmless
// read) until the sandbox has connected, and the Code Mode calls follow.
func TestOpencodeV2Launch(t *testing.T) {
	requireE2E(t)

	project := newProject(t)
	calls := append([]mockmodel.ToolCall{{Name: "read", Arguments: map[string]string{"path": project}}}, opencodeV2Calls(t)...)
	model := mockmodel.Start(mockmodel.Script{
		ToolCalls:      calls,
		FinalText:      func(results []string) string { return finalPrefix + strings.TrimSpace(results[len(results)-1]) },
		FirstTurnDelay: 3 * time.Second,
	})
	t.Cleanup(model.Close)
	configDir, _, environ := opencodeV2Env(t, model, nil)
	before := readFile(t, filepath.Join(configDir, "opencode.json"))

	output := runAgent(t, project, environ, bins.sandbox,
		"launch", "opencode", "run", "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	assertOpencodeV2Conversation(t, output, model, calls, 1)
	if !strings.Contains(output, "--standalone") {
		t.Errorf("launch did not note running opencode v2 --standalone")
	}
	if after := readFile(t, filepath.Join(configDir, "opencode.json")); after != before {
		t.Errorf("launch changed opencode.json:\n%s", after)
	}
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
	data, err := os.ReadFile(filepath.Join(configDir, "opencode.json"))
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
