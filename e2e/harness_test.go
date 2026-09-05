package e2e

import (
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/e2e/mockmodel"
)

// The scenario every agent runs. The mock model asks the agent to run a
// command the sandbox must reject (curl is not whitelisted), then one it must
// run, and finally reports what the second one printed. The prompt is only
// there to look plausible; the mock never reads it.
const (
	blockedCommand = "curl http://example.com"
	allowedCommand = "echo hello-from-sandbox"
	allowedOutput  = "hello-from-sandbox"
	prompt         = "Run the command echo hello-from-sandbox and tell me what it printed."
	finalPrefix    = "The sandbox printed: "
	// curlRejected is the sandbox's whitelist rejection, as fed back to the model.
	curlRejected = `command "curl" is not allowed`
)

// sandboxCalls scripts the two sandbox commands as calls to the agent's name
// for the sandbox bash tool. Callers may prepend agent-specific calls (e.g. a
// call to the built-in shell that a hook must block).
func sandboxCalls(sandboxTool string) []mockmodel.ToolCall {
	var calls []mockmodel.ToolCall
	for _, command := range []string{blockedCommand, allowedCommand} {
		calls = append(calls, mockmodel.ToolCall{Name: sandboxTool, Arguments: map[string]string{"command": command}})
	}
	return calls
}

// startModel starts the mock model for a scripted list of calls. Its final
// answer quotes the last tool result, which the tests look for in the agent's
// output to prove the sandbox's result made the round trip.
func startModel(t *testing.T, calls []mockmodel.ToolCall) *mockmodel.Server {
	t.Helper()
	model := mockmodel.Start(mockmodel.Script{
		ToolCalls: calls,
		FinalText: func(results []string) string { return finalPrefix + strings.TrimSpace(results[len(results)-1]) },
	})
	t.Cleanup(model.Close)
	return model
}

// env builds the environment for a subprocess: a minimal base (so nothing from
// the developer's real agent setups leaks in) plus extra KEY=VALUE pairs. PATH
// starts with the provisioned binaries.
func env(home string, extra ...string) []string {
	path := strings.Join(bins.pathDirs, string(os.PathListSeparator)) + string(os.PathListSeparator) + os.Getenv("PATH")
	base := []string{"PATH=" + path, "HOME=" + home, "NO_COLOR=1", "TERM=dumb"}
	for _, k := range []string{"TMPDIR", "LANG", "LC_ALL"} {
		if v := os.Getenv(k); v != "" {
			base = append(base, k+"="+v)
		}
	}
	return append(base, extra...)
}

// installSandbox runs `lite-sandbox install <agent>` under environ and fails
// the test if it does not succeed.
func installSandbox(t *testing.T, agent string, environ []string) {
	t.Helper()
	cmd := exec.Command(bins.sandbox, "install", agent)
	cmd.Env = environ
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("lite-sandbox install %s failed: %v\n%s", agent, err, out)
	}
	t.Logf("lite-sandbox install %s:\n%s", agent, out)
}

// runAgent runs one non-interactive agent invocation in dir and returns its
// combined output. stdin is /dev/null (Codex otherwise waits for more input).
// A failing exit is reported but not fatal: some agents exit non-zero on a
// mock protocol hiccup and the output is what explains it.
func runAgent(t *testing.T, dir string, environ []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = environ
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Logf("%s %s:\n%s", filepath.Base(name), strings.Join(args, " "), output)
	if err != nil {
		t.Errorf("%s exited with error: %v", filepath.Base(name), err)
	}
	return output
}

// newProject creates an empty working directory for the agent to run in, with
// a git repo so agents that insist on one (Codex) are happy.
func newProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

// assertConversation checks what every agent must have done, independent of
// the wire protocol it used:
//
//   - its output contains the mock's final answer quoting the sandbox output;
//   - it took at least one agent turn per scripted call plus the answer;
//   - the first agent turn offered the sandbox tool;
//   - the tool results it fed back end with curl rejected by the whitelist and
//     the allowed command's output — i.e. the sandbox, not a built-in shell,
//     ran the commands. A tool result the sandbox refused (curl) must not be
//     mistaken for the built-in shell having run it, so it is matched on the
//     sandbox's own rejection text.
//
// It returns the tools offered on the first turn for agent-specific checks.
func assertConversation(t *testing.T, output string, model *mockmodel.Server, calls []mockmodel.ToolCall, sandboxTool string) map[string]bool {
	t.Helper()
	if _, answer, ok := strings.Cut(output, finalPrefix); !ok || !strings.Contains(answer, allowedOutput) {
		t.Errorf("final answer missing the sandboxed command's output")
	}
	turns := model.AgentTurns()
	if want := len(calls) + 1; len(turns) < want {
		t.Fatalf("expected at least %d agent turns (%d tool calls + answer), got %d (protocols: %v)", want, len(calls), len(turns), protocols(model))
	}
	tools := turns[0].Tools
	t.Logf("tools offered on the first agent turn (%s): %v", turns[0].Protocol, slices.Sorted(maps.Keys(tools)))
	if !tools[sandboxTool] {
		t.Errorf("sandbox tool %s not offered to the model", sandboxTool)
	}

	results := turns[len(turns)-1].ToolResults
	t.Logf("tool results fed back: %q", results)
	if len(results) != len(calls) {
		t.Fatalf("expected %d tool results, got %d", len(calls), len(results))
	}
	if got := results[len(results)-2]; !strings.Contains(got, curlRejected) {
		t.Errorf("sandbox did not reject curl: %q", got)
	}
	// Agents may wrap results in their own framing (Codex adds timing lines),
	// so look for the output rather than requiring it verbatim.
	if got := results[len(results)-1]; !strings.Contains(got, allowedOutput) {
		t.Errorf("tool result is not the sandbox's output: %q", got)
	}
	return tools
}

func protocols(model *mockmodel.Server) []string {
	var out []string
	for _, turn := range model.Turns() {
		out = append(out, turn.Protocol)
	}
	return out
}

// writeFile writes content to path, creating parent directories.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
