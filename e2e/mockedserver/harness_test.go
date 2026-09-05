package mockedserver

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

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
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
	// The same text appears whether the MCP tool or the AST-validating hook did
	// the rejecting.
	curlRejected = `command "curl" is not allowed`
)

// Fragments of the PreToolUse hook's deny reasons (see cmd/hook.go), as the
// agents feed them back to the model.
const (
	// hookBlockedShell is the redirect the hook issues for the built-in shell
	// when it is not validating it in place.
	hookBlockedShell = "the built-in Bash tool is disabled"
	// hookRejectedCommand is the AST-validating hook's denial (--bash-ast-hook-mode).
	hookRejectedCommand = "did not pass sandbox validation"
	// hookOutsideWritable is the path-boundary denial for a file write.
	hookOutsideWritable = "outside the sandbox's writable paths"
	// outsidePath is a write target no default config allows (the denial means
	// nothing is written).
	outsidePath = "/etc/lite-sandbox-e2e-denied.txt"
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
//
// Nothing in these runs should reach the network: the model is the local mock
// and each agent's update/telemetry calls are switched off where it offers a
// switch (Crush's version check has none). HTTPS_PROXY points every remaining
// https request at a closed loopback port so it fails fast and identically on
// every machine instead of depending on connectivity. The mock is plain http
// on loopback, which NO_PROXY keeps off the proxy (Claude Code would otherwise
// send it there too).
func env(home string, extra ...string) []string {
	path := strings.Join(bins.pathDirs, string(os.PathListSeparator)) + string(os.PathListSeparator) + os.Getenv("PATH")
	base := []string{"PATH=" + path, "HOME=" + home, "NO_COLOR=1", "TERM=dumb",
		"HTTPS_PROXY=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost"}
	for _, k := range []string{"TMPDIR", "LANG", "LC_ALL"} {
		if v := os.Getenv(k); v != "" {
			base = append(base, k+"="+v)
		}
	}
	return append(base, extra...)
}

// installSandbox runs `lite-sandbox install <agent> [flags...]` under environ
// and fails the test if it does not succeed.
func installSandbox(t *testing.T, agent string, environ []string, flags ...string) {
	t.Helper()
	args := append([]string{"install", agent}, flags...)
	cmd := exec.Command(bins.sandbox, args...)
	cmd.Env = environ
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("lite-sandbox %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	t.Logf("lite-sandbox %s:\n%s", strings.Join(args, " "), out)
}

// agentTimeout bounds one agent invocation. A healthy run takes about a
// second; the budget only matters when something is wrong, and it is kept
// well inside `go test`'s default 10-minute binary timeout even if every
// invocation in the suite hits it.
const agentTimeout = 2 * time.Minute

// runAgent runs one non-interactive agent invocation in dir and returns its
// combined output. stdin is /dev/null (Codex otherwise waits for more input).
// A failing exit is reported but not fatal: some agents exit non-zero on a
// mock protocol hiccup and the output is what explains it.
func runAgent(t *testing.T, dir string, environ []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), agentTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = environ
	// The agents spawn `lite-sandbox serve-mcp`, which inherits the output pipe;
	// without WaitDelay a timed-out agent whose child kept the pipe open would
	// block CombinedOutput indefinitely.
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Logf("%s %s:\n%s", filepath.Base(name), strings.Join(args, " "), output)
	switch {
	case ctx.Err() != nil:
		t.Errorf("%s did not finish within %s", filepath.Base(name), agentTimeout)
	case err != nil:
		t.Errorf("%s exited with error: %v", filepath.Base(name), err)
	}
	return output
}

// newProject creates an empty working directory for the agent to run in.
func newProject(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// assertConversation checks what every agent must have done, independent of
// the wire protocol it used:
//
//   - its output contains the mock's final answer quoting the command output;
//   - it took at least one agent turn per scripted call plus the answer, and
//     the mock actually reached its answer;
//   - the sandbox tool was offered on the first agent turn — or, when
//     wantSandboxTool is false (--bash-ast-hook-mode configures no MCP
//     server), was not;
//   - the tool results it fed back end with curl rejected and the allowed
//     command's output — i.e. lite-sandbox (the MCP tool, or the validating
//     hook) decided what ran. A result the sandbox refused (curl) must not be
//     mistaken for the shell having run it, so it is matched on the sandbox's
//     own rejection text.
//
// It returns the tools offered on the first turn for agent-specific checks.
func assertConversation(t *testing.T, output string, model *mockmodel.Server, calls []mockmodel.ToolCall, sandboxTool string, wantSandboxTool bool) map[string]bool {
	t.Helper()
	if _, answer, ok := strings.Cut(output, finalPrefix); !ok || !strings.Contains(answer, allowedOutput) {
		t.Errorf("final answer missing the command's output")
	}
	turns := model.AgentTurns()
	if want := len(calls) + 1; len(turns) < want {
		t.Fatalf("expected at least %d agent turns (%d tool calls + answer), got %d (protocols: %v)", want, len(calls), len(turns), protocols(model))
	}
	tools := turns[0].Tools
	t.Logf("tools offered on the first agent turn (%s): %v", turns[0].Protocol, slices.Sorted(maps.Keys(tools)))
	if tools[sandboxTool] != wantSandboxTool {
		t.Errorf("sandbox tool %s offered: %v, want %v", sandboxTool, tools[sandboxTool], wantSandboxTool)
	}

	results := lastResults(t, model)
	t.Logf("tool results fed back: %q", results)
	if len(results) != len(calls) {
		t.Fatalf("expected %d tool results, got %d", len(calls), len(results))
	}
	assertResult(t, results, len(results)-2, curlRejected)
	// Agents may wrap results in their own framing (Codex adds timing lines),
	// so look for the output rather than requiring it verbatim.
	assertResult(t, results, len(results)-1, allowedOutput)
	return tools
}

// assertResult checks that the i-th tool result fed back contains want.
func assertResult(t *testing.T, results []string, i int, want string) {
	t.Helper()
	if !strings.Contains(results[i], want) {
		t.Errorf("tool result %d does not contain %q: %q", i, want, results[i])
	}
}

// lastResults returns the tool results in the transcript of the turn the mock
// answered (falling back to the last agent turn), i.e. everything the agent
// fed back for the scripted calls.
func lastResults(t *testing.T, model *mockmodel.Server) []string {
	t.Helper()
	turn, answered := model.AnswerTurn()
	if !answered {
		t.Errorf("the mock never reached its final answer (protocols: %v)", protocols(model))
	}
	return turn.ToolResults
}

// assertDirective checks the installer's usage directive (from CLAUDE.md,
// AGENTS.md, or CRUSH.md) reached the model on the first agent turn. Where an
// agent puts it (system prompt, developer message, first user turn) is its
// business, so this looks at all the text the model saw.
func assertDirective(t *testing.T, model *mockmodel.Server, snippet string) {
	t.Helper()
	turns := model.AgentTurns()
	if len(turns) == 0 || !strings.Contains(turns[0].Text, snippet) {
		t.Errorf("usage directive %q not found in the text sent to the model", snippet)
	}
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
