package mockedserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// configRequest is the config request the agent makes: `lite-sandbox config`
// on its own, which the sandbox runs only with the user's approval.
const configRequest = "lite-sandbox config commands allow make"

// TestClaudeCodeConfigRequest drives a config request through a real Claude
// Code. lite-sandbox's PreToolUse hook answers "ask" for it, and a `claude -p`
// run settles that prompt the way its permission flow does:
//
//   - declined: nothing can answer the prompt, so Claude Code denies the call,
//     feeding lite-sandbox's reason back to the model, and the config is left
//     alone;
//   - approved: the approver (see serveApprover), passed as
//     --permission-prompt-tool, answers the prompt as the user would. It is
//     asked about the command the agent ran, and the MCP server, holding the
//     ticket the hook recorded, runs it: the project's override now allows
//     make.
//
// Each run then runs an ordinary command, which must still go through.
func TestClaudeCodeConfigRequest(t *testing.T) {
	requireE2E(t)
	calls := []mockmodel.ToolCall{
		{Name: claudeSandboxTool, Arguments: map[string]string{"command": configRequest}},
		{Name: claudeSandboxTool, Arguments: map[string]string{"command": allowedCommand}},
	}

	t.Run("declined", func(t *testing.T) {
		run := runConfigRequest(t, calls, false)
		results := lastResults(t, run.model)
		if len(results) != len(calls) {
			t.Fatalf("results = %q, want one per call", results)
		}
		// The model reads lite-sandbox's reason for asking: the scoped command.
		assertResult(t, results, 0, "lite-sandbox config --dir ")
		if strings.Contains(results[0], "Scoped to") {
			t.Errorf("the config request ran without approval: %q", results[0])
		}
		if allowsMake(t, run.configPath, run.project) {
			t.Error("the config allows make although the request was never approved")
		}
		assertResult(t, results, 1, allowedOutput)
	})

	t.Run("approved", func(t *testing.T) {
		run := runConfigRequest(t, calls, true)
		results := lastResults(t, run.model)
		if len(results) != len(calls) {
			t.Fatalf("results = %q, want one per call", results)
		}

		// One permission prompt was raised, for the sandbox's bash tool and
		// the command the agent ran; the ordinary command needed none.
		data, err := os.ReadFile(run.promptLog)
		if err != nil {
			t.Fatalf("no permission prompt was raised: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 1 {
			t.Fatalf("permission prompts = %q, want one", lines)
		}
		var prompt struct {
			ToolName string `json:"tool_name"`
			Input    struct {
				Command string `json:"command"`
			} `json:"input"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &prompt); err != nil {
			t.Fatalf("parse the permission prompt: %v\n%s", err, lines[0])
		}
		if prompt.ToolName != claudeSandboxTool || prompt.Input.Command != configRequest {
			t.Errorf("prompt for %s %q, want %s %q", prompt.ToolName, prompt.Input.Command, claudeSandboxTool, configRequest)
		}

		// The server ran it, scoped to the project, and the next command
		// still runs.
		assertResult(t, results, 0, "Scoped to")
		if !allowsMake(t, run.configPath, run.project) {
			data, _ := os.ReadFile(run.configPath)
			t.Errorf("the approved request did not allow make for %s; config:\n%s", run.project, data)
		}
		assertResult(t, results, 1, allowedOutput)
	})
}

// configRequestRun is one `claude -p` run that made a config request.
type configRequestRun struct {
	model      *mockmodel.Server
	configPath string // lite-sandbox's config file for the run
	project    string // the agent's working directory
	promptLog  string // the approver's log of the prompts it answered, when approve is set
}

// runConfigRequest installs lite-sandbox for Claude Code with a config file of
// its own and runs `claude -p` once against a mock scripted with calls. With
// approve, the run gets the approver as its permission prompt tool.
func runConfigRequest(t *testing.T, calls []mockmodel.ToolCall, approve bool) configRequestRun {
	t.Helper()
	model := startModel(t, calls)
	_, environ := claudeEnv(t, model)
	run := configRequestRun{
		model:      model,
		configPath: filepath.Join(t.TempDir(), "config.yaml"),
		project:    newProject(t),
	}
	environ = append(environ, "LITE_SANDBOX_CONFIG="+run.configPath)
	installSandbox(t, "claude", environ)

	args := []string{"-p", "--output-format", "json"}
	if approve {
		run.promptLog = filepath.Join(t.TempDir(), "permission-prompts.jsonl")
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		mcpConfig, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
			"approver": map[string]any{"command": self, "env": map[string]string{approverLogEnv: run.promptLog}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		// --mcp-config is variadic: the = form keeps it from taking the
		// prompt as a second config.
		args = append(args, "--permission-prompt-tool", approverTool, "--mcp-config="+string(mcpConfig))
	}

	runAgent(t, run.project, environ, bins.claude, append(args, prompt)...)
	return run
}

// allowsMake reports whether the config at configPath allows make in project.
// The override is looked up by the directory it names, symlinks resolved: the
// server records the directory as it spells its working directory, which may
// differ from the test's spelling (/var against /private/var on macOS).
func allowsMake(t *testing.T, configPath, project string) bool {
	t.Helper()
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load %s: %v", configPath, err)
	}
	want := realPath(project)
	for _, o := range cfg.Overrides {
		if realPath(o.Path) != want {
			continue
		}
		for _, e := range cfg.ForDirectory(o.Path).AllCommandEntries() {
			if e.Command == "make" && e.Allow != nil && *e.Allow {
				return true
			}
		}
	}
	return false
}

func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}
