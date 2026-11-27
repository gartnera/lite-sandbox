package mockedserver

// lite-sandbox's opencode v2 plugin, driven through a real opencode v2: it
// confines the built-in file tools to the sandbox's paths and puts config
// requests to the user through opencode's permission prompt.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// opencodeV2CodeModeCall scripts a Code Mode program calling the sandbox's
// bash tool with command, returning the tool's output or its error.
func opencodeV2CodeModeCall(t *testing.T, command string) mockmodel.ToolCall {
	t.Helper()
	quoted, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	code := fmt.Sprintf(`try { return await %s({ command: %s }) } catch (e) { return String(e) }`, opencodeV2CodeModeBash, quoted)
	return mockmodel.ToolCall{Name: "execute", Arguments: map[string]string{"code": code}}
}

// TestOpencodeV2Plugin drives `lite-sandbox launch opencode run ...` against
// v2 with a script that uses the built-in file tools inside and outside the
// project, then makes a config request and runs an ordinary command:
//
//   - the reads and writes outside the project are rejected with
//     lite-sandbox's reason, and those inside go through;
//   - declined: `opencode run` rejects every permission prompt, so the config
//     request fails and the config is left alone;
//   - approved: `opencode run --auto` allows each prompt once, as a user
//     would, and the MCP server runs the request on the ticket the hook
//     recorded: the project's override now allows make.
func TestOpencodeV2Plugin(t *testing.T) {
	requireE2E(t)

	for _, approve := range []bool{false, true} {
		name := "declined"
		if approve {
			name = "approved"
		}
		t.Run(name, func(t *testing.T) {
			project := newProject(t)
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret.txt")
			writeFile(t, secret, "TOP-SECRET")
			inside := filepath.Join(project, "made.txt")
			escaped := filepath.Join(outside, "escaped.txt")

			calls := []mockmodel.ToolCall{
				// Harmless, while the sandbox's server connects in the background.
				{Name: "read", Arguments: map[string]string{"path": project}},
				{Name: "read", Arguments: map[string]string{"path": secret}},
				{Name: "write", Arguments: map[string]string{"path": inside, "content": "made inside"}},
				{Name: "write", Arguments: map[string]string{"path": escaped, "content": "escaped"}},
				opencodeV2CodeModeCall(t, configRequest),
				opencodeV2CodeModeCall(t, allowedCommand),
			}
			model := mockmodel.Start(mockmodel.Script{
				ToolCalls:      calls,
				FinalText:      func(results []string) string { return finalPrefix + strings.TrimSpace(results[len(results)-1]) },
				FirstTurnDelay: 3 * time.Second,
			})
			t.Cleanup(model.Close)
			_, _, environ := opencodeV2Env(t, model, nil)
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			environ = append(environ, "LITE_SANDBOX_CONFIG="+configPath)

			args := []string{"launch", "opencode", "run", "--format", "json", "-m", "mock/" + model.ModelID}
			if approve {
				args = append(args, "--auto")
			}
			output := runAgent(t, project, environ, bins.sandbox, append(args, prompt)...)

			results := lastResults(t, model)
			for i, r := range results {
				t.Logf("result %d: %s", i, r)
			}
			if len(results) != len(calls) {
				t.Fatalf("results = %q, want one per call\n%s", results, output)
			}
			assertResult(t, results, 1, "Blocked by lite-sandbox")
			if strings.Contains(results[1], "TOP-SECRET") {
				t.Errorf("read outside the project returned the file: %q", results[1])
			}
			if got, err := os.ReadFile(inside); err != nil || string(got) != "made inside" {
				t.Errorf("write inside the project: %q, %v (result %q)", got, err, results[2])
			}
			assertResult(t, results, 3, "Blocked by lite-sandbox")
			if _, err := os.Stat(escaped); !os.IsNotExist(err) {
				t.Errorf("write outside the project created %s", escaped)
			}

			if approve {
				assertResult(t, results, 4, "Scoped to")
				if !allowsMake(t, configPath, project) {
					data, _ := os.ReadFile(configPath)
					t.Errorf("the approved request did not allow make for %s; config:\n%s", project, data)
				}
			} else {
				if strings.Contains(results[4], "Scoped to") {
					t.Errorf("the config request ran without approval: %q", results[4])
				}
				if allowsMake(t, configPath, project) {
					t.Error("the config allows make although the request was never approved")
				}
				// opencode run reports the prompt it rejected, named after the
				// request.
				if !strings.Contains(output, "permission requested: lite-sandbox: "+configRequest) {
					t.Errorf("no permission prompt for the config request in the output:\n%s", output)
				}
			}
			assertResult(t, results, 5, allowedOutput)
		})
	}
}
