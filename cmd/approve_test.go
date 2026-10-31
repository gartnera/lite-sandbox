package cmd

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/hook"
)

// TestExternalApprovalConfigRequest is the contract with an approval plugin:
// with --external-approval the hook neither asks nor records a ticket, so the
// server refuses a config request until `lite-sandbox approve` records the
// user's approval of exactly that command, and runs it once.
func TestExternalApprovalConfigRequest(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	c := setupClientWith(t, serveOptions{configRequests: true})
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	const command = "lite-sandbox config commands allow make"
	opts := hookOptions{configRequests: true, externalApproval: true}

	// The hook pre-approves the call like any sandbox call: no ask, no ticket.
	if d := evaluate(bashEvent(t, command, false), opts); decisionOf(d) != hook.DecisionAllow {
		t.Fatalf("hook decision = %+v, want the plain pre-approval", d)
	}
	if text, isErr := runBash(t, c, command); !isErr || !strings.Contains(text, "was not approved") {
		t.Fatalf("call without approval = %q (error %v), want a refusal", text, isErr)
	}

	// A malformed request is still refused by the hook.
	if d := evaluate(bashEvent(t, "lite-sandbox config --dir / mode set open", false), opts); decisionOf(d) != hook.DecisionDeny {
		t.Errorf("out-of-project --dir: hook decision = %+v, want deny", d)
	}

	// A dry run says what would run and records nothing.
	scoped := "lite-sandbox config --dir " + cwd + " commands allow make"
	res, err := approve(cwd, command, approveOptions{dryRun: true})
	if err != nil || res.Kind != "config" || res.Command != scoped || res.Approved {
		t.Fatalf("dry run = %+v, %v; want kind config, command %q, not approved", res, err, scoped)
	}
	if _, isErr := runBash(t, c, command); !isErr {
		t.Fatal("a dry run approved the request")
	}

	// Approved: it runs scoped to the project, once.
	if res, err := approve(cwd, command, approveOptions{}); err != nil || !res.Approved {
		t.Fatalf("approve = %+v, %v", res, err)
	}
	if text, isErr := runBash(t, c, command); isErr {
		t.Fatalf("approved call failed: %s", text)
	}
	if want := []string{"--dir", cwd, "commands", "allow", "make"}; len(*runs) != 1 || !slices.Equal((*runs)[0], want) {
		t.Fatalf("runs = %v, want one run of %v", *runs, want)
	}
	if _, isErr := runBash(t, c, command); !isErr {
		t.Fatal("one approval ran two requests")
	}
}

// TestApproveGlobal checks a request approved with --global runs as written,
// against the global config, and that only that approval does so.
func TestApproveGlobal(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	c := setupClientWith(t, serveOptions{configRequests: true})
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	const command = "lite-sandbox config paths allow ~/shared"

	res, err := approve(cwd, command, approveOptions{global: true})
	if err != nil || !res.Approved || !res.Global || res.Command != "lite-sandbox config paths allow ~/shared" {
		t.Fatalf("approve --global = %+v, %v", res, err)
	}
	if text, isErr := runBash(t, c, command); isErr {
		t.Fatalf("globally approved call failed: %s", text)
	}
	if want := []string{"paths", "allow", "~/shared"}; len(*runs) != 1 || !slices.Equal((*runs)[0], want) {
		t.Fatalf("runs = %v, want one unscoped run of %v", *runs, want)
	}
	if _, isErr := runBash(t, c, command); !isErr {
		t.Fatal("one global approval ran two requests")
	}

	// A request naming its own --dir cannot be approved globally.
	if _, err := approve(cwd, "lite-sandbox config --dir "+cwd+" mode set open", approveOptions{global: true}); err == nil {
		t.Error("approve --global accepted a request naming --dir")
	}
	// --global is for config requests only.
	if _, err := approve(cwd, "make", approveOptions{global: true}); err == nil {
		t.Error("approve --global accepted a plain command")
	}
}

// TestApproveNone checks commands that need no approval say so and record
// nothing.
func TestApproveNone(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"ls", "lite-sandbox config paths --help"} {
		res, err := approve(cwd, command, approveOptions{})
		if err != nil || res.Kind != "none" || res.Approved {
			t.Errorf("%q: approve = %+v, %v; want kind none", command, res, err)
		}
	}
}

// TestApproveDenied checks sandboxed commands cannot mint their own approval.
func TestApproveDenied(t *testing.T) {
	if !slices.Contains(config.DefaultDeniedCommands(), "lite-sandbox approve") {
		t.Fatalf("lite-sandbox approve is not on the built-in deny list: %v", config.DefaultDeniedCommands())
	}
}

// TestClaudePlanExternalApproval checks the installer registers the hook with
// --external-approval when asked.
func TestClaudePlanExternalApproval(t *testing.T) {
	p := claudeOptions{withToolHook: true, redirectBash: true, externalApproval: true}.plan("/bin/lite-sandbox")
	if !strings.HasSuffix(p.hookCommand, " --config-requests --external-approval") {
		t.Errorf("hook command = %q, want --config-requests --external-approval", p.hookCommand)
	}
	p = claudeOptions{withToolHook: true, redirectBash: true}.plan("/bin/lite-sandbox")
	if strings.Contains(p.hookCommand, "--external-approval") {
		t.Errorf("hook command = %q without the option", p.hookCommand)
	}
	// launch's own posture (the hook governs the file tools, Bash denied).
	p = claudeOptions{withToolHook: true, externalApproval: true}.plan("/bin/lite-sandbox")
	if !strings.HasSuffix(p.hookCommand, " --config-requests --external-approval") {
		t.Errorf("launch hook command = %q, want --config-requests --external-approval", p.hookCommand)
	}
	// --bash-ast-hook-mode has no MCP server, so no config requests to approve.
	p = claudeOptions{bashASTHookMode: true, externalApproval: true}.plan("/bin/lite-sandbox")
	if strings.Contains(p.hookCommand, "--external-approval") {
		t.Errorf("bash-ast-hook-mode hook command = %q, want no --external-approval", p.hookCommand)
	}
}
