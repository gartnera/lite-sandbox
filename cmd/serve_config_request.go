package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/configrequest"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// configCommandTimeout bounds a `lite-sandbox config` run. Every subcommand a
// config request may run edits a small file and returns.
const configCommandTimeout = time.Minute

// runConfigCommand runs `lite-sandbox config <args>` in dir and returns its
// combined output. It runs as a separate process because the config
// subcommands print to stdout, which in this process is the MCP transport.
// configrequest.RootEnv makes the subprocess itself refuse a --dir outside dir.
// A variable so tests can stand in for the binary.
var runConfigCommand = func(ctx context.Context, dir string, args []string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the lite-sandbox binary: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, configCommandTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, exe, append([]string{"config"}, args...)...)
	c.Dir = dir
	c.Env = append(c.Environ(), configrequest.RootEnv+"="+dir)
	out, err := c.CombinedOutput()
	return string(out), err
}

// runConfigRequest runs a config request — a bash tool command that is just
// `lite-sandbox config ...` (configrequest.Parse) — once the user has approved
// it. It runs on the host, not in the sandbox, whose deny list exists to stop
// exactly this command. It is always scoped to cwd (Request.Scope): the change
// lands in a per-directory override, never the global config. The approval is
// the ticket the PreToolUse hook records
// when it asks the user (see internal/configrequest); a request without one
// was never shown to the user and is refused.
func runConfigRequest(ctx context.Context, sandbox *bash_sandboxed.Sandbox, opts serveOptions, cwd string, req configrequest.Request, background bool) *mcp.CallToolResult {
	if background {
		return mcp.NewToolResultError("`lite-sandbox config` cannot run in the background; run it with run_in_background false")
	}
	if err := req.Validate(); err != nil {
		return mcp.NewToolResultError(err.Error())
	}
	scoped, err := req.Scope(cwd)
	if err != nil {
		return mcp.NewToolResultError(err.Error())
	}
	if err := configrequest.Consume(cwd, req); err != nil {
		if errors.Is(err, configrequest.ErrNoTicket) {
			return mcp.NewToolResultError(fmt.Sprintf(
				"Refused: `%s` was not approved. lite-sandbox runs config changes only after its PreToolUse hook "+
					"asks the user to approve them, and the hook did not run for this call (or the approval expired). "+
					"Ask the user to run the command themselves, or to re-run `lite-sandbox install` so the hook is registered.",
				scoped.Command()))
		}
		return mcp.NewToolResultError("checking the approval: " + err.Error())
	}

	out, err := runConfigCommand(ctx, cwd, scoped.Args)
	out = strings.TrimRight(out, "\n")
	if err != nil {
		msg := fmt.Sprintf("`%s` failed: %v", scoped.Command(), err)
		if out != "" {
			msg += "\n" + out
		}
		return mcp.NewToolResultError(msg)
	}
	// Apply the new config now rather than wait for the file watcher, so the
	// very next command runs under it.
	if opts.reload != nil {
		opts.reload()
	} else if cfg, err := config.LoadForDirectory(cwd); err == nil {
		sandbox.UpdateConfig(cfg, cwd)
	}
	return mcp.NewToolResultText(out + "\n")
}

// configRequestHint is appended to an error that names a `lite-sandbox config`
// fix when this agent can make config requests, so the agent runs the change
// itself (with the user's approval) instead of only relaying it.
const configRequestHint = "\n\nYou can make this config change yourself: run the `lite-sandbox config ...` command " +
	"with the mcp__lite-sandbox__bash tool, as a command of its own. The user is asked to approve it, " +
	"and it applies to the next command. It is scoped to this working directory (a `--dir` override is " +
	"added when the command has none); global changes are left to the user."

// configRequestAloneHint replaces configRequestHint when the error is the deny
// list refusing `lite-sandbox config` itself: the command was run, just not on
// its own, and lifting the deny entry (the fix the error names) is not what
// the agent wants.
const configRequestAloneHint = "\n\n`lite-sandbox config` runs only as a command of its own: " +
	"a single `lite-sandbox config ...` invocation with literal arguments — no pipes, `&&`, `;`, " +
	"redirections, variables or globs. Run it that way and the user is asked to approve it."

// withConfigRequestHint appends the config request hint to msg when it names a
// `lite-sandbox config` command. A command deny list error gets none: its fix
// lifts a denial the user (or lite-sandbox, for its own subcommands) made on
// purpose, which is not a change to steer the agent toward. The one exception
// is the denial of `lite-sandbox config` itself, which a config request that
// was not run on its own hits; that one is told how to run it.
func withConfigRequestHint(msg string) string {
	if strings.Contains(msg, `deny list entry "lite-sandbox config"`) {
		return msg + configRequestAloneHint
	}
	if strings.Contains(msg, "command deny list entry") {
		return msg
	}
	if strings.Contains(msg, "lite-sandbox config ") {
		return msg + configRequestHint
	}
	return msg
}

// bashToolArgs reads the bash tool's command and run_in_background from the
// tool's arguments. The tool handler and the hook both read a call through it,
// so they agree on what a call runs: in particular on whether it is a config
// request, which the hook must ask the user about and the server only runs
// when the hook did. (Decoding into a struct, the hook would match keys case
// insensitively and read {"command": ..., "Command": "ls"} as "ls".)
func bashToolArgs(args map[string]any) (command string, background, ok bool) {
	command, ok = args["command"].(string)
	background, _ = args["run_in_background"].(bool)
	return command, background, ok
}
