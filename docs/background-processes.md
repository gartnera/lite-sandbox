# Background processes

The `bash` tool can run long-lived commands in the background, like Claude
Code's `Bash` / `KillShell` tools. Pass `run_in_background: true` to start a
command without waiting for it; the call returns a shell id and the path of
the file the command's output is written to. The tools involved:

- **`bash`** with `run_in_background: true`: validates the command (validation
  errors are returned synchronously), starts it detached from the request, and
  returns its shell id and output file. `timeout` is ignored for background
  commands.
- **`list_shells`**: lists all background processes with their id, status
  (`running`, `completed`, `failed`, or `killed`), exit code once finished, and
  output file.
- **`kill_shell`** (`shell_id`): stops a running background process.

**MCP tasks.** A client that declares the MCP tasks extension
(`io.modelcontextprotocol/tasks`, on protocol revision 2026-07-28) gets
background commands as tasks instead. The `bash` call returns a task handle,
the client polls it with `tasks/get`, and when the command exits the task
completes with its exit code, its output file, and the last 8 KiB of its
output. A non-zero exit or a kill is reported as an error result. Cancelling
the task (`tasks/cancel`) kills the command. Such a client follows and stops
background commands through the task, so `list_shells` and `kill_shell` are
neither listed for it nor callable by it. Foreground commands are still
answered directly.

In Claude Code (2.1.304 or later), these commands show in `/tasks`, can be
stopped from there, and wake Claude with the result when they finish, the way
its own background `Bash` commands do. Claude Code only uses MCP tasks in some
sessions (the interactive CLI, and Agent SDK sessions with
`CLAUDE_AUTO_BACKGROUND_TASKS=1`, among other conditions; see its
[MCP docs](https://code.claude.com/docs/en/mcp#mcp-tasks-that-run-on-the-server)).
It never uses them for calls from subagents or one-shot `claude -p` runs.
Those calls, and every other agent's, get the shell id reply. A subagent shares
its session's tool list, though, so in a session that runs tasks it is not
offered `list_shells` or `kill_shell`. It can still read its background
command's output file, and the command is stopped when the session ends.
Because a command is validated once its task exists, a command the sandbox
refuses shows up as a task that fails on its first poll rather than as an
immediate error.

**Reading output.** There is no dedicated output tool: stdout and stderr are
written, as they are produced, to `<shell id>.log` in a per-server directory
under `$TMPDIR/lite-sandbox-<uid>/` (`/tmp/lite-sandbox-<uid>/` on Linux), and
the agent reads it with the `bash` tool like any other file (`tail -n 50`,
`grep ERROR`, `wc -l`). That directory is a read grant for the bash tool and
the file-tool hook, and an internal write grant for the OS sandbox worker
(bound writable into it; on Linux the worker's `/tmp` is otherwise private),
so the agent's own commands cannot write there. (On macOS the root sits inside
the per-user `$TMPDIR`, which is already granted read+write on its own.) The root is created
`0700` and is refused if it is a symlink or owned by another user. Each output
file is capped at 32 MiB: past the cap it is compacted to its most recent half
behind a `[lite-sandbox: output exceeded the size cap; ...]` line.

**Cleanup.** When the MCP server exits (the agent closes it, or it receives
SIGTERM/SIGINT), it kills its background processes and deletes its output
directory. A server that could not clean up (SIGKILL, a crash) leaves its
directory behind; the next server to start a background command removes the
directories of servers that are no longer running.

Background commands go through the same AST validation, path confinement, and
OS sandbox as foreground commands. They are terminated when the server shuts
down.

**Stopping background processes.** `kill_shell` and shutdown kill the whole
process group, so children the command forked (dev servers, daemons,
`something &`) are stopped too, not just the direct process:

- Background commands run through a bare `commands` allow entry, which is
  where forking servers usually run, lead their own process group on the host
  and are killed as a group.
- Under the OS sandbox on Linux, the worker kills each command's process
  group. On macOS the sandbox's signal restrictions limit this to the direct
  process; the worker's own process group is killed on shutdown.
- For validated commands run by the interpreter outside the OS sandbox,
  `kill_shell` signals only the direct process. Grandchildren are killed on
  shutdown.
