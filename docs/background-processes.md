# Background processes

The `bash` tool can run long-lived commands in the background, mirroring the
Claude Code `Bash` / `BashOutput` / `KillShell` tools. Pass
`run_in_background: true` to start a command without blocking; it returns a
shell id immediately. Three companion tools manage these processes:

- **`bash`** with `run_in_background: true` — validates the command (validation
  errors are returned synchronously), starts it detached from the request, and
  returns its shell id. The `timeout` parameter is ignored for background
  commands.
- **`bash_output`** (`bash_id`, optional `filter`) — returns the output produced
  since the previous call, plus the process status (`running`, `completed`,
  `failed`, or `killed`) and exit code once finished. `filter` is a regular
  expression that keeps only matching output lines. Per-process output is capped
  (oldest bytes are dropped) so chatty commands can't grow unbounded.
- **`kill_shell`** (`shell_id`) — stops a running background process.
- **`list_shells`** — lists all background processes with their id, status, and
  exit code.

Background commands pass through the same AST validation, path confinement, and
OS sandbox as foreground commands. They are terminated when the server shuts
down.

**Stopping background processes.** `kill_shell` (and shutdown) tears down the
whole process group, so children the command forked — dev servers, daemons,
`something &` — are reaped, not just the direct process:

- Bare `extra_commands` background commands (where forking servers typically
  run) lead their own process group on the host and are killed as a group.
- Under the OS sandbox, the worker kills each command's process group on Linux;
  on macOS the sandbox's signal confinement limits this to the direct process,
  with the worker's own process group reaped on shutdown.
- For validated commands run through the interpreter (not the OS sandbox), kill
  signals the direct process; deeply forked grandchildren of those are reaped on
  shutdown.
