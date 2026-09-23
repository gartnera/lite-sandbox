# Background processes

The `bash` tool can run long-lived commands in the background, like Claude
Code's `Bash` / `BashOutput` / `KillShell` tools. Pass
`run_in_background: true` to start a command without waiting for it; the call
returns a shell id immediately. The tools involved:

- **`bash`** with `run_in_background: true`: validates the command (validation
  errors are returned synchronously), starts it detached from the request, and
  returns its shell id. `timeout` is ignored for background commands.
- **`bash_output`** (`bash_id`, optional `filter`): returns the output produced
  since the previous call, plus the process status (`running`, `completed`,
  `failed`, or `killed`) and the exit code once it has finished. `filter` is a
  regular expression; only matching lines are returned. Output is capped per
  process (oldest bytes are dropped).
- **`kill_shell`** (`shell_id`): stops a running background process.
- **`list_shells`**: lists all background processes with their id, status, and
  exit code.

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
