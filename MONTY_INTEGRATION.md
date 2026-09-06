# Monty integration — implementation guide

Handoff notes for wiring [monty](https://github.com/pydantic/monty) (a sandboxed
Python interpreter written in Rust) into lite-sandbox, so an agent's `python` /
`python3` invocations run in a real sandbox instead of being rejected.

Planning document — delete once the work lands.

## Decisions already made

- **Surface:** transparent alias. The agent writes `python3 script.py` or
  `python3 -c "..."` as usual and lite-sandbox routes it to monty. `python` stays
  out of `allowedCommands` for its own sake; it is dispatched, not executed.
- **Vehicle:** the Go binding, embedded in-process. No CLI, no subprocess.
- **Boundary:** monty's OS calls are serviced by a Go callback wired into
  lite-sandbox's existing path authorization, so Python file I/O obeys the same
  read/write path sets as `bash`.

## Dependency

`github.com/gartnera/monty-go` — a fork of `fugue-labs/monty-go`, upgraded to
monty v0.0.23 (see its git history for what that involved).

**No Rust toolchain is needed anywhere in lite-sandbox.** monty-go commits its
`monty.wasm` and pulls it in with `go:embed`, so the blob ships inside the Go
module zip. `go build` is all that is required, GoReleaser is unaffected.

The fork's `go.mod` still declares the upstream module path, so use a replace
directive rather than importing the fork path directly:

```bash
go mod edit -replace github.com/fugue-labs/monty-go=github.com/gartnera/monty-go@main
go get github.com/fugue-labs/monty-go
go mod tidy
```

Import as `montygo "github.com/fugue-labs/monty-go"`. Costs ~4.8 MB of binary
size and one transitive dependency (wazero, pure Go, no cgo). monty-go needs
Go >= 1.25; lite-sandbox is on 1.26.

## How monty works, in one paragraph

The interpreter performs **no I/O of its own**. When Python touches the
filesystem or environment, the VM suspends and hands the host a typed OS call;
the host services it and resumes the VM. That is the whole security model — the
sandbox reaches the host only through the callback you give it. In this
integration lite-sandbox *is* that host, which is why the path boundary can be
the one already in `paths.go` rather than a second, parallel policy.

## Where the code goes

### 1. Dispatch seam — `tool/bash_sandboxed/bash_exec.go`

`buildSecurityHandlers` already special-cases commands that must not reach the
OS: see the `switch cmdName` around line 614 (`awk` → `executeAwk`, `bash`/`sh`
→ `executeBash`) and the `deno` argv rewrite just above it. Add:

```go
case "python", "python3":
    return s.executePython(ctx, args, sets)
```

`sets` is the `resolvedPathSets` built once at line 527 — pass it through, it is
the authorization input for the OS-call handler.

Note this runs **in the MCP server process**, not in the bwrap/sandbox-exec
worker, since monty is in-process wasm. That is fine — monty itself cannot touch
the filesystem — but it means the host-side file operations your handler
performs are not covered by the OS sandbox. Contain them with `os.Root`
(Go 1.24+, openat2-rooted) rather than path arithmetic; this is the same
primitive (`cap_std::fs::Dir`) upstream's own mount implementation relies on,
and it is what makes the handler's boundary kernel-enforced.

### 2. New file — `tool/bash_sandboxed/python.go`

```go
func (s *Sandbox) executePython(ctx context.Context, args []string, sets resolvedPathSets) error
```

Responsibilities:

1. Parse argv into (code, script path). Support `-c CODE`, `script.py`,
   and `-` (stdin). Reject `-m` with a message naming monty.
2. Read the script through the read path set (it is a file access like any
   other).
3. Build a `montygo.Runner` — compile once, reuse. Put it on `Sandbox` behind
   the existing mutex, built lazily; `Runner.Execute` makes a fresh isolated
   instance per call, so one Runner is safe to share.
4. `Execute` with the options below, streaming print output to
   `interp.HandlerCtx(ctx).Stdout`.
5. Map a `*montygo.MontyError` to the traceback on stderr plus
   `interp.ExitStatus(1)`.

Options to pass:

```go
montygo.WithPrintFunc(func(s string) { io.WriteString(hc.Stdout, s) })
montygo.WithOsCallFunc(s.montyOsCall(hc.Dir, sets))   // the authorization hook
montygo.WithLimits(montygo.Limits{
    MaxDuration:       cfg.Timeout,
    MaxMemoryBytes:    ...,   // enforced via monty-alloc as of the fork's upgrade
    MaxRecursionDepth: 1000,
    MaxSuspensions:    ...,   // bounds host calls per run; see note below
})
```

### 3. The authorization hook

`OsCallFunc` receives `{Function string, Args []any, Kwargs map[string]any}` and
returns `(any, error)`. Switch on `Function`, take the path from `Args[0]`,
resolve it against `hc.Dir`, check it, perform it under `os.Root`.

Read-side (validate against the **read** set) — `Path.exists`, `Path.is_file`,
`Path.is_dir`, `Path.is_symlink`, `Path.read_text`, `Path.read_bytes`,
`Path.stat`, `Path.iterdir`, `Path.resolve`, `Path.absolute`.

Write-side (validate against the **write** set, same as `cp`/`mv`/`sed` in
`writeCommands`) — `Path.write_text`, `Path.append_text`, `Path.write_bytes`,
`Path.append_bytes`, `Path.mkdir`, `Path.unlink`, `Path.rmdir`,
`Path.rename` (both src and dst), and `open` (mode decides which set).

Non-filesystem — `os.getenv`, `os.environ`, `date.today`, `datetime.now`.
Return an empty environment: monty has no env by default and re-exposing the
host's would leak credentials the rest of the sandbox masks.

Returning an **error** from the handler ends the run. Returning a *denial value*
would let a script retry in a loop, which is what `MaxSuspensions` exists to
stop — prefer the error.

Reuse `validateExpandedPaths` / `validateOpenPath` (`paths.go:591`, `:606`) or
factor out the inner check they share; do not write a second path policy.

### 4. Static validation — `commands.go`

Add `python` / `python3` to `allowedCommands` and register a
`validatePythonArgs` in `commandArgValidators`. Both handlers re-check at
runtime, so the static pass only needs to reject unsupported argv shapes early
with a good message.

### 5. Config

Add `Python *PythonConfig` to `RuntimesConfig` (`config/config.go:496`) plus a
`cmd/config_python.go` following `config_runtimes.go`.

**Open decision:** the earlier plan was "auto-enable when monty is detected on
PATH", which assumed the CLI. With the wasm embedded there is nothing to detect
— it is always available. So either default it on (recommended: monty's
isolation is stronger than the bash-side boundary, and the whole point is that
the agent does not have to ask) or default it off and require opt-in like the
other runtimes. Whichever you pick, keep the off-switch.

## What will bite you

**monty is a Python subset.** No third-party imports, ever — no numpy, pandas,
requests, yaml. Partial stdlib: `os`, `pathlib`, `json`, `re`, `math`,
`datetime`, `sys`, `typing`, `asyncio`. No class inheritance, `super()`,
`@property`/`@classmethod`/`@staticmethod`, generators, `match`, or `del`.

Because the alias is transparent, an agent hitting one of these gets a confusing
error and will try to `pip install`. **Rewrite the failure message** — when a
`ModuleNotFoundError` or `ImportError` comes back, say plainly that this is
monty, that third-party imports are unavailable, and that `uv run` is the escape
hatch for real CPython (already supported via `runtimes.uv`). This is the single
highest-value detail in the whole integration; without it the feature reads as
broken.

## Testing

- Unit: argv parsing, and the OS-call handler against the path boundary —
  a write inside the working directory succeeds, one outside is denied, a
  symlink escape is denied, `.git` is denied.
- e2e (`e2e/mockedserver/`): an agent asked to rewrite a file with Python.
- `e2e/claude/`: does Claude actually pick the sandbox tool for Python work.

Label the PR `release:minor` (new capability). Update `docs/runtimes.md` and
`docs/security.md` — the latter should say plainly that Python file I/O goes
through the same path sets as bash, and that monty's isolation (no network, no
env, no ambient filesystem) is stronger than the AST-level boundary around it.
