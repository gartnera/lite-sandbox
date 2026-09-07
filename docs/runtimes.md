# Runtime Support

Code execution runtimes are disabled by default and can be enabled individually
via config. This page covers Go, pnpm, Rust, Deno, Flutter, uv, and Python.

Python is the exception: it is **enabled by default**, because it does not run a
toolchain from the host at all. See [Python Runtime Support](#python-runtime-support).

## Go Runtime Support

Go commands (`go build`, `go test`, `go mod`, etc.) are disabled by default. Enable them via config:

```yaml
runtimes:
  go:
    enabled: true    # Allow go build, test, mod, etc. (default: false)
    generate: false  # Allow go generate (default: false)
```

Go runtime commands use the same runtime path validation as other commands to ensure file paths stay within allowed directories. This enables safe development workflows like:

```bash
go mod init myproject
go test ./...
go build -o mybinary
```

The `go generate` subcommand requires explicit opt-in since it can execute arbitrary code specified in source files.

See `e2e/claude/test_go_runtime_e2e.py` for a complete example demonstrating a Go development workflow (module init, testing, git workflow) using only the sandboxed tool.

## pnpm Runtime Support

pnpm commands are disabled by default. Enable them via config:

```yaml
runtimes:
  pnpm:
    enabled: true   # Allow pnpm install, add, test, run, etc. (default: false)
    publish: false  # Allow pnpm publish (default: false)
```

Enable pnpm via CLI:

```bash
# Enable pnpm commands
lite-sandbox config runtimes pnpm enable

# Enable with publish permission
lite-sandbox config runtimes pnpm enable --with-publish

# Show current pnpm configuration
lite-sandbox config runtimes pnpm show
```

pnpm runtime commands enable safe package management workflows:

```bash
pnpm install
pnpm add react
pnpm test
pnpm run build
```

When the OS sandbox is enabled, the pnpm runtime automatically detects and
grants write access to:

- **pnpm store** — `pnpm store path`, where downloaded packages live.
- **pnpm cache** — the `cache-dir` setting, defaulting to the OS cache
  directory joined with `pnpm` (e.g. `~/Library/Caches/pnpm` on macOS,
  `~/.cache/pnpm` on Linux). This holds registry metadata and the `pnpm dlx`
  cache, so pnpm invoked indirectly inside the sandbox (e.g. by a lefthook job
  or package script) can populate its cache.

Security features:
- `pnpm dlx` is blocked when invoked directly (downloads and executes remote packages)
- `pnpm publish` requires explicit opt-in since it affects the npm registry (shared state)

## Deno Runtime Support

Deno commands are disabled by default. Enable them via config:

```yaml
runtimes:
  deno:
    enabled: true        # Allow deno run, test, fmt, lint, task, etc. (default: false)
    publish: false       # Allow deno publish to JSR (default: false)
    auto_sandbox: true   # Auto-scope --allow-read/--allow-write to sandbox paths (default: true)
    allow_network: false # Allow outbound network sockets (default: false)
    allow_import: true   # Allow fetching remote modules (default: true)
```

Enable deno via CLI:

```bash
# Enable deno commands (auto-sandbox is on by default)
lite-sandbox config runtimes deno enable

# Allow outbound network sockets
lite-sandbox config runtimes deno enable --with-network

# Lock down remote module imports (also blocks deno cache/add/install)
lite-sandbox config runtimes deno disable --with-import

# Turn off auto-sandbox but keep deno enabled
lite-sandbox config runtimes deno disable --with-auto-sandbox

# Show current deno configuration
lite-sandbox config runtimes deno show
```

Deno runtime commands enable safe development workflows:

```bash
deno run main.ts
deno test
deno fmt
deno lint
deno task build
```

Security features:
- `deno publish` requires explicit opt-in since it affects the JSR registry (shared state)
- `deno upgrade` is blocked (modifies the deno installation in place)
- `deno eval` is blocked — it runs with implicit access to *all* permissions and
  rejects every `--allow-*`/`--deny-*` flag, so it cannot be confined (an
  unsandboxable code-execution escape hatch, like shell `eval`/`exec`).
- **Auto-sandbox** (`auto_sandbox: true`, the default) — Deno runs with no
  permissions by default and prompts interactively when a script requests
  access it wasn't granted, which would hang a non-interactive sandbox. With
  auto-sandbox enabled, lite-sandbox automatically injects
  `--allow-read`/`--allow-write` scoped to the sandbox's allowed paths for
  permissioned subcommands (`run`, `test`, `bench`, `repl`, `serve`, `compile`,
  `install`), so Deno's permission model mirrors the sandbox filesystem policy
  and runs non-interactively. Existing read/write grants on the command
  (including short `-R`/`-W` or a blanket `-A`) are respected.
- **Network sockets off by default** — `--deny-net` is forced unless
  `allow_network: true`. This is enforced whenever deno is enabled, independent
  of auto-sandbox, so turning auto-sandbox off does not re-open the network.
  `--deny-net` takes precedence over any `--allow-net`/`-A` the invoker passes.
- **Remote imports on by default, behind a flag** — Deno fetches remote modules
  from a default host allowlist (`deno.land`/`jsr.io`/…) out of the box, which
  is core to normal usage, so imports are allowed by default. Setting
  `allow_import: false` blocks remote module fetching on code-executing
  subcommands with `--no-remote` (https/jsr) + `--no-npm` (npm) — the levers
  that actually stop the module graph from being fetched — plus `--deny-import`
  for runtime dynamic imports. It also blocks the CLI fetch subcommands
  (`deno cache`, `deno add`, `deno install`), which fetch at the CLI level where
  an injected flag cannot stop them. (Already-cached modules can still load;
  with `allow_import: false` from the start, nothing new is fetched or cached.)

## Flutter Runtime Support

Flutter, Dart, and fvm (Flutter Version Management) commands are disabled by
default. Enable them via config:

```yaml
runtimes:
  flutter:
    enabled: true   # Allow flutter, dart, and fvm commands (default: false)
```

Enable Flutter via CLI:

```bash
# Enable flutter/dart/fvm commands
lite-sandbox config runtimes flutter enable

# Disable them again
lite-sandbox config runtimes flutter disable

# Show current flutter configuration
lite-sandbox config runtimes flutter show
```

Flutter runtime commands enable normal mobile/web development workflows:

```bash
fvm install
fvm flutter pub get
fvm flutter test
flutter build apk
dart run build_runner build
```

Like Go (which auto-detects `GOPATH`/`GOCACHE`), the Flutter runtime
automatically detects and grants access to the paths these tools read and write,
so builds and tests work without hand-configuring `readable_paths`:

- **fvm cache** — `FVM_CACHE_PATH` (or the legacy `FVM_HOME`), defaulting to
  `~/fvm`. This is where fvm stores each managed Flutter SDK version.
- **pub cache** — `PUB_CACHE`, defaulting to `~/.pub-cache`. This is where
  Dart/Flutter packages are downloaded.
- **Flutter SDK root** — `FLUTTER_ROOT`, or resolved from a `flutter` binary on
  `PATH` (for a non-fvm global install). Flutter writes to `bin/cache` under
  this directory. A candidate is only accepted when it looks like a real SDK
  checkout (it contains a `packages/` directory), so a stray binary in a system
  directory never widens access to `/usr`.
- **Flutter/Dart config directories** — `~/.config/flutter`, `~/.config/dart`,
  `~/.flutter`, and `~/.dart`, where the tools persist settings and analytics
  state.

Directories that don't exist yet (fresh machine, cold caches) are created up
front so the OS sandbox has a bind-mount source for them.

Flutter is a code-execution runtime: like Go, Rust, and Deno, its containment
relies on the OS sandbox confining writes to the working directory and the
detected runtime paths, rather than on per-argument validation. Once enabled,
all `flutter`/`dart`/`fvm` subcommands are permitted.

## uv Runtime Support

[uv](https://docs.astral.sh/uv/) commands (`uv`, `uvx`) are disabled by default.
Enable them via config:

```yaml
runtimes:
  uv:
    enabled: true   # Allow uv sync, add, run, pip, venv, build, tool, etc. (default: false)
    publish: false  # Allow uv publish (default: false)
```

Enable uv via CLI:

```bash
# Enable uv commands
lite-sandbox config runtimes uv enable

# Enable with publish permission
lite-sandbox config runtimes uv enable --with-publish

# Show current uv configuration
lite-sandbox config runtimes uv show
```

Enabling the uv runtime automatically detects and grants access to the paths uv
needs outside the working directory (the same mechanism used for Go's `$GOPATH`).
These are discovered by shelling out to uv and confined so uv can populate them:

- `uv cache dir` — the package/wheel cache (default `~/.cache/uv`)
- `uv python dir` — uv-managed Python interpreters (default `~/.local/share/uv/python`)
- `uv tool dir` — tool environments from `uv tool install` (default `~/.local/share/uv/tools`)

The tool *bin* directory (`uv tool dir --bin`, default `~/.local/bin`) is
deliberately left unbound: it sits on the user's `PATH`, so granting write
access would let a sandboxed command install executables that persist and run
outside the sandbox. As a result `uv tool install` cannot place its launcher and
fails; use `uvx` (ephemeral tool runs, cached under `uv cache dir`) instead.

uv runtime commands enable safe Python development workflows:

```bash
uv init
uv add requests
uv sync
uv run main.py
uv pip install flask
uvx ruff check
```

Security features:
- `uv publish` requires explicit opt-in since it uploads distributions to a
  package index (shared state)
- `uv self update` is blocked — it downloads and overwrites the uv executable in
  place (an unsandboxable modification of the tool itself, like `deno upgrade`)

## Monty Python Runtime Support

`python` and `python3` are **enabled by default** and do not run any Python on
your `PATH`. They are served by [monty](https://github.com/pydantic/monty), a
Python interpreter compiled to WebAssembly and embedded in the lite-sandbox
binary, running in-process. The runtime is called `montypython` in config, to
keep it distinct from the real thing.

```bash
python3 -c "print('hello')"
python3 script.py --flag input.csv     # arguments arrive as sys.argv
python3 -m py_compile script.py        # syntax check
echo "print(6*7)" | python3 -
```

This is on by default where every other runtime is off because there is nothing
to install or detect, and monty is more contained than most commands already on
the whitelist: it has no network access, no environment, and no filesystem
access of its own. Turn it off with:

```yaml
runtimes:
  montypython:
    enabled: false   # Reject python/python3 (default: true)
```

```bash
lite-sandbox config runtimes montypython disable
lite-sandbox config runtimes montypython show
```

### Restricting it to inline code

`inline_only` keeps monty for programs the agent writes inline -- `-c`, or a
heredoc -- and refuses a script *file*:

```yaml
runtimes:
  montypython:
    inline_only: true   # Only -c and stdin; refuse script files (default: false)
```

```bash
lite-sandbox config runtimes montypython enable --inline-only
lite-sandbox config runtimes montypython disable --inline-only   # clear it, python stays on
```

The two cases fail differently. A snippet an agent just composed is written
against whatever the interpreter provides, and if it hits one of monty's walls
the error says so. A project's own `.py` file was written for CPython: it
imports packages monty does not have, and where monty's subset diverges it can
produce a plausible wrong answer instead of an error. With `inline_only` set,
the first case still works and the second says so up front.

Nothing falls through to the host interpreter as a result -- refusing is the
whole behavior. For real CPython, enable the [uv runtime](#uv-python) and use
`uv run`. `python3 -m py_compile file.py` still works, since it answers a
question about a file rather than running it.

### How file access works

monty performs no I/O itself. When Python touches the filesystem the interpreter
suspends and hands lite-sandbox a typed OS call, which is authorized against the
**same readable/writable paths as bash** before being performed:

- Reads (`read_text`, `read_bytes`, `stat`, `iterdir`, `exists`, …) are checked
  against the readable paths.
- Writes (`write_text`, `append_text`, `write_bytes`, `mkdir`, `unlink`,
  `rmdir`, `rename`, …) are checked against the writable paths.
- `.git` is off limits, as it is for `cat` and `sed`.
- A denied call ends the run. Python cannot catch it, so a script cannot loop on
  the boundary probing for a gap.

```bash
# Works: inside the working directory
python3 -c "from pathlib import Path; Path('out.txt').write_text('hi')"

# Denied: outside it, including via a symlink that points out
python3 -c "from pathlib import Path; print(Path('/etc/passwd').read_text())"
```

The builtin `open()` works and is bounded the same way. monty holds no file
descriptor: it builds its file object from a handle lite-sandbox returns, and
every read or write behind that object comes back as one of the authorized OS
calls above -- so `open()` is neither more nor less permissive than `pathlib`.
`read()`, `read(n)`, `readline()`, `readlines()`, `write()`, `seek()`,
`tell()`, `close()`, `with open(...) as f`, binary mode, and `.name` / `.mode`
/ `.closed` all behave. The open-time effect happens when you open, as in
CPython: `"w"` truncates, `"a"` creates, and `"r"` on a missing file raises a
`FileNotFoundError` the script can catch.

`os.getenv` and `os.environ` always report an empty environment. Re-exposing the
host's would hand Python the credentials the rest of the sandbox masks.

### What monty does not support

monty implements a **subset of Python**, and this is the thing most likely to
surprise you. There are no third-party packages — `numpy`, `pandas`, `requests`
and everything else cannot be imported, and there is no `pip` or `venv`. The
standard library is partial: `os`, `pathlib`, `json`, `re`, `math`, `datetime`,
`sys`, `typing`, `asyncio`, `dataclasses`, `collections`, `functools`,
`itertools` and `base64` are available.

Also unavailable:

| Not supported | Use instead |
| --- | --- |
| Iterating a file (`for line in f`) | `f.readlines()` |
| `open()` update modes (`r+`, `w+`, `a+`) | Read, then write separately |
| `python -m module` (except `py_compile`) | `-c` or a script file |
| `sys.exit`, `sys.stdout.write` | `print()`, and the shell for exit codes |
| Class inheritance, `super()`, `@property`, `@classmethod`, `@staticmethod` | Plain functions and classes |
| Generators, `match`, `del` | Lists and comprehensions |

When a program hits one of these, the error names monty and says what to do
instead, so it is not mistaken for a broken environment.

### sys.argv and sys.stdin

monty has neither of its own — its `sys` module is built from a fixed attribute
list, and Python cannot assign to it. lite-sandbox supplies both, so arguments
and piped input reach programs the way they do under CPython:

```bash
python3 tool.py --verbose data.csv   # sys.argv == ['tool.py', '--verbose', 'data.csv']
python3 -c "import sys; print(sys.argv)" a b   # ['-c', 'a', 'b']

cat data.json | python3 -c "import sys, json; print(json.load(sys.stdin))"   # no: see below
cat data.json | python3 -c "import sys, json; print(json.loads(sys.stdin.read()))"
```

`sys.stdin` supports `read()`, `readline()` and `readlines()`. It is the same
stdin the command was given, so it works in a pipeline, from a heredoc, or with
`< file` redirection, and reads as empty when nothing is piped in. `python3 -`
takes the program from stdin, which leaves nothing for the program to read —
the same as CPython. Reading `/dev/stdin` by name gets the same stream;
everything else about that path stays on the normal boundary.

Two gaps to know about, both monty's rather than lite-sandbox's: `json.load(f)`
does not exist (only `loads`), and a file object is not iterable, so
`for line in sys.stdin:` fails — use `sys.stdin.readlines()`.

`import sys`, `import sys as s`, `import sys, json` and `from sys import argv`
(or `stdin`) all work. This only happens for programs that mention `argv` or
`stdin`; anything else is handed to monty exactly as written. Tracebacks are
reported in your own line numbering either way.

### Syntax checking

`python -m py_compile FILE...` works and is a genuine check: monty compiles a
whole module before executing any of it, so the file is parsed without a line of
it running. It is silent and exits 0 when the files compile, and prints the
compiler's error and exits 1 when one does not. No `.pyc` files are written.

```bash
python3 -m py_compile script.py && echo "syntax ok"
```

No other `-m` module is available.

### Opting out: running the real python

There are three ways out, and every monty limitation message names all of them
so an agent that hits one is not left guessing.

**1. Run the host interpreter for `python` itself.** Add it to
`extra_commands`, and `python`/`python3` resolve from `$PATH` as usual:

```bash
lite-sandbox config extra-commands add python3
```

```yaml
extra_commands:
  - python3            # every invocation uses the host interpreter
  - python3 manage.py  # or only matching ones; the rest stay on monty
```

Like any `extra_commands` entry this **bypasses sandbox command validation** for
those invocations — the script runs as real CPython with subprocesses, network
and no path boundary (the OS sandbox, if enabled, still confines it; use
`unsandboxed_commands` to bypass that too). A bare entry also lifts the refusal
to run python as a wrapped subcommand of `xargs`/`env`/`timeout`/`find -exec`,
since it already runs unwrapped.

**2. Run CPython under uv, which stays sandboxed.** `uv run` executes real
CPython as a subprocess confined by the OS sandbox rather than by monty:

```bash
lite-sandbox config runtimes uv enable
uv run script.py
```

**3. Turn the built-in interpreter off.** `python`/`python3` are then rejected
like any other command that is not allowed:

```bash
lite-sandbox config runtimes montypython disable
```

### Limits

Each run is bounded by the bash tool's command timeout, plus a memory cap, a
recursion limit, and a cap on how many filesystem operations one run may make.
Exceeding any of them stops the program with a message that says which limit it
hit.
