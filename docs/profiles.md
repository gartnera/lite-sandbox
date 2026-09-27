# Toolchain Profiles

A profile is a built-in preset of **commands** and **paths** for one toolchain:
`go`, `pnpm`, `rust`, `deno`, `flutter`, `uv`, and `montypython`. Profiles are
off by default and enabled one at a time:

```yaml
profiles:
  - go
  - rust
  - name: deno            # a profile with options
    options:
      allow_network: true
```

```bash
lite-sandbox config profiles list            # every profile, enabled or not, with its options
lite-sandbox config profiles enable go rust
lite-sandbox config profiles disable rust
lite-sandbox config profiles set deno allow_network true
lite-sandbox config profiles show go         # commands, options, and the paths detected now
```

A profile is written in the config's own terms: a list of
[`commands`](configuration.md#commands) entries and a list of
[`paths`](configuration.md#paths) entries. Enabling it merges those entries
into your `commands` and `paths` lists before the sandbox sees them, so an entry
means what it would mean had you written it (`no_sandbox` on a command,
`read`/`write`/`internal` on a path), with two differences:

- **Commands**: a profile's allow of a command name whitelists the command
  rather than skipping validation the way your own allow does. It keeps its
  argument validator, so `go test` runs while `go run pkg@latest` stays
  refused.
- **Paths**: the directories come from asking the toolchain (e.g.
  `go env GOPATH GOCACHE`). The built-in profiles grant each one readable by the
  agent and writable only by the programs a command runs (`internal`, the OS
  sandbox layer). A profile's grant never lifts a built-in path denial the way
  a grant you write does.

`lite-sandbox config profiles show <name>` prints a profile's entries, with the
paths detected on this machine.

The subcommands a profile's validators refuse because they reach shared state
(`go generate`, `pnpm publish`, `cargo publish`, `deno publish`, `uv publish`)
each take a `commands` entry for exactly that text:

```bash
lite-sandbox config commands allow "cargo publish"
```

`montypython` is the exception to "off by default": `python`/`python3` run on
an interpreter embedded in lite-sandbox, so it is **enabled by default**. See
[Monty Python](#monty-python).

A config written with the older `runtimes:` section is migrated to profiles
the first time it is loaded, and the file is rewritten in the new form:
`runtimes.go.enabled: true` becomes `- go`, deno's and montypython's settings
become profile options, and `go.generate` / `<x>.publish` become the commands
entries above. The former `lite-sandbox config runtimes <x> enable` commands
still work as an alias.

## Go

The `go` profile whitelists `go` and `gofmt` (`go build`, `go test`, `go mod`, etc.)
and grants `GOPATH` and `GOCACHE`:

```yaml
profiles:
  - go
commands:
  - command: go generate   # optional: allow go generate
    allow: true
```

Go commands get the same runtime path validation as other commands, so file paths stay within the allowed directories:

```bash
go mod init myproject
go test ./...
go build -o mybinary
```

`go generate` needs its own `commands` entry because it runs arbitrary commands specified in source files.

`e2e/claude/test_go_runtime_e2e.py` has a full example of a Go workflow (module init, testing, git) using only the sandboxed tool.

## pnpm

The `pnpm` profile whitelists `pnpm` (`pnpm install`, `add`, `test`, `run`, etc.):

```bash
lite-sandbox config profiles enable pnpm
lite-sandbox config commands allow "pnpm publish"   # optional
```

For example:

```bash
pnpm install
pnpm add react
pnpm test
pnpm run build
```

The profile detects and grants (writable at the OS sandbox layer):

- **pnpm store**: `pnpm store path`, where downloaded packages live.
- **pnpm cache**: the `cache-dir` setting, defaulting to the OS cache
  directory joined with `pnpm` (e.g. `~/Library/Caches/pnpm` on macOS,
  `~/.cache/pnpm` on Linux). It holds registry metadata and the `pnpm dlx`
  cache, so pnpm run indirectly inside the sandbox (e.g. by a lefthook job or
  package script) can populate it.

Restrictions:
- `pnpm dlx` is blocked when invoked directly, since it downloads and runs remote packages
- `pnpm publish` needs a `commands` entry because it changes the npm registry

## Rust

The `rust` profile whitelists `cargo` and `rustc` (`cargo build`, `test`, `run`,
`fmt`, `clippy`, `add`, etc.):

```bash
lite-sandbox config profiles enable rust
lite-sandbox config commands allow "cargo publish"   # optional
```

`CARGO_HOME` (default `~/.cargo`) and `RUSTUP_HOME` (default `~/.rustup`) are
granted, writable at the OS sandbox layer, so cargo can populate its registry
cache and toolchains.

Restrictions:
- `cargo publish` needs a `commands` entry because it changes the crates.io registry
- `cargo login`, `logout`, `owner`, and `yank` are blocked
- `cargo install` is allowed only with `--path`; installing a crate by name
  fetches it and runs its build script

## Deno

The `deno` profile whitelists `deno` (`deno run`, `test`, `fmt`, `lint`, `task`,
etc.) and has three options:

```yaml
profiles:
  - name: deno
    options:
      auto_sandbox: true   # Auto-scope --allow-read/--allow-write to sandbox paths (default: true)
      allow_network: false # Allow outbound network sockets (default: false)
      allow_import: true   # Allow fetching remote modules (default: true)
```

```bash
lite-sandbox config profiles enable deno
lite-sandbox config profiles set deno allow_network true   # allow outbound sockets
lite-sandbox config profiles set deno allow_import false   # lock down remote imports (blocks cache/add/install)
lite-sandbox config profiles set deno auto_sandbox false   # keep deno, drop the injected --allow-read/--allow-write
lite-sandbox config commands allow "deno publish"          # optional
```

For example:

```bash
deno run main.ts
deno test
deno fmt
deno lint
deno task build
```

Restrictions:
- `deno publish` needs a `commands` entry because it changes the JSR registry
- `deno upgrade` is blocked because it modifies the deno installation in place
- `deno eval` is blocked: it always runs with *all* permissions and rejects
  every `--allow-*`/`--deny-*` flag, so it can't be confined.
- **Auto-sandbox** (`auto_sandbox: true`, the default): Deno starts with no
  permissions and prompts interactively when a script asks for more, which
  would hang in the sandbox. With auto-sandbox on, lite-sandbox injects
  `--allow-read`/`--allow-write` scoped to the sandbox's allowed paths for the
  permissioned subcommands (`run`, `test`, `bench`, `repl`, `serve`,
  `compile`, `install`), so Deno's permissions match the sandbox's filesystem
  policy and it never prompts. Read/write grants already on the command
  (including `-R`/`-W` or `-A`) are kept.
- **Network off by default**: `--deny-net` is forced unless
  `allow_network: true`. This applies whenever deno is enabled, whether or not
  auto-sandbox is on, and `--deny-net` overrides any `--allow-net`/`-A` on the
  command.
- **Remote imports on by default**: normal Deno usage fetches modules from a
  default host allowlist (`deno.land`/`jsr.io`/…), so imports are allowed by
  default. `allow_import: false` adds `--no-remote` (https/jsr) and `--no-npm`
  (npm) to code-executing subcommands, which stop the module graph from being
  fetched, plus `--deny-import` for dynamic imports at runtime. It also blocks
  `deno cache`, `deno add`, and `deno install`, which fetch at the CLI level
  where an injected flag can't stop them. Modules already in the cache can
  still load.

## Flutter

The `flutter` profile whitelists `flutter`, `dart`, and `fvm` (Flutter Version
Management):

```bash
lite-sandbox config profiles enable flutter
```

For example:

```bash
fvm install
fvm flutter pub get
fvm flutter test
flutter build apk
dart run build_runner build
```

As with Go's `GOPATH`/`GOCACHE`, the profile detects and grants the paths these
tools read and write, so builds and tests work without
extra `paths` grants:

- **fvm cache**: `FVM_CACHE_PATH` (or the legacy `FVM_HOME`), default `~/fvm`,
  where fvm stores each Flutter SDK version.
- **pub cache**: `PUB_CACHE`, default `~/.pub-cache`, where Dart/Flutter
  packages are downloaded.
- **Flutter SDK root**: `FLUTTER_ROOT`, or found from a `flutter` binary on
  `PATH` (for a non-fvm global install). Flutter writes to `bin/cache` under
  it. A candidate is accepted only if it contains a `packages/` directory, so a
  stray binary in a system directory can't widen access to `/usr`.
- **Flutter/Dart config directories**: `~/.config/flutter`, `~/.config/dart`,
  `~/.flutter`, and `~/.dart`, where the tools keep settings and analytics
  state.

Directories that don't exist yet are created up front so the OS sandbox has
something to bind-mount.

Like Go, Rust, and Deno, Flutter runs arbitrary code, so it is contained by the
OS sandbox confining writes to the working directory and the detected paths,
not by argument validation. Once enabled, all `flutter`/`dart`/`fvm`
subcommands are allowed.

## uv

The `uv` profile whitelists [uv](https://docs.astral.sh/uv/) and `uvx` (`uv sync`,
`add`, `run`, `pip`, `venv`, `build`, `tool`, etc.):

```bash
lite-sandbox config profiles enable uv
lite-sandbox config commands allow "uv publish"   # optional
```

It grants the paths uv needs outside the working directory, found by asking uv:

- `uv cache dir`: the package/wheel cache (default `~/.cache/uv`)
- `uv python dir`: uv-managed Python interpreters (default `~/.local/share/uv/python`)
- `uv tool dir`: tool environments from `uv tool install` (default `~/.local/share/uv/tools`)

The tool *bin* directory (`uv tool dir --bin`, default `~/.local/bin`) is not
granted. It is on the user's `PATH`, so write access would let a sandboxed
command install executables that later run outside the sandbox. As a result,
`uv tool install` can't place its launcher and fails; use `uvx` instead (tool
runs are cached under `uv cache dir`).

For example:

```bash
uv init
uv add requests
uv sync
uv run main.py
uv pip install flask
uvx ruff check
```

Restrictions:
- `uv publish` needs a `commands` entry because it uploads to a package index
- `uv self update` is blocked because it overwrites the uv executable in place

## Monty Python

`python` and `python3` are **enabled by default** and don't run any Python on
your `PATH`. They are served by [monty](https://github.com/pydantic/monty), a
Python interpreter compiled to WebAssembly, embedded in the lite-sandbox
binary, and run in-process. The profile is called `montypython` to distinguish
it from real Python; it grants no paths.

```bash
python3 -c "print('hello')"
python3 script.py --flag input.csv     # arguments arrive as sys.argv
python3 -m py_compile script.py        # syntax check
echo "print(6*7)" | python3 -
```

It's on by default, unlike the other profiles, because there's nothing to
install or detect, and monty is more contained than many commands already on
the whitelist: it has no network access, no environment, and no filesystem
access of its own. To turn it off:

```yaml
profiles:
  - name: montypython
    enabled: false   # Reject python/python3, in denylist mode too
```

```bash
lite-sandbox config profiles disable montypython
lite-sandbox config profiles show montypython
```

### Restricting it to inline code

The `inline_only` option allows programs the agent writes inline (`-c` or a
heredoc) and refuses script *files*:

```yaml
profiles:
  - name: montypython
    options:
      inline_only: true   # Only -c and stdin; refuse script files (default: false)
```

```bash
lite-sandbox config profiles set montypython inline_only true
lite-sandbox config profiles set montypython inline_only false   # clear it, python stays on
```

The reason: a snippet the agent just wrote targets whatever the interpreter
provides, and if it hits one of monty's limits the error says so. A project's
own `.py` file was written for CPython. It may import packages monty doesn't
have, and where monty's subset differs it can produce a plausible wrong answer
instead of an error. With `inline_only`, the first case still works and the
second is refused up front.

A refused script doesn't fall back to the host interpreter. For real CPython,
enable the [uv profile](#uv) and use `uv run`.
`python3 -m py_compile file.py` still works, since it checks a file without
running it.

### How file access works

monty does no I/O itself. When Python touches the filesystem, the interpreter
suspends and hands lite-sandbox a typed OS call, which is checked against the
**same readable/writable paths as bash** before it is performed:

- Reads (`read_text`, `read_bytes`, `stat`, `iterdir`, `exists`, …) are checked
  against the readable paths.
- Writes (`write_text`, `append_text`, `write_bytes`, `mkdir`, `unlink`,
  `rmdir`, `rename`, …) are checked against the writable paths.
- `.git` is off limits, as it is for `cat` and `sed`.
- A denied call ends the run. Python can't catch it, so a script can't loop
  probing the boundary.

```bash
# Works: inside the working directory
python3 -c "from pathlib import Path; Path('out.txt').write_text('hi')"

# Denied: outside it, including via a symlink that points out
python3 -c "from pathlib import Path; print(Path('/etc/passwd').read_text())"
```

The builtin `open()` works with the same bounds. monty holds no file
descriptor: it builds its file object from a handle lite-sandbox returns, and
every read or write on that object comes back as one of the checked OS calls
above, so `open()` allows exactly what `pathlib` does. `read()`, `read(n)`,
`readline()`, `readlines()`, `write()`, `seek()`, `tell()`, `close()`,
`with open(...) as f`, binary mode, and `.name` / `.mode` / `.closed` all
work. As in CPython, the mode takes effect at open time: `"w"` truncates, `"a"`
creates, and `"r"` on a missing file raises a `FileNotFoundError` the script
can catch.

`os.getenv` and `os.environ` always see an empty environment, since the host's
would expose the credentials the rest of the sandbox masks.

### What monty does not support

monty implements a **subset of Python**, which is the most likely source of
surprises. There are no third-party packages: `numpy`, `pandas`, `requests`,
and the rest can't be imported, and there's no `pip` or `venv`. The standard
library is partial: `os`, `pathlib`, `json`, `re`, `math`, `datetime`, `sys`,
`typing`, `asyncio`, `dataclasses`, `collections`, `functools`, `itertools`,
and `base64` are available.

Also unavailable:

| Not supported | Use instead |
| --- | --- |
| Iterating a file (`for line in f`) | `f.readlines()` |
| `open()` update modes (`r+`, `w+`, `a+`) | Read, then write separately |
| `python -m module` (except `py_compile`) | `-c` or a script file |
| `sys.exit`, `sys.stdout.write` | `print()`, and the shell for exit codes |
| Class inheritance, `super()`, `@property`, `@classmethod`, `@staticmethod` | Plain functions and classes |
| Generators, `match`, `del` | Lists and comprehensions |

When a program hits one of these, the error names monty and suggests an
alternative.

### sys.argv and sys.stdin

monty provides neither: its `sys` module has a fixed set of attributes, and
Python can't assign to it. lite-sandbox supplies both, so arguments and piped
input work as they do in CPython:

```bash
python3 tool.py --verbose data.csv   # sys.argv == ['tool.py', '--verbose', 'data.csv']
python3 -c "import sys; print(sys.argv)" a b   # ['-c', 'a', 'b']

cat data.json | python3 -c "import sys, json; print(json.load(sys.stdin))"   # no: see below
cat data.json | python3 -c "import sys, json; print(json.loads(sys.stdin.read()))"
```

`sys.stdin` supports `read()`, `readline()`, and `readlines()`. It's the
command's own stdin, so it works in a pipeline, from a heredoc, or with
`< file`, and reads as empty when nothing is piped in. `python3 -` reads the
program from stdin, which leaves nothing for the program itself to read, as in
CPython. Reading `/dev/stdin` by name gets the same stream; any other use of
that path is subject to the normal boundary.

Two monty gaps to watch for: `json.load(f)` doesn't exist (only `loads`), and
file objects aren't iterable, so `for line in sys.stdin:` fails. Use
`sys.stdin.readlines()` instead.

`import sys`, `import sys as s`, `import sys, json`, and `from sys import argv`
(or `stdin`) all work. The shim is only added to programs that mention `argv`
or `stdin`; everything else goes to monty unchanged. Tracebacks use your
program's line numbers either way.

### Syntax checking

`python -m py_compile FILE...` is a real syntax check: monty compiles a whole
module before running any of it, so the file is parsed without executing. It
prints nothing and exits 0 when the files compile, or prints the compiler's
error and exits 1. No `.pyc` files are written.

```bash
python3 -m py_compile script.py && echo "syntax ok"
```

No other `-m` module is available.

### Opting out: running the real python

There are three options, and every monty limitation message lists all of them.

**1. Run the host interpreter for `python` itself.** Allow it as a
[`commands` entry](configuration.md#commands), and `python`/`python3` resolve
from `$PATH` as usual:

```bash
lite-sandbox config commands allow python3
```

```yaml
commands:
  - command: python3            # every invocation uses the host interpreter
    allow: true
  - command: python3 manage.py  # or only matching ones; the rest stay on monty
    allow: true
```

Like any allowed command, this **skips sandbox command validation** for those
invocations: the script runs as real CPython with subprocesses, network, and no
path boundary. The OS sandbox, if enabled, still confines it; add
`no_sandbox: true` to bypass that too. A bare entry also allows python as a
wrapped subcommand of `xargs`/`env`/`timeout`/`find -exec`, since it can
already run unwrapped.

**2. Run CPython under uv, which stays sandboxed.** `uv run` runs real CPython
as a subprocess, confined by the OS sandbox instead of by monty:

```bash
lite-sandbox config profiles enable uv
uv run script.py
```

**3. Turn the built-in interpreter off.** `python`/`python3` are then rejected
like any other command that isn't allowed:

```bash
lite-sandbox config profiles disable montypython
```

### Limits

Each run is bounded by the bash tool's command timeout, a memory cap, a
recursion limit, and a cap on filesystem operations per run. A program that
exceeds one is stopped with a message naming the limit.
