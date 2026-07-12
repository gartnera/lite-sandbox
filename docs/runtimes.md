# Runtime Support

Code execution runtimes are disabled by default and can be enabled individually
via config. This page covers Go, pnpm, Rust, Deno, and Flutter.

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

Security features:
- `pnpm dlx` is blocked (downloads and executes remote packages)
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
  `~/.flutter`, `~/.dart`, and `~/.dart-tool`, where the tools persist settings
  and analytics state.

Directories that don't exist yet (fresh machine, cold caches) are created up
front so the OS sandbox has a bind-mount source for them.

Flutter is a code-execution runtime: like Go, Rust, and Deno, its containment
relies on the OS sandbox confining writes to the working directory and the
detected runtime paths, rather than on per-argument validation. Once enabled,
all `flutter`/`dart`/`fvm` subcommands are permitted.
