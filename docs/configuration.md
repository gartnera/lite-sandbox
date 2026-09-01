# Configuration

Extra commands can be allowed via a config file at the platform-appropriate location:

- **Linux**: `~/.config/lite-sandbox/config.yaml`
- **macOS**: `~/Library/Application Support/lite-sandbox/config.yaml`

```yaml
extra_commands:
  - curl
  - python3
```

A bare entry (a single token) allows the command with any arguments and, when it
is the leading command of an invocation, bypasses bash AST parsing entirely —
the whole command string runs via the real bash. An entry with a subcommand
(e.g. `uv run pyright`) restricts the command to invocations whose leading
non-flag arguments match, and still goes through normal parsing and validation.
When the [OS sandbox](security.md#os-level-sandboxing-optional) is enabled,
bare entries run inside it like every other command, so filesystem confinement
applies even though validation is skipped.

### Unsandboxed commands

`unsandboxed_commands` is parsed exactly like `extra_commands` (same bare and
subcommand-restricted entry formats, same validation bypass) with one
difference: matching invocations always run **directly on the host**, bypassing
the [OS sandbox](security.md#os-level-sandboxing-optional) worker
(bwrap/sandbox-exec) even when it is enabled. This is a trust-based escape hatch
for commands that cannot run confined.

```yaml
unsandboxed_commands:
  - docker            # talk to the real docker daemon, not the filtering proxy
  - ./scripts/deploy.sh
```

Because these commands leave the OS sandbox, the docker filtering proxy is also
bypassed: the proxy `DOCKER_HOST` override is not applied, so `docker` reaches
the real daemon (or whatever `DOCKER_HOST` the host environment already sets).
Subcommand-restricted entries only unsandbox matching invocations — e.g.
`git push` leaves other `git` subcommands confined.

Manage the list with
`lite-sandbox config unsandboxed-commands add|list|remove`.

The config file is automatically reloaded when changed — no server restart needed.

## CLI config management

```bash
# Print config file path
lite-sandbox config path

# Show current configuration
lite-sandbox config show

# Add extra allowed commands
lite-sandbox config extra-commands add curl wget

# List extra allowed commands
lite-sandbox config extra-commands list

# Remove extra allowed commands
lite-sandbox config extra-commands remove curl
```

## Readable / writable paths

By default the sandbox confines reads and writes to the working directory. Extra
locations can be granted via `readable_paths` / `writable_paths`:

```yaml
readable_paths:
  - ~/reference-data                 # this dir and everything under it
  - ~/.superconductor/worktrees/haystack/*  # only paths NESTED below it
writable_paths:
  - ~/scratch
```

A bare path grants the directory **and** all of its contents. A trailing `/*`
grants only paths **nested below** the directory — the directory itself is not a
valid read/search target. This is useful for a container that holds many sibling
directories (e.g. a worktree parent): `worktrees/haystack/*` lets the sandbox
read an individual peer worktree while blocking a single `grep`/`ls` from
sweeping every worktree at once. Manage these with
`lite-sandbox config readable-paths add <path>` / `writable-paths add <path>`.

The Claude Code per-user scratchpad root (`/tmp/claude-<uid>`, which macOS
resolves to `/private/tmp/claude-<uid>`) is always readable and writable without
a config entry, so agents can use it for temporary files. It is uid-scoped and
was already writable at the OS-sandbox layer; this only opens the agent-facing
boundary to match.

## Internal readable / writable paths (OS sandbox only)

`internal_readable_paths` / `internal_writable_paths` grant access **only at the
OS sandbox layer** (see [Security](security.md)), so programs a command spawns
can reach their own data — while the agent itself still cannot read or write
those paths directly (the AST/runtime path validation, the file-tool hook, and
Deno's injected `--allow-read`/`--allow-write` all keep denying them):

```yaml
internal_writable_paths:
  - ~/.cache/some-tool   # the tool can update its cache; `cat`/`sed` there still fail
internal_readable_paths:
  - /opt/reference-data
```

Use these when a tool needs its own state directory to function under the OS
sandbox, but you don't want to widen the boundary the agent can touch. They only
have an effect when `os_sandbox` is enabled — without it there is no OS layer to
loosen. Note that inside the OS sandbox the filesystem is already broadly
readable, so `internal_readable_paths` mainly matters for host paths hidden by
the sandbox's `/tmp` overlay on Linux. Manage these with
`lite-sandbox config internal-readable-paths add <path>` /
`internal-writable-paths add <path>`.

## Per-directory overrides

Any part of the configuration can be changed for specific working directories via
the top-level `overrides` list. Each entry pairs a `path` with any config
sections that replace the base for commands run **at or under** that path. This is
not AWS-specific — `aws`, `docker`, `runtimes`, `readable_paths`/`writable_paths`,
`os_sandbox`, and every other section can be overridden the same way.

```yaml
os_sandbox: true
writable_paths:
  - ~/scratch
aws:
  force_profile: "default"        # base mode for everything else

overrides:
  - path: ~/work/acme             # ~ is expanded
    aws:
      force_profile: "acme-dev"   # broker a different AWS profile here
    writable_paths:
      - ~/work/acme/artifacts     # replaces (not extends) writable_paths here
  - path: ~/work/acme/prod
    aws:
      force_profile: "acme-prod"  # more specific path wins under prod/
  - path: ~/scratch
    os_sandbox: false             # any section can be overridden
```

Resolution rules:

- **Most specific wins.** When a directory lies under more than one override
  `path`, the longest matching path applies; the others are ignored (overrides do
  not stack).
- **Whole sections replace, they don't merge.** An override that sets `aws:`
  defines the *entire* AWS mode for its directory — its fields do not merge with
  the base `aws:` block. Sections the override leaves unset are inherited from the
  base config unchanged.
- **Paths support `~`** and are resolved to absolute paths, so relative inputs
  match the concrete directory they denote.

Section-specific CLI subcommands accept a `--dir <path>` flag to edit the
corresponding section of an override instead of the base (e.g. `lite-sandbox
config aws force-profile <profile> --dir <path>`).

## Git Support

Git commands are enabled by default with granular permission levels that can be configured:

```yaml
git:
  local_read: true             # git status, log, diff, show (default: true)
  local_write: true            # git add, commit, branch, tag (default: true)
  remote_read: true            # git fetch, pull, clone (default: true)
  remote_write: false          # git push (default: false)
  allow_worktree_parent: false # if cwd is a linked worktree, also allow read+write to the main worktree (default: false)
```

Remote write operations (`git push`) are disabled by default since they affect shared state. Enable them only if you want to allow Claude to push commits:

```bash
# Show current git configuration
lite-sandbox config show

# Edit config file to enable git push
# Add 'remote_write: true' under the git section
```

Git commands use runtime path validation to ensure repository paths stay within allowed directories, even when variables are expanded (e.g., `git -C $REPO_DIR status` validates the expanded path).
