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

The per-user system temp directory (`$TMPDIR`, e.g. macOS's
`/var/folders/.../T`) is likewise always readable and writable without a config
entry, since many tools place scratch files there by default. It is granted only
when it is a private, per-user location; when `$TMPDIR` is unset and the temp dir
is the world-shared `/tmp` (the common Linux default), it is **not** granted
wholesale — the uid-scoped scratchpad above still covers `/tmp/claude-<uid>`
there.

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

## Redundant `cd` rejection

Agents habitually prefix a command with `cd /abs/path/to/repo && ...` even though
the sandbox already runs in that directory. By default the sandbox rejects this
noise so the agent drops it:

```
unneeded cd: cwd is already /abs/path/to/repo (drop the leading "cd /abs/path/to/repo")
```

The match is deliberately narrow: only a **leading `cd` with a single literal,
absolute-path argument that resolves exactly to the working directory** is
rejected. A `cd` into a subdirectory, a relative `cd`, `cd .`, a dynamic target
like `cd "$PWD"`, or a `cd` carrying flags are all left alone — those are either
legitimate or not the redundant prefix agents emit.

Disable it (allowing the redundant `cd`) with:

```yaml
reject_redundant_cd: false
```

Manage it with `lite-sandbox config redundant-cd enable|disable|show`. Like every
section it can be flipped per directory via the overrides below.

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
  - path: ~/work/trusted
    merge: true                   # deep-merge instead of replace (see below)
    docker:
      allow_privileged: true      # only this flag changes; docker.enabled etc. kept
```

Resolution rules:

- **Most specific wins.** When a directory lies under more than one override
  `path`, the longest matching path applies; the others are ignored (overrides do
  not stack).
- **Replace vs. merge.** By default an override **replaces** each section it sets:
  an override with an `aws:` block defines the *entire* AWS mode for its
  directory, dropping any base `aws:` fields it doesn't restate. Set `merge: true`
  on an override to **deep-merge** it instead — it recurses into a section and
  applies only the fields it sets, inheriting the rest (so the `~/work/trusted`
  example above flips just `docker.allow_privileged` and keeps the base
  `docker.enabled`). Either way, sections the override never mentions are
  inherited from the base unchanged, and leaf values it does set (scalars, flags,
  and lists like `writable_paths`) come from the override.
- **Paths support `~`** and are resolved to absolute paths, so relative inputs
  match the concrete directory they denote.

The `config aws` subcommands accept a `--dir <path>` flag to edit the AWS section
of an override instead of the base (e.g. `lite-sandbox config aws force-profile
<profile> --dir <path>`). Overrides for other sections — and the `merge` flag —
are authored by editing the `overrides` list in the config file directly.

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
