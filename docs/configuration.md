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
