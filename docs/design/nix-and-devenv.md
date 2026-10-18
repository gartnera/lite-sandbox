# Nix and devenv support: evaluation

Status: proposal. Nothing here is implemented yet.

This evaluates adding [toolchain profiles](../profiles.md) for Nix and devenv.
Findings marked *tested* were reproduced on Linux with Nix 2.34.6 (multi-user,
daemon), devenv 2.4.0, and bubblewrap, as a non-root user, in `allowlist` mode
with the OS sandbox on. The rest comes from the current Nix, devenv, and
nix-direnv sources and documentation.

## Summary

Both are feasible and fit the profile model (`config/profiles.go`): a list of
commands entries, path grants from a detector, and argument validators in
`tool/bash_sandboxed/profiles.go`. Getting them to *run* takes two internal
cache grants. The work is in the validators, because Nix and devenv offer
several ways to run code the current validation layer cannot see.

## What works today

| Test | Result |
|---|---|
| `nix build`, `nix eval`, `nix develop -c …` in the sandbox | works once `~/.cache/nix` has an internal write grant; without it: `creating directory "~/.cache/nix": Read-only file system` (*tested*) |
| Reaching the Nix daemon from inside bubblewrap | works unchanged: `--ro-bind / /` makes the client's `auto` store fall through to the daemon, and `connect()` to a socket on a read-only mount succeeds (*tested*). On macOS the sandbox-exec profile's `(allow network*)` permits it |
| `devenv shell -- jq --version`, `devenv test`, `devenv tasks list`, `devenv up -d` | works once `~/.local/share/devenv` is also granted (*tested*) |
| `cat result/bin/x`, `./result/bin/x` after a build | refused: `result` resolves into `/nix/store`, outside the read boundary, and running it hits the local-binary gate (*tested*) |
| `nix profile install` | refused by the read-only `$HOME` in `allowlist` mode (*tested*); would succeed in `denylist` mode |
| Single-user Nix (no daemon) | the client picks the local store and fails on the read-only `/nix`; supporting it would mean making the store writable. Not proposed |

## Security findings

1. **Wrapped commands escape validation.** `nix develop -c X`,
   `nix shell … -c X` and `devenv shell -- X` run `X` themselves, so it never
   reaches the interpreter's handlers. Even a restricted allow of
   `"devenv shell"` let `devenv shell -- sh -c "cat ~/…"` read outside the
   boundary (*tested*). Both also run the project's `shellHook` / `enterShell`
   (agent-editable) inside the OS sandbox. They must be validated as wrappers,
   like `env` and `xcrun`, with the child through `validateSubCommand`.
2. **Client-side settings run arbitrary programs at eval time.**
   `nix eval --allow-unsafe-native-code-during-evaluation --impure -f x.nix`
   ran `builtins.exec` (*tested*), and so did `--option …` and
   `NIX_CONFIG=…`, both as a prefix assignment and via `export` (*tested*).
   Nix accepts every setting as a `--<setting>` flag, with `--extra-` and
   `--no-` forms, so the validator must refuse settings flags generally, and
   `NIX_CONFIG`, `NIX_USER_CONF_FILES` and `NIX_CONF_DIR` belong in
   `blockedEnvVars`.
3. **A trusted user is root.** The Nix manual says adding a user to
   `trusted-users` is "essentially equivalent to giving that user root
   access". With the test user trusted,
   `nix build --rebuild --option post-build-hook ./hook.sh` from inside
   bubblewrap ran the hook as `uid=0(root)` (*tested*). Untrusted, the daemon
   ignored it with a warning. devenv's `--nix-option` and a flake's
   `nixConfig` (with `accept-flake-config`) are further ways in.
   `nix store info --json` reports `"trusted": true|false`, so the profile can
   check it.
4. **devenv's auto-activation list.** `devenv allow`, run inside the sandbox
   with `~/.local/share/devenv` granted, wrote `~/.local/share/devenv/allowed`
   (*tested*): the directories a host shell with devenv's hook auto-activates,
   i.e. runs an agent-written `devenv.nix` on `cd`. Only `gc/` and
   `cachix_trusted_keys.json` may be granted. direnv's allow list
   (`~/.local/share/direnv`), `~/.config/nix`, and
   `~/.local/share/nix/trusted-settings.json` (accepted flake `nixConfig`
   settings) need protecting in `denylist` mode, where `$HOME` is writable.
5. **Builds run in the daemon, outside the OS sandbox.** This is the Docker
   trust model again. On Linux Nix's own build sandbox applies (fixed-output
   derivations do get the network). On macOS `sandbox` defaults to `false`,
   so an agent-written derivation runs unconfined as a `_nixbld` user.
6. **Smaller items.**
   - Untrusted users may run `nix store gc` / `nix store delete`, which act on
     the whole shared store.
   - `--impure` evaluation reads any file the OS sandbox does not mask (the
     same class as `go` / `cargo` build scripts).
   - `nix run github:…` builds and runs remote code (why `go run pkg@latest` is
     refused).
   - `devenv machines` deploys over root SSH; `devenv shell --from github:…`
     loads `devenv.nix` from elsewhere.
   - devenv's `claude.code.enable` generates `.claude/` files, which bash
     treats as read-only (`tool/bash_sandboxed/claude_dir.go`).

## Proposed design

### `nix` profile

- **Store stays read-only; the daemon does every store write.** This is the
  Nix-in-Docker arrangement (store mounted read-only, daemon socket reachable):
  `/nix` is already read-only under the worker's `--ro-bind / /`, and the
  profile sets `NIX_REMOTE=daemon` so relying on the daemon is explicit and a
  single-user or daemonless setup fails with "cannot connect to daemon" rather
  than a read-only filesystem error. The daemon is then the trust boundary,
  which is why the trust check below and the refusal of `store gc` matter: a
  read-only store stops neither a trusted user's root-run `post-build-hook`
  nor store-wide garbage collection, both of which go through the socket.
- **Paths:** `~/.cache/nix` (or `$XDG_CACHE_HOME/nix`) as read plus internal
  write. Optionally a *read* grant on `/nix/store` in the validation layer's
  boundary (not the OS sandbox, where it is already readable), so the agent's
  own commands can read and run `result/` build outputs.
- **Allowed:** `build`, `eval`, `flake show|metadata|check|lock|update`, `log`,
  `path-info`, `search`, `why-depends`, `print-dev-env`, `store ls|cat`.
- **Wrappers:** `develop` and `shell` require `-c`/`--command`, validate the
  child with `validateSubCommand`, and accept only local flake references.
- **Refused:** `run`, `repl`, `profile`, `registry`, `copy`,
  `store gc|delete|repair|optimise`, `upgrade-nix`, `daemon`, `nix-env`,
  `nix-channel`, `nix-collect-garbage`, every settings flag, and `--impure`
  unless an option allows it. Opening one follows the existing restricted
  allow pattern (`"go generate"`).
- **Preconditions:** refuse to enable for a trusted user or a local-store
  (single-user) install; on macOS warn when `sandbox` is off.

### `devenv` profile

Requires the `nix` profile.

- **Paths:** `~/.local/share/devenv/gc` and the cachix keys file only.
- **Allowed:** `shell` as a wrapper with a required command, `test`, `build`,
  `eval`, `info`, `search`, `tasks`, `update`, `inputs add`, `init`.
- **Background:** `up` (foreground blocks), `processes`, `down`. The agent
  uses the bash tool's background mode or `up -d`.
- **Refused:** `machines`, `container copy|run`, `allow`, `revoke`, `hook`,
  `mcp`, `lsp`, `repl`, `--from <remote>`, `--nix-option`.

### Optional extras

- **Dev environment activation.** Today commands only see a dev environment
  when the agent was started from a shell where direnv already loaded it.
  The sandbox could capture `nix print-dev-env --json` inside the worker
  (cached against the lock file) and merge its variables into the
  interpreter's environment, so every command keeps full runtime validation
  instead of the wrapper path. The JSON form is the only one that does not
  run `shellHook`. devenv puts its runtime directory under `/tmp`, which is
  private to the worker, so a host-side `devenv up` service is reachable over
  TCP but not through its Unix socket.
- **Packaging lite-sandbox with Nix.** A `flake.nix` with `buildGoModule` is
  straightforward since the monty-go fork commits `monty.wasm`. Two fixes come
  with it: `install` resolves symlinks (`cmd/install.go`), so it would save a
  `/nix/store/<hash>/…` path that breaks after an upgrade plus garbage
  collection; and `lite-sandbox update` should refuse a binary in the store.

## Order

1. `nix` profile: validators, blocked environment variables, trust check,
   deny-list entries.
2. `devenv` profile.
3. Dev environment activation.
4. Flake packaging.

Each needs e2e coverage against a real Nix daemon in CI.

## Open questions

- Is a trusted user a hard refusal or a profile option?
- Should `/nix/store` be readable by default? It is world-readable by design,
  but some setups leak secrets into it.
