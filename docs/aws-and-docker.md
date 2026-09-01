# AWS & Docker Access

Both of these are opt-in integrations that let sandboxed commands reach AWS and
Docker **without** handing them your raw credentials or an unrestricted daemon
socket. Both are disabled by default and most useful with the
[OS sandbox](security.md#os-level-sandboxing-optional) enabled.

## AWS credentials

By default the OS sandbox denies access to `~/.aws`. The `aws` config section
controls how (and whether) sandboxed commands get credentials. It has two
mutually exclusive modes:

```yaml
aws:
  allow_raw_credentials: false  # let commands read ~/.aws directly (default: false)
  force_profile: ""             # broker credentials for this profile via a local IMDS server (default: "")
```

- **Disabled** (no `aws` section) — `~/.aws` stays blocked under the OS sandbox; commands have no AWS credentials.
- **Raw credentials** (`allow_raw_credentials: true`) — `~/.aws` is left readable so the AWS CLI/SDK use your long-term credential files directly. Simplest, but exposes the credential files to sandboxed commands.
- **Brokered via IMDS** (`force_profile: "<profile>"`) — lite-sandbox starts a local [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)-compatible metadata server on `127.0.0.1` (random port), resolves **temporary** credentials for the named profile, and injects `AWS_EC2_METADATA_SERVICE_ENDPOINT` into the sandbox so the SDK fetches them from there. `~/.aws` is blocked, so the raw credential files are never exposed — only short-lived, auto-refreshed credentials reach the command. Works with SSO, assume-role, and IAM-user profiles.

> SSH private keys in `~/.ssh` are always blocked by the OS sandbox regardless of the AWS mode.

> **Region.** In brokered IMDS mode `~/.aws/config` is masked, so the profile's `region` setting isn't visible to commands. lite-sandbox resolves the brokered profile's region on the host and injects it as both `AWS_REGION` and `AWS_DEFAULT_REGION` (tooling is split on which it honors), so regional AWS commands work without an explicit `--region` — matching how the profile behaves outside the sandbox. An `AWS_REGION`/`AWS_DEFAULT_REGION` already in the environment, a per-command `AWS_REGION=… aws …`, or an explicit `--region` flag all still take precedence. If the profile configures no region, nothing is injected.

### Multiple profiles

`allowed_profiles` lets a command choose among several brokered profiles at
runtime via `AWS_PROFILE`, on top of the default `force_profile`. Each listed
profile gets its own IMDS server; `force_profile` is the default (used when a
command sets no `AWS_PROFILE`) and is always implicitly allowed.

```yaml
aws:
  force_profile: "ro"                 # default profile when no AWS_PROFILE is set
  allowed_profiles: ["dev", "prod"]   # additionally selectable via AWS_PROFILE
```

With this config:

- `aws s3 ls` → uses the `ro` profile (the default).
- `AWS_PROFILE=dev aws s3 ls` → routed to the `dev` profile's broker; the `dev` profile's region is applied.
- `AWS_PROFILE=staging aws s3 ls` → **denied** with `AWS profile "staging" is not in allowed_profiles (dev, prod, ro)` (the message lists what is allowed).
- `aws configure list-profiles` → prints the brokered profiles (`dev`, `prod`, `ro`) so an agent can discover what it may select. (The real command reads the masked `~/.aws` and would return nothing, so lite-sandbox answers it directly.) Only this exact command is intercepted — any additional args or flags run the real command.

How it works: for a command that sets `AWS_PROFILE` (inline `AWS_PROFILE=X aws …`
or an `export` in the same command), lite-sandbox strips the selector and
repoints `AWS_EC2_METADATA_SERVICE_ENDPOINT` (and the region) at that profile's
server — the SDK never reads the masked `~/.aws`. Notes:

- A **shell-level** `AWS_PROFILE` inherited from the host is ignored (stripped) — select a profile per command, not via a session-wide export. This prevents a stray host `AWS_PROFILE` from affecting every command.
- Selecting a profile applies that profile's region, unless the same command sets an explicit `AWS_REGION`/`AWS_DEFAULT_REGION` (or passes `--region`), which is honored.
- Routing applies to normal validated commands. Bare `extra_commands`/`unsandboxed_commands` (which run via raw `bash -c`) always use the default profile.

### Per-directory overrides

AWS settings can be changed for specific working directories through the
top-level [`overrides`](configuration.md#per-directory-overrides) list — the same
generic mechanism every config section uses, not an AWS-only feature. An override
that sets `aws:` fully defines the mode for its directory (at the override's
`path` or any directory beneath it); its fields replace the base AWS settings
rather than merging, so the two modes never mix, and the most specific (longest)
matching `path` wins.

```yaml
aws:
  force_profile: "default"          # base mode for everything else

overrides:
  - path: ~/work/acme               # ~ is expanded
    aws:
      force_profile: "acme-dev"     # broker a different profile here
  - path: ~/work/acme/prod
    aws:
      force_profile: "acme-prod"    # more specific path wins under prod/
  - path: ~/scratch
    aws:
      allow_raw_credentials: true   # switch modes for this tree
```

### CLI

```bash
lite-sandbox config aws show                            # Show current AWS mode and overrides
lite-sandbox config aws allow-raw-credentials           # Enable raw-credentials mode
lite-sandbox config aws force-profile <profile>         # Enable brokered IMDS mode for <profile>
lite-sandbox config aws force-profile <profile> --dir <path>   # ...only for commands run under <path>
lite-sandbox config aws allowed-profiles <name...>      # Set profiles selectable via AWS_PROFILE (no args clears)
lite-sandbox config aws allowed-profiles <name...> --dir <path>  # ...for a per-directory override (set force-profile there first)
lite-sandbox config aws allow-raw-credentials --dir <path>     # ...only for commands run under <path>
lite-sandbox config aws remove-override <path>          # Remove a per-directory override
lite-sandbox config aws disable                         # Disable AWS access entirely
```

## Docker access

The `docker` section routes the docker CLI through a **filtering proxy** instead
of giving it the real daemon socket. The proxy enforces the sandbox's path
boundaries and blocks privilege escalation, while normal container/image
workflows keep working.

```yaml
docker:
  enabled: false               # Enable the docker proxy (default: false)
  socket_path: ""              # Upstream daemon socket; auto-detected if empty
  allow_privileged: false      # Permit privileged containers and escalation flags (default: false)
  allow_host_namespaces: false # Permit --pid=host, --net=host, --ipc=host only (default: false)
  allow_unsandboxed: false     # Permit docker without the OS sandbox (default: false)
```

When enabled, lite-sandbox starts the proxy on a private unix socket, points the
sandboxed CLI at it via `DOCKER_HOST`, and (under the OS sandbox) masks the real
daemon socket so the proxy can't be bypassed.

**Requires the OS sandbox.** Only the OS sandbox can mask the real socket and
make the proxy unbypassable — otherwise a command could just `unset DOCKER_HOST`
(or pass `-H`) and talk to `/var/run/docker.sock` directly. The proxy therefore
refuses to start unless `os_sandbox` is enabled, unless you explicitly opt out
with `allow_unsandboxed: true` (not recommended).

### What the proxy enforces

- **Endpoint allowlist** — Normal read and lifecycle operations on containers, images, networks, and volumes (plus `build`, `exec`, and BuildKit) are forwarded; anything outside the allowlist is rejected with `403`.
- **No privilege escalation** (unless `allow_privileged: true`) — rejects `--privileged`, `--cap-add`, `--device`/`--gpus`, device cgroup rules, `--security-opt` `unconfined`, host PID/IPC/user/network namespaces, and `docker build --network=host`.
- **Host namespaces** (opt-in via `allow_host_namespaces: true`) — permits just `--pid=host`, `--net=host`, and `--ipc=host` (and `docker build --network=host`) without allowing full privileged mode. The host user namespace, container-joined namespaces, and all other escalation vectors stay blocked. Implied by `allow_privileged: true`.
- **Bind-mount confinement** — host bind mounts (`-v`, `--mount type=bind`, and `local`-driver volumes with a `device` path) must resolve inside the sandbox boundary: read-only mounts within the readable paths, read-write mounts within the writable paths. Named/anonymous volumes are allowed. Ambiguous binds are rejected fail-closed.

### Upstream socket auto-detection

If `socket_path` is unset, the upstream daemon socket is resolved in this order:
`DOCKER_HOST` (unix:// only) → the active docker context → well-known per-tool
paths (Docker Desktop, OrbStack, Colima) → `/var/run/docker.sock`.

### CLI

```bash
lite-sandbox config docker show                  # Show current docker config
lite-sandbox config docker enable [--socket <path>]  # Enable the proxy (optionally pin the upstream socket)
lite-sandbox config docker allow-privileged      # Permit privileged containers / escalation flags
lite-sandbox config docker allow-host-namespaces # Permit --pid=host, --net=host, --ipc=host only
lite-sandbox config docker allow-unsandboxed     # Permit docker without the OS sandbox (weakens the boundary)
lite-sandbox config docker disable               # Disable docker access
```
