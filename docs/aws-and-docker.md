# AWS & Docker Access

These opt-in integrations let sandboxed commands use AWS and Docker **without**
access to your raw credentials or an unrestricted daemon socket. Both are
disabled by default and work best with the
[OS sandbox](security.md#os-level-sandboxing-optional) enabled.

## AWS credentials

`~/.aws` is a built-in entry of the OS sandbox's [deny list](configuration.md#denials-read-false-write-false-denylist-mode).
It is hidden in `denylist` mode, and in every mode once credentials are
brokered. The `aws` config section controls whether and how sandboxed commands
get credentials, and sets that entry's scope to match. It has two mutually
exclusive modes:

```yaml
aws:
  allow_raw_credentials: false  # let commands read ~/.aws directly (default: false)
  force_profile: ""             # broker credentials for this profile via a local IMDS server (default: "")
```

- **Disabled** (no `aws` section): `~/.aws` stays blocked under the OS sandbox in `denylist` mode, and commands have no AWS credentials.
- **Raw credentials** (`allow_raw_credentials: true`): the `~/.aws` entry is dropped, so the AWS CLI/SDK read your long-term credential files directly. This is the simplest option but exposes the credential files to sandboxed commands. A `paths` grant on `~/.aws` [lifts the entry](configuration.md#lifting-a-built-in-denial) the same way without touching the `aws` section.
- **Brokered via IMDS** (`force_profile: "<profile>"`): lite-sandbox starts a local [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)-compatible metadata server on `127.0.0.1` (random port), resolves **temporary** credentials for the named profile, and sets `AWS_EC2_METADATA_SERVICE_ENDPOINT` in the sandbox so the SDK fetches them from there. `~/.aws` is blocked in every mode, so commands only ever see short-lived, auto-refreshed credentials. Works with SSO, assume-role, and IAM-user profiles.

> SSH private keys in `~/.ssh` are blocked by the OS sandbox regardless of the AWS mode; only a `paths` grant on `~/.ssh` or on a key [lifts that](configuration.md#lifting-a-built-in-denial).

> **Region.** In brokered IMDS mode `~/.aws/config` is masked, so commands can't see the profile's `region`. lite-sandbox resolves the region on the host and sets both `AWS_REGION` and `AWS_DEFAULT_REGION` (tools differ on which they read), so regional commands work without `--region`, as they do outside the sandbox. An `AWS_REGION`/`AWS_DEFAULT_REGION` already in the environment, a per-command `AWS_REGION=… aws …`, or an explicit `--region` flag takes precedence. If the profile has no region, nothing is set.

### Multiple profiles

`allowed_profiles` lets a command pick one of several brokered profiles with
`AWS_PROFILE`. Each listed profile gets its own IMDS server. `force_profile` is
the default when a command sets no `AWS_PROFILE`, and is always allowed.

```yaml
aws:
  force_profile: "ro"                 # default profile when no AWS_PROFILE is set
  allowed_profiles: ["dev", "prod"]   # additionally selectable via AWS_PROFILE
```

With this config:

- `aws s3 ls` uses the `ro` profile (the default).
- `AWS_PROFILE=dev aws s3 ls` is routed to the `dev` profile's broker, with the `dev` profile's region.
- `AWS_PROFILE=staging aws s3 ls` is **denied** with `AWS profile "staging" is not in allowed_profiles (dev, prod, ro)`.
- `aws configure list-profiles` prints the brokered profiles (`dev`, `prod`, `ro`) so an agent can see what it may select. The real command would read the masked `~/.aws` and print nothing, so lite-sandbox answers it directly. Only this exact command is intercepted; with any extra args or flags, the real command runs.

For a command that sets `AWS_PROFILE` (inline `AWS_PROFILE=X aws …` or an
`export` in the same command), lite-sandbox strips the variable and points
`AWS_EC2_METADATA_SERVICE_ENDPOINT` (and the region) at that profile's server.
The SDK never reads the masked `~/.aws`. Notes:

- An `AWS_PROFILE` inherited from the host shell is stripped and ignored, so a stray host setting can't affect every command. Select a profile per command instead.
- Selecting a profile applies that profile's region, unless the same command sets `AWS_REGION`/`AWS_DEFAULT_REGION` or passes `--region`.
- Routing only applies to validated commands. Bare allowed commands (`commands` entries, with or without `no_sandbox`, which run via raw `bash -c`) always use the default profile.

### Per-directory overrides

AWS settings can be changed per working directory with the top-level
[`overrides`](configuration.md#per-directory-overrides) list, like any other
section. An override that sets `aws:` fully defines the AWS config for its
directory and everything below it: its fields replace the base AWS settings
instead of merging, so the two modes never mix. The most specific (longest)
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
lite-sandbox config aws allowed-profiles <name...> --dir <path>  # ...for a per-directory override
lite-sandbox config aws allow-raw-credentials --dir <path>     # ...only for commands run under <path>
lite-sandbox config aws remove-override <path>          # Remove a per-directory override
lite-sandbox config aws disable                         # Disable AWS access entirely
```

Every `lite-sandbox config` command takes `--dir`; see
[Per-directory overrides](configuration.md#per-directory-overrides).

## Docker access

The `docker` section sends the docker CLI through a **filtering proxy** instead
of the real daemon socket. The proxy enforces the sandbox's path boundaries and
blocks privilege escalation; normal container and image workflows still work.

```yaml
docker:
  enabled: false               # Enable the docker proxy (default: false)
  socket_path: ""              # Upstream daemon socket; auto-detected if empty
  allow_privileged: false      # Permit privileged containers and escalation flags (default: false)
  allow_host_namespaces: false # Permit --pid=host, --net=host, --ipc=host only (default: false)
  allow_unsandboxed: false     # Permit docker without the OS sandbox (default: false)
```

When enabled, lite-sandbox starts the proxy on a private unix socket, points the
sandboxed CLI at it with `DOCKER_HOST`, and (under the OS sandbox) masks the
real daemon socket.

**Requires the OS sandbox.** Without it, the real socket can't be masked, and a
command could `unset DOCKER_HOST` (or pass `-H`) and talk to
`/var/run/docker.sock` directly. The proxy refuses to start unless `os_sandbox`
is enabled or you set `allow_unsandboxed: true` (not recommended).

### What the proxy enforces

- **Endpoint allowlist**: normal read and lifecycle operations on containers, images, networks, and volumes (plus `build`, `exec`, and BuildKit) are forwarded. Anything else is rejected with `403`.
- **No privilege escalation** (unless `allow_privileged: true`): rejects `--privileged`, `--cap-add`, `--device`/`--gpus`, device cgroup rules, `--security-opt` `unconfined`, host PID/IPC/user/network namespaces, and `docker build --network=host`.
- **Host namespaces** (`allow_host_namespaces: true`): permits only `--pid=host`, `--net=host`, and `--ipc=host` (and `docker build --network=host`) without full privileged mode. The host user namespace, container-joined namespaces, and all other escalation flags stay blocked. Implied by `allow_privileged: true`.
- **Bind-mount confinement**: host bind mounts (`-v`, `--mount type=bind`, and `local`-driver volumes with a `device` path) must resolve inside the sandbox boundary: read-only mounts within the readable paths, read-write mounts within the writable paths. Named and anonymous volumes are allowed. Ambiguous binds are rejected.

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
