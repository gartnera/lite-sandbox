# Building & Development

## Building

```bash
go install .            # Build and install lite-sandbox to $GOPATH/bin
lite-sandbox install    # Configure the detected agent CLIs
```

`go build -o lite-sandbox` builds the binary in the working directory instead.

## Development

```bash
go test ./...              # Run all tests
go test -v ./tool/...      # Run tool package tests with verbose output
```

The `Docs` workflow runs [lychee](https://github.com/lycheeverse/lychee) on every Markdown file to check relative links and `#anchor` fragments, with the options in `lychee.toml` (offline; external URLs aren't fetched). To run the same check locally:

```bash
lychee './**/*.md'
```

## Releasing

**Every push to `main` is tagged and released** by `.github/workflows/release.yaml`. It builds Linux and macOS (amd64/arm64) binaries with [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) and uploads them, with a `checksums.txt` and GitHub-generated release notes, to a [GitHub release](https://github.com/gartnera/lite-sandbox/releases). Every asset gets a signed build-provenance attestation, and releases are published as immutable. No manual steps are needed.

### Version bumps via PR labels

The semver bump comes from the `release:*` labels on the pull requests merged since the last release. `.github/scripts/next-version.sh` maps each first-parent commit in `<last tag>..HEAD` to its merged PR through the GitHub API.

| Label | Bump | Use for |
|---|---|---|
| `release:major` | major (minor while on 0.x, see below) | breaking changes |
| `release:minor` | minor | new features |
| `release:patch` | patch | fixes and chores; **the default** for an unlabeled PR or a direct push |
| `release:skip` | none | changes that need no release (docs, CI) |

When several PRs are released together (for example, when a failed run on one commit leaves its changes for the next successful one), the highest bump wins. A release is skipped only when every PR is `release:skip`. The `PR labels` workflow fails a PR with more than one of these labels.

**The project stays on 0.x for now.** `RELEASE_ALLOW_MAJOR` in `release.yaml` is `"false"`, so `release:major` bumps the minor version instead (with a note in the run log). To move to 1.0, set it to `"true"` and merge a `release:major` PR, or push a `v1.0.0` tag by hand and re-run the workflow, since the script starts from the highest existing `v*` tag.

### How the workflow runs

- It runs on every push to `main`. `CI` and `E2E` don't gate it; they're expected to have passed on the pull request (enable a merge queue if that needs enforcing). Runs are serialized (`concurrency: release`) so two merges can't race on the version.
- The workflow creates the tag through the GitHub API (a lightweight tag on the released commit). GoReleaser then builds against it and uploads to a **draft** release (`release.draft: true`). The workflow attests the assets and publishes the draft as its last step, so a half-built release is never visible. If a run fails after the tag exists, re-running the workflow redoes that release, as long as `main` hasn't moved on: the leftover draft is replaced (`replace_existing_draft`), and the version script only counts a *published* release as done. If `main` has moved on, the next release starts from the orphaned tag, which is left with nothing or with an unpublished draft that a maintainer can delete.
- **Immutable releases.** Turn on *release immutability* for the repository once, under *Settings → General → Releases* (or `gh api -X PUT repos/gartnera/lite-sandbox/immutable-releases`; this needs admin, which the workflow token doesn't have). After that, a published release's assets can't be added, changed, or removed, its tag can't be moved or deleted, and GitHub signs a release attestation for the assets on publish. That's why everything that touches assets happens while the release is a draft: GoReleaser refuses to update an immutable release. The workflow prints a warning if a release came out mutable (the setting is off). Releases published before the setting was turned on stay mutable.
- **Attestations.** `actions/attest` signs a [SLSA build-provenance attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations) for each `*.tar.gz` and for `checksums.txt` through GitHub's Sigstore instance (the job has `id-token: write` and `attestations: write`). Attestations are stored on the repository, not as release assets, so the asset list `lite-sandbox update` relies on is unchanged. See [Verifying a download](installation.md#verifying-a-download) for the `gh attestation verify` command.
- The version script fails the run on a GitHub API error instead of guessing, so a failed `Release` run always needs a look; it never means "nothing to release". GitHub keeps at most one pending run per concurrency group, so a burst of merges can drop a pending run. The next release then covers everything since the last tag, so a commit's release is delayed, not lost.
- **Manual release**: *Actions → Release → Run workflow* on `main`. The `bump` input overrides the labels.
- The binaries embed the tag, short commit, and commit date (RFC 3339) in `internal/version` via `-ldflags -X`, and `lite-sandbox version` prints them (`lite-sandbox v0.4.0 (1a2b3c4, 2026-09-05T18:11:02Z)`). Other builds fall back to Go build info: a `go install`ed binary reports its module version, and a `go build` in a checkout reports the tag at HEAD, or a pseudo-version for an untagged commit (so `lite-sandbox update` treats a local build of a tagged commit as up to date). Only a build with no version information reports `dev`.

`lite-sandbox update` (`internal/selfupdate`, built on the GitHub release downloader in `internal/ghrelease` that the e2e suite also uses) depends on the asset names GoReleaser produces (`lite-sandbox_<version>_<os>_<arch>.tar.gz` and `checksums.txt`), so change `.goreleaser.yaml` and `selfupdate.AssetName`/`ChecksumsFile` together.

To dry-run the release build locally without a tag or token:

```bash
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean   # artifacts land in dist/
```

## E2E Testing

There are two suites under `e2e/`. `e2e/mockedserver` runs the real agent binaries against a mock model server; it needs no API key and checks that each installer's configuration works end to end. `e2e/claude` uses a real model to check that Claude actually *chooses* the sandbox tool.

### `e2e/mockedserver`: agents against a mocked model server

This suite runs the **real agent binaries** ([Crush](https://github.com/charmbracelet/crush), [Codex](https://developers.openai.com/codex), [Claude Code](https://code.claude.com), and [opencode](https://opencode.ai)) through `lite-sandbox install <agent>` and a non-interactive run. It checks that each agent loaded the generated config, launched `lite-sandbox serve-mcp`, offered the sandbox tools (and dropped or blocked its built-in shell), and passed the sandbox's results back to the model. `e2e/mockedserver/mockmodel` stands in for the LLM, so no API key is needed.

```bash
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v                 # all agents
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v -run TestCodex  # one agent
```

Before any test runs, regardless of `-run`, `TestMain` sets up everything in `e2e/mockedserver/.bin` (override with `E2E_BIN_DIR`). It builds `lite-sandbox`, downloads the pinned Crush, Codex, and opencode GitHub releases, and downloads the pinned Claude Code native binary from the distribution `claude.ai/install.sh` uses, verified against its manifest checksum. No Node or npm is involved. If `GITHUB_TOKEN` (or `GH_TOKEN`) is set, as it is in the workflow, GitHub downloads go through the authenticated REST API and avoid the per-IP rate limit; otherwise they use the public download URLs.

Versions are pinned in `e2e/mockedserver/versions.go`. Each agent is installed into its own versioned directory (`e2e/mockedserver/.bin/agents/<agent>/<version>`), so switching versions never re-downloads one that's already there. To try a different version for one run, set `E2E_CRUSH_VERSION`, `E2E_CODEX_VERSION`, `E2E_CLAUDE_CODE_VERSION`, or `E2E_OPENCODE_VERSION`. Without `LITE_SANDBOX_E2E`, every test skips, so `go test ./...` stays offline. The `E2E` GitHub workflow runs the same command on Linux and macOS, caching `e2e/mockedserver/.bin/agents` keyed on `versions.go` and `main_test.go`, so CI behaves the same as a local run.

The runs are offline. The model is the mock, and each agent's update and telemetry calls are turned off where the agent has a switch (`DISABLE_AUTOUPDATER` for Claude Code, `check_for_update_on_startup = false` for Codex; Crush's background version check has none). The harness also points `HTTPS_PROXY` at a closed loopback port, so any other outbound https call fails fast and the same way on every machine (`NO_PROXY` keeps the loopback mock off the proxy).

Each test isolates its agent in per-test temp directories using the agent's own config-dir variables (`CRUSH_GLOBAL_CONFIG`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, and the XDG directories for opencode). The installers honor the same variables, so nothing on the developer's machine is read or written.

#### The mock model

The agents use three wire protocols: Crush and opencode use OpenAI chat completions, Codex uses only the OpenAI Responses API, and Claude Code uses the Anthropic Messages API. `mockmodel` is one server with three endpoints (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, streaming and non-streaming). Tests don't see the protocol: every request is normalized into a `Turn` (the tool names offered and the tool results so far), and the scripted behavior is the same for all of them: make the next scripted tool call, or give the final answer once every call has a result. Codex exposes MCP tools under a namespace (`mcp__lite_sandbox` with functions `bash`, …), which the mock records as `mcp__lite_sandbox__bash` and calls back with the namespace-qualified form.

The shared scenario asks each agent to run a blocked command (`curl`, which isn't whitelisted) and then an allowed one, checks the sandbox's rejection and output in the results, and checks that the installer's usage directive (`CLAUDE.md` / `AGENTS.md` / `CRUSH.md`) reached the model. The install modes are covered too:

- **Claude Code**: default (built-in `Bash` denied and removed from the tool list), `--with-tool-hook` (`Bash` stays but the hook blocks it with a redirect, and a `Write` outside the writable paths is denied), and `--bash-ast-hook-mode` (no MCP server; the hook rejects `curl` and lets `echo` run).
- **Codex**: default (the hook redirects the built-in shell, then the MCP tool runs the scenario) and `--bash-ast-hook-mode`. `codex exec` runs with `--dangerously-bypass-hook-trust`, since Codex otherwise skips hooks the user hasn't trusted via `/hooks`.
- **Crush**: both config formats the installer edits (`crushrc` and the legacy `crush.json`). Crush has no hook integration.
- **opencode**: the one install mode (built-in `bash` denied via permissions and removed from the tool list). opencode has no hook protocol.

### `e2e/claude`: Claude Agent SDK against a real model

`e2e/claude` sends real prompts through the Claude Agent SDK and checks that Claude uses the sandboxed MCP tool instead of falling back to built-in Bash. It needs an Anthropic API key and runs on demand, not in CI:

```bash
cd e2e/claude
uv run pytest -v          # Run all e2e tests
uv run pytest -v -k test_go_project_workflow  # Run specific test
```

`e2e/claude/test_go_runtime_e2e.py` runs a full Go workflow (module init, writing code and tests, `go test`, and a git commit) using only the `bash` MCP tool, with no built-in Bash calls.
