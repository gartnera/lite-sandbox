# CLAUDE.md

## Commands

```bash
go build -o lite-sandbox
go test ./...
OS_SANDBOX_TESTS=1 go test ./...                     # include real OS sandbox tests (needs bubblewrap on Linux)
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v    # agent e2e against a mock model; run after security/validation/installer changes
cd e2e/claude && uv run pytest -v                    # real-model e2e (needs API key)
```

## Notes

- `docs/security.md` is the source of truth for the security model; keep `docs/` in sync with behavior changes.
- monty (embedded Python) comes from the `gartnera/monty-go` fork; changing the Go/wasm boundary means rebuilding `monty.wasm` there.
- Always inspect local `man` pages of commands you are asked to parse.
- Label every PR with exactly one `release:*` label (`minor` feature, `patch` fix/refactor, `skip` docs/CI/tests only, `major` breaking). Every merge to `main` is released.
