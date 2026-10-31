---
name: autodev
description: Headless end-to-end development. Takes a requested feature or fix all the way to a merged PR without check-ins - implement, test the affected Go packages, commit, rebase, code review, then a security review when the change touches the sandbox boundary, triage and fix findings, open a labeled PR with auto-merge, then watch CI and merge conflicts until it merges. Use whenever the prompt contains the word "autodev" or asks for hands-off develop-to-merge work.
argument-hint: <feature or fix to make>
allowed-tools: Bash(go *) Bash(gofmt *) Bash(git *) Bash(gh *)
---

# autodev

Take this request to a merged pull request without check-ins:

$ARGUMENTS

If nothing appears above, the skill was loaded from the word "autodev"
somewhere in the user's message, for example "fix X /autodev". In that case
the request is the rest of that message.

Invoking autodev counts as the user's explicit request to commit, push, open a
pull request, label it, enable auto-merge and merge it once CI is green.
**Every merge to `main` is released**, so the bar for "green" is the full CI.

## Ground rules

- **Headless.** Don't ask the user questions or wait for confirmation. When the
  request is ambiguous, pick the narrowest reasonable reading and write it
  under *Assumptions* in the PR body. Stop and report back only when:
  - every reasonable reading would weaken the sandbox's security model
    (`docs/security.md`) in a way the request doesn't clearly ask for, or
  - the work needs something you can't get, such as credentials, access, or a
    decision about a breaking change.
- **Stay in scope.** If you find an unrelated problem that doesn't block this
  change (a bug, a flaky test, stale docs, a lint nit in code you didn't
  touch), don't fix it. File it as a GitHub issue (see
  [Filing issues](#filing-issues)) and link it from the PR. Fix an unrelated
  problem only when it blocks this change, for example a test broken on `main`
  that fails this PR's CI. Then make the fix a separate commit and explain it
  in the PR.
- **Follow the project rules.** Follow `CLAUDE.md`. In particular, keep
  `docs/` in sync with behavior, read the local `man` page of any command
  whose parsing you change, and follow *Adding or changing a command* in
  `docs/development.md`.
- **Never** skip, disable or loosen a test to get green. Never push to `main`
  or rewrite anyone else's branch. Never push an empty commit or close and
  reopen a PR to restart CI.
- **Keep a running log** of what you ran, what review found, how you triaged
  it, and which issues you filed. The PR body and the final report come from
  it.

## 1. Set up the branch

```bash
git fetch origin main
```

If the session or environment names a development branch, use it. Otherwise
create `autodev/<short-slug>` from `origin/main`. If the branch's earlier PR
has already merged, restart the branch from `origin/main`. Don't stack new
work on merged history.

## 2. Develop

Read enough of the code to change it the way it is already written. Implement
the feature or fix. Add or update tests that would fail without the change.
Update `docs/` and code comments that describe the old behavior.

## 3. Test only what the change affects

Full coverage is CI's job. Locally, use your judgment to pick the packages
the change can affect, and test only those:

- the packages you changed, including their `testdata/` and embedded files;
- packages whose behavior depends on what you changed. For example, a change
  to an exported API, a shared type, or validation logic matters to its
  callers. Grep for the callers. Skip dependents that only import the package
  for something you didn't touch;
- everything (`./...`) when `go.mod` or `go.sum` changed.

```bash
go build ./...
gofmt -l <changed .go files>     # must print nothing
go vet <packages> && go test <packages>
```

A docs-only or CI-only change needs no Go tests.

Add these when they apply:

- **You test `os_sandbox` or `tool/bash_sandboxed`:** rerun those
  packages with `OS_SANDBOX_TESTS=1`. This needs `bwrap` on Linux. If it isn't
  installed, note that CI covers it.
- **Installer, launcher or hook code changed** (`cmd/install*`,
  `cmd/launch*`, `cmd/hook*`, `cmd/pi_extension*`, `e2e/mockedserver`): run
  only the relevant agent with
  `LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v -run Test<Agent>`.
  `TestMain` downloads every pinned agent first. If the network blocks that,
  say so in the PR and rely on the `E2E` workflow.
- **Markdown changed:** run `lychee './**/*.md'` if it is installed. If not,
  the `Docs` workflow checks the links.
- Run a test with `-run` and `-count=1` while you iterate. Rerun every
  package you picked before you commit.

Fix every failure before you move on. If a failure is clearly not caused by
your change, check it against `origin/main`. If it fails there too, it's an
unrelated problem: file an issue, and fix it only if it blocks this change.

## 4. Commit

Commit with an imperative, specific title in the style of `git log`, for
example "Hold ssh's remote command to read-only commands per host". Explain
the why in the body. Add the attribution trailers your environment requires.
Use one logical commit for the change and separate commits for any blocking
fixes.

## 5. Rebase

```bash
git fetch origin main && git rebase origin/main
```

Resolve conflicts by keeping both sides' intent. After a non-trivial
conflict, rerun step 3.

## 6. Code review

Review the branch diff against `origin/main` with a reviewer that hasn't seen
your reasoning. Run the `code-review` skill at `high` on the branch diff. If
it isn't available, start a fresh `Agent` to review it. Give the agent the
diff and the request, not your conclusions.

## 7. Triage

Put each finding in exactly one bucket and log it:

| Bucket | When | Action |
| --- | --- | --- |
| **Fix** | It's real, and it's in code this change adds or alters, or caused by it | Fix it in this PR |
| **Reject** | It's a false positive, or it contradicts the documented design | Log one line on why |
| **Issue** | It's real, but it's pre-existing or unrelated and doesn't block this change | File a GitHub issue; don't fix it |

Check a finding against the code before you act on it. Reviewers can be wrong.

## 8. Fix, retest, commit, rebase

Apply the **Fix** findings. Rerun step 3 and commit, either amending the
change or adding a follow-up commit. Rebase again as in step 5. If the fixes
were substantial, run step 6 once more on the new diff. Do at most two code
review rounds, then proceed.

## 9. Security review (only when the change touches the security boundary)

Run this step only if the diff changes the security boundary: decide from
what the diff does, not just from file names. `tool/bash_sandboxed`,
`os_sandbox`, `config`, `internal/hook`, `cmd/hook*`, `cmd/install*`,
`cmd/launch*`, and anything `docs/security.md` describes usually qualify.
Otherwise skip it and write "Security review: skipped, no security-boundary
change" in the PR's **Review** section.

When it applies, run the `security-review` skill as a separate pass on the
diff you have after step 8, so it sees the code-review fixes. Triage its
findings as in step 7. Fix them as in step 8, and rerun this step after a
substantial fix. Do at most two security review rounds. Also check that
`docs/security.md` still matches the behavior.

## 10. Push and open the PR

```bash
git push --force-with-lease -u origin <branch>
```

Open a PR against `main`. Use the `gh` CLI when it's installed and
authenticated. Otherwise use the GitHub MCP tools (`create_pull_request`,
`issue_write` for labels). If the repository has a PR template, follow its
headings. Otherwise use:

- **Summary:** what the PR changes and why.
- **Testing:** the commands you ran locally, and what you left to CI (full
  `go test ./...`, macOS, E2E).
- **Review:** what the code review and the security review found, each
  separately: findings fixed, findings rejected with reasons, and links to the
  issues you filed. If you skipped the security review, say so.
- **Assumptions:** how you read anything ambiguous in the request.

Add **exactly one** `release:*` label: `release:minor` for a feature,
`release:patch` for a fix or refactor, `release:skip` for a docs-only,
CI-only or tests-only change, `release:major` for a breaking change.

## 11. Auto-merge and watch

Nothing gates a merge on CI here: there is no merge queue, and `main` may not
require status checks. Enabling auto-merge right away could therefore merge
before CI runs.

1. Wait until every check on the PR's **current head SHA** is green: CI on
   Linux and macOS, E2E, PR labels, and Docs when it runs. Then enable
   auto-merge with the squash method (`gh pr merge --auto --squash`, or
   `enable_pr_auto_merge`). If GitHub refuses because the PR is already
   mergeable or auto-merge is turned off for the repository, merge it with
   squash directly. A green PR is what auto-merge would have merged.
2. Keep watching until the PR is merged or closed:
   - **Cloud session with `subscribe_pr_activity`:** subscribe to the PR and
     end the turn. CI results, reviews and conflicts wake the session. Follow
     the rules that arrive with the subscription.
   - **Otherwise:** run `gh pr checks <pr> --watch --fail-fast` in the
     background, and check `gh pr view <pr> --json
     state,mergeable,mergeStateStatus,autoMergeRequest` whenever it finishes
     or `main` moves. Space the checks out to match how long CI takes.
3. **CI failure:** read the failing job's log (`gh run view <run>
   --log-failed`, or `get_job_logs`). Reproduce the failure locally with the
   job's exact command and environment (`OS_SANDBOX_TESTS=1` and so on).
   Fix it and show the same command passing. If the fix touches the security
   boundary, run step 9 on it. Then commit, rebase and push as
   in steps 4, 5 and 10, and wait for green again before re-enabling auto-merge
   if GitHub dropped it. If the failure only happens on macOS, reason from the
   log and say so in the PR. If a failure is unrelated to the diff and passes
   when rerun locally, rerun only the failed jobs once (`gh run rerun <run>
   --failed`). If it fails again, file a flaky-test issue.
4. **Merge conflict** (`mergeable: CONFLICTING` or `mergeStateStatus:
   DIRTY`): rebase onto `origin/main`, resolve, rerun step 3, then push with
   `--force-with-lease`.
5. **Review comments from people:** treat them as findings and triage them as
   in step 7. Reply to the ones you reject with the reason, ending the reply
   with your environment's attribution footer. Don't resolve or dismiss
   anyone else's review.
6. If the same failure survives three fix attempts, stop. Leave the PR open
   with auto-merge off and report what you tried.

After the merge, check that the `CI` and `Release` runs on `main` for the
merge commit pass. If this change broke `main`, start a new autodev run to fix
it forward.

## Filing issues

For each unrelated, non-blocking problem:

1. Search for an existing issue first, with `gh issue list --search
   "<keywords>" --state all` or `gh api -X GET search/issues -f
   q='repo:<owner>/<repo> <keywords>'`. If one already covers it, comment on
   it only if you have new information.
2. Otherwise file a new one with `gh issue create` or the `issue_write` MCP
   tool. Give it a specific title. In the body, cover:
   - what's wrong and where, as `path:line` on `main`'s current SHA;
   - how to reproduce it, or the evidence;
   - why it's out of scope for the autodev PR, with a link to the PR.

   End the body with your environment's attribution footer.
3. Link the issue from the PR's **Review** section and list it in the final
   report.

Don't file an issue for style preferences or speculation. File one only for a
problem you have confirmed.

## Final report

When the PR merges, or when you stop, give the user:

- the PR link and its final state;
- what changed, in two or three lines;
- what you tested locally, and what CI covered;
- the review findings and how you triaged them;
- the issues you filed;
- anything still unresolved.
