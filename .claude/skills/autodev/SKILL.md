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

This skill says *what* to do and *when*. It doesn't say which tools to use.
Use whatever this environment provides for git, GitHub and watching the PR,
and follow the environment's own rules for branches, attribution and PR
activity.

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

## 1. Develop

Work on the branch the environment designates. If it doesn't designate one,
create a new branch from an up-to-date `main`. Read enough of the code to
change it the way it is already written. Implement the feature or fix. Add or
update tests that would fail without the change. Update `docs/` and code
comments that describe the old behavior.

## 2. Test only what the change affects

Full coverage is CI's job. Locally, use your judgment to pick the packages
the change can affect, and test only those:

- the packages you changed, including their `testdata/` and embedded files;
- packages whose behavior depends on what you changed, such as callers of a
  changed API, shared type, or validation logic;
- everything when `go.mod` or `go.sum` changed.

Build the whole module, check `gofmt` on the files you changed, then vet and
test the packages you picked. A docs-only or CI-only change needs no Go tests.

This repo has a few extra suites that only run when you opt in. Run them when
they apply:

- **Sandbox packages** (`os_sandbox`, `tool/bash_sandboxed`): run them with
  `OS_SANDBOX_TESTS=1`. On Linux this needs `bwrap`.
- **Installer, launcher or hook code:** run the mocked-model E2E test for the
  affected agent only (`LITE_SANDBOX_E2E=1`, see *E2E Testing* in
  `docs/development.md`). It downloads the pinned agents first.
- **Markdown:** check the links the way the `Docs` workflow does.

If a suite can't run here (a missing tool, a blocked network), note it in the
PR and rely on CI. Fix every failure before you move on. If a failure looks
unrelated to your change, check it against `main`. If it fails there too, it's
an unrelated problem: file an issue, and fix it only if it blocks this change.

## 3. Commit and rebase

Commit with an imperative, specific title in the style of `git log`, and
explain the why in the body. Use one logical commit for the change and
separate commits for any blocking fixes. Rebase onto the latest `main`,
resolving conflicts by keeping both sides' intent. After a non-trivial
conflict, rerun step 2.

## 4. Code review

Review the branch diff against `main` with a reviewer that hasn't seen your
reasoning, for example the `code-review` skill at `high`, or a fresh agent.
Give the reviewer the diff and the request, not your conclusions.

## 5. Triage

Put each finding in exactly one bucket and log it:

| Bucket | When | Action |
| --- | --- | --- |
| **Fix** | It's real, and it's in code this change adds or alters, or caused by it | Fix it in this PR |
| **Reject** | It's a false positive, or it contradicts the documented design | Log one line on why |
| **Issue** | It's real, but it's pre-existing or unrelated and doesn't block this change | File a GitHub issue; don't fix it |

Check a finding against the code before you act on it. Reviewers can be wrong.

## 6. Fix

Apply the **Fix** findings. Rerun step 2, commit, and rebase again. If the
fixes were substantial, run step 4 once more on the new diff. Do at most two
code review rounds, then proceed.

## 7. Security review (only when the change touches the security boundary)

Run this step only if the diff changes the security boundary: decide from
what the diff does, not just from file names. `tool/bash_sandboxed`,
`os_sandbox`, `config`, `internal/hook`, `cmd/hook*`, `cmd/install*`,
`cmd/launch*`, and anything `docs/security.md` describes usually qualify.
Otherwise skip it and write "Security review: skipped, no security-boundary
change" in the PR's **Review** section.

When it applies, run a separate security review, for example the
`security-review` skill, on the diff you have after step 6, so it sees the
code-review fixes. Triage its findings as in step 5 and fix them as in step 6.
Rerun this step after a substantial fix, with at most two security review
rounds. Also check that `docs/security.md` still matches the behavior.

## 8. Push and open the PR

Push the branch and open a PR against `main`. If the repository has a PR
template, follow its headings. Otherwise use:

- **Summary:** what the PR changes and why.
- **Testing:** what you ran locally, and what you left to CI.
- **Review:** what the code review and the security review found, each
  separately: findings fixed, findings rejected with reasons, and links to the
  issues you filed. If you skipped the security review, say so.
- **Assumptions:** how you read anything ambiguous in the request.

Add **exactly one** `release:*` label: `release:minor` for a feature,
`release:patch` for a fix or refactor, `release:skip` for a docs-only,
CI-only or tests-only change, `release:major` for a breaking change.

## 9. Auto-merge and watch

Nothing in this repo gates a merge on CI: there is no merge queue, and `main`
may not require status checks. Enabling auto-merge right away could therefore
merge, and release, before CI runs.

- Wait until every check on the PR's current head commit is green. Then
  enable auto-merge with the squash method. If GitHub won't enable it
  (for example because the PR is already mergeable), squash-merge the green
  PR directly.
- Keep watching until the PR merges or closes, in whatever way this
  environment supports.
- **CI failure:** read the failing job's log and reproduce the failure
  locally with the job's command and environment. Fix it and show the same
  command passing. If the fix touches the security boundary, run step 7 on
  it. Commit, rebase, push, and wait for green again before re-enabling
  auto-merge if it was dropped. If the failure can't be reproduced here (for
  example, it only happens on macOS), reason from the log and say so in the
  PR. If a failure is unrelated to the diff and looks flaky, rerun the failed
  jobs once. If it fails again, file an issue.
- **Merge conflict:** rebase onto `main`, resolve, rerun step 2, and push.
- **Review comments from people:** triage them as in step 5. Reply to the
  ones you reject with the reason. Don't resolve or dismiss anyone else's
  review.
- If the same failure survives three fix attempts, stop. Leave the PR open
  with auto-merge off and report what you tried.

After the merge, check that CI and the release on `main` pass for the merge
commit. If this change broke `main`, start a new autodev run to fix it
forward.

## Filing issues

For each unrelated, non-blocking problem:

1. Search the repository's issues, open and closed, for an existing one. If
   one covers the problem, comment on it only if you have new information.
2. Otherwise file a new issue with a specific title. In the body, cover:
   - what's wrong and where, as `path:line` on `main`;
   - how to reproduce it, or the evidence;
   - why it's out of scope for the autodev PR, with a link to the PR.
3. Link the issue from the PR's **Review** section and list it in the final
   report.

File an issue only for a problem you have confirmed, not for style
preferences or speculation.

## Final report

When the PR merges, or when you stop, give the user:

- the PR link and its final state;
- what changed, in two or three lines;
- what you tested locally, and what CI covered;
- the review findings and how you triaged them;
- the issues you filed;
- anything still unresolved.
