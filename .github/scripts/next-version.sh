#!/usr/bin/env bash
# next-version.sh — compute the next release tag from pull request labels.
#
# Prints the tag to create (e.g. "v0.4.0") on stdout, or nothing when there is
# nothing to release. Progress and reasoning go to stderr. Runs in
# .github/workflows/release.yaml against a full checkout (all history + tags) of
# the commit to release.
#
# The bump is decided by the release:* labels on the pull requests merged since
# the last release (every first-parent commit in <last tag>..HEAD, resolved to
# its PR through the GitHub API):
#
#   release:major  breaking change
#   release:minor  new feature
#   release:patch  fix or chore — also the default for an unlabeled PR, or a
#                  commit pushed without one
#   release:skip   no release for this change
#
# The highest bump across those PRs wins; a release is skipped only when every
# one of them is release:skip. While RELEASE_ALLOW_MAJOR is not "true", a major
# bump is downgraded to a minor one, keeping the project on 0.x until the
# maintainers opt in (or push a v1.0.0 tag by hand).
#
# Usage: next-version.sh [--bump auto|patch|minor|major]
#   --bump   override the label-derived bump (the workflow_dispatch input)
#
# Environment:
#   GITHUB_REPOSITORY    owner/name (set by Actions)
#   GH_TOKEN             token for `gh api`
#   RELEASE_ALLOW_MAJOR  "true" to let release:major bump the major version
set -euo pipefail

bump_override=auto
while [ $# -gt 0 ]; do
  case "$1" in
    --bump) bump_override=${2:?--bump needs a value}; shift 2 ;;
    *) echo "usage: $0 [--bump auto|patch|minor|major]" >&2; exit 2 ;;
  esac
done
case "$bump_override" in auto|patch|minor|major) ;; *) echo "invalid --bump: $bump_override" >&2; exit 2 ;; esac

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}
allow_major=${RELEASE_ALLOW_MAJOR:-false}
log() { echo "$*" >&2; }

# Levels: 0 skip, 1 patch, 2 minor, 3 major.
level_of_label() {
  case "$1" in
    release:major) echo 3 ;;
    release:minor) echo 2 ;;
    release:patch) echo 1 ;;
    release:skip)  echo 0 ;;
    *) echo -1 ;;
  esac
}
level_name() { case "$1" in 3) echo major ;; 2) echo minor ;; 1) echo patch ;; *) echo skip ;; esac; }

head=$(git rev-parse HEAD)
latest=$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n1 || true)

if [ -n "$latest" ]; then
  if git merge-base --is-ancestor "$head" "$latest"; then
    # Nothing new. The one exception: HEAD is the last tag itself but the
    # release never made it out (a failed upload) — re-emit the tag so
    # GoReleaser can complete it.
    if [ "$(git rev-parse "$latest^{commit}")" = "$head" ] && ! gh release view "$latest" --repo "$repo" >/dev/null 2>&1; then
      log "$latest is tagged at HEAD but has no GitHub release yet; releasing it"
      echo "$latest"
    else
      log "HEAD ($head) is already included in $latest; nothing to release"
    fi
    exit 0
  fi
  range="$latest..$head"
  base=${latest#v}
else
  # First release ever: only the commit being released is considered.
  range="$head^!"
  base=0.0.0
  log "no release tag found; starting from v$base"
fi

# pr_labels prints the release labels of the merged PR that introduced the
# commit to the default branch (nothing for a commit pushed without a PR). An
# API failure is retried once and then fatal: guessing here would publish a
# wrong version, which cannot be taken back.
pr_labels() {
  local sha=$1 out
  for attempt in 1 2; do
    if out=$(gh api "repos/$repo/commits/$sha/pulls" --jq '.[] | select(.merged_at != null) | .labels[].name' 2>&1); then
      echo "$out"
      return 0
    fi
    log "gh api commits/$sha/pulls failed (attempt $attempt): $out"
    sleep 2
  done
  return 1
}

level=0
for sha in $(git rev-list --first-parent "$range"); do
  labels=$(pr_labels "$sha") || { log "cannot resolve the pull request for $sha; refusing to guess the version"; exit 1; }
  commit_level=-1
  for l in $labels; do
    ll=$(level_of_label "$l")
    if [ "$ll" -gt "$commit_level" ]; then commit_level=$ll; fi
  done
  if [ "$commit_level" -lt 0 ]; then
    commit_level=1 # no release label: patch
    log "${sha:0:12}: no release label -> patch"
  else
    log "${sha:0:12}: $(level_name "$commit_level")"
  fi
  if [ "$commit_level" -gt "$level" ]; then level=$commit_level; fi
done

if [ "$bump_override" != auto ]; then
  case "$bump_override" in major) level=3 ;; minor) level=2 ;; patch) level=1 ;; esac
  log "bump overridden to $bump_override"
fi

if [ "$level" -eq 0 ]; then
  log "every change since $latest is release:skip; nothing to release"
  exit 0
fi

if [ "$level" -eq 3 ] && [ "$allow_major" != true ]; then
  log "release:major requested but RELEASE_ALLOW_MAJOR is not true; bumping the minor version instead"
  level=2
fi

IFS=. read -r major minor patch <<<"$base"
case "$level" in
  3) major=$((major + 1)); minor=0; patch=0 ;;
  2) minor=$((minor + 1)); patch=0 ;;
  1) patch=$((patch + 1)) ;;
esac
next="v$major.$minor.$patch"
log "next release: $next ($(level_name "$level") bump from ${latest:-none})"
echo "$next"
