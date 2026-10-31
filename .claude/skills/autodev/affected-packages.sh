#!/usr/bin/env bash
# Prints the Go packages a branch's changes touch, plus every package in this
# module that depends on them (directly, or through its tests), one import path
# per line. Prints nothing when no Go package is affected (docs/CI-only change).
#
#   affected-packages.sh [base-ref]   # default: origin/main
#
# Changes are measured from the merge base with base-ref and include
# uncommitted and untracked files; `git fetch origin main` first so the base
# is current. A change to go.mod or go.sum affects ./...
set -euo pipefail

base="${1:-origin/main}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

mb="$(git merge-base HEAD "$base")"
files="$( { git diff --name-only "$mb"; git ls-files --others --exclude-standard; } | sort -u)"
[ -n "$files" ] || exit 0

if grep -qxE 'go\.(mod|sum)' <<<"$files"; then
  go list ./...
  exit 0
fi

module="$(go list -m)"

# Every package in the module, with its non-test dependencies and its test
# imports: "<pkg> <dep> <dep> ...".
graph="$(go list -f '{{.ImportPath}}{{range .Deps}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./...)"
all_pkgs="$(cut -d' ' -f1 <<<"$graph")"

# A changed file belongs to the package in its nearest enclosing directory
# below the repository root (so testdata/, embedded assets, etc. count for the
# package that owns them). Markdown never affects a package, and at the root
# only .go files do, so docs/, .github/, .claude/, README.md and friends are
# not tested as the main package.
changed=""
while IFS= read -r f; do
  case "$f" in *.md) continue ;; esac
  d="$(dirname "$f")"
  while [ "$d" != "." ]; do
    if grep -qxF "$module/$d" <<<"$all_pkgs"; then changed+="$module/$d"$'\n'; continue 2; fi
    d="$(dirname "$d")"
  done
  if [ "$(dirname "$f")" = "." ] && [[ "$f" == *.go ]]; then changed+="$module"$'\n'; fi
done <<<"$files"
changed="$(sort -u <<<"$changed" | sed '/^$/d')"
[ -n "$changed" ] || exit 0

# Changed packages plus everything whose deps or test imports include one.
awk -v changed="$changed" '
  BEGIN { n = split(changed, c, "\n"); for (i = 1; i <= n; i++) if (c[i] != "") want[c[i]] = 1 }
  { for (i = 1; i <= NF; i++) if ($i in want) { print $1; next } }
' <<<"$graph" | sort -u
