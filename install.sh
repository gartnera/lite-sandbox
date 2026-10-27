#!/bin/sh
# Install the lite-sandbox binary from a GitHub release.
#
#   curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh
#   curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh -s -- --version v0.9.0 --dir /usr/local/bin
#
# With the GitHub CLI (2.67 or later) installed and logged in, the archive is
# downloaded with `gh release download` and its build provenance attestation is
# checked with `gh attestation verify` (signed by this repository's release
# workflow on main). Otherwise it is downloaded with curl and checked against
# the release's checksums.txt.
#
# The archive and checksum names follow .goreleaser.yaml; change them together.

# `local` is not POSIX, but every sh this runs under (dash, bash, zsh, busybox
# ash) supports it.
# shellcheck disable=SC3043

set -eu

REPO=gartnera/lite-sandbox
BINARY=lite-sandbox
# The release workflow run from main is the only accepted attestation signer.
SIGNER="https://github.com/$REPO/.github/workflows/release.yaml@refs/heads/main"
# gh 2.49-2.66 can report success for an archive with no attestation
# (CVE-2025-25204); older versions have no `gh attestation`.
GH_MIN_MAJOR=2
GH_MIN_MINOR=67

usage() {
	cat <<EOF
Install $BINARY from https://github.com/$REPO/releases

Usage: install.sh [--version <tag>] [--dir <directory>]

  --version <tag>  release to install, e.g. v0.9.0 (default: the latest)
  --dir <dir>      directory to install into (default: \$HOME/.local/bin)
EOF
}

log() {
	printf '%s\n' "$*" >&2
}

fail() {
	log "error: $*"
	exit 1
}

has() {
	command -v "$1" >/dev/null 2>&1
}

# detect_platform prints "<os>_<arch>" in GoReleaser's naming.
detect_platform() {
	local os arch
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) fail "unsupported OS $(uname -s): releases are built for Linux and macOS" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) fail "unsupported architecture $(uname -m): releases are built for amd64 and arm64" ;;
	esac
	echo "${os}_${arch}"
}

# gh_available reports whether a recent enough GitHub CLI is installed and
# logged in to github.com; `gh attestation verify` needs an authenticated API
# client.
gh_available() {
	has gh && gh_recent_enough 2>/dev/null && gh auth status --hostname github.com >/dev/null 2>&1
}

# gh_recent_enough reports whether `gh --version` ("gh version 2.67.0 (...)")
# is at least GH_MIN_MAJOR.GH_MIN_MINOR.
gh_recent_enough() {
	local version major minor
	version=$(gh --version | awk 'NR == 1 { print $3 }')
	major=${version%%.*}
	minor=${version#*.}
	minor=${minor%%.*}
	[ "$major" -gt "$GH_MIN_MAJOR" ] ||
		{ [ "$major" -eq "$GH_MIN_MAJOR" ] && [ "$minor" -ge "$GH_MIN_MINOR" ]; }
}

# latest_tag prints the tag of the latest release.
latest_tag() {
	if [ "$use_gh" = 1 ]; then
		gh api "repos/$REPO/releases/latest" --jq .tag_name
	else
		# github.com redirects /releases/latest to /releases/tag/<tag>; reading
		# the redirect avoids the API's anonymous rate limit.
		local url
		url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
		echo "${url##*/}"
	fi
}

# download_with_gh downloads the archive into $dir and verifies its build
# provenance attestation.
download_with_gh() {
	local tag="$1" archive="$2" dir="$3"
	log "Downloading $archive with gh"
	gh release download "$tag" --repo "$REPO" --pattern "$archive" --dir "$dir"
	log "Verifying the build provenance attestation"
	gh attestation verify "$dir/$archive" --repo "$REPO" --cert-identity "$SIGNER" >/dev/null ||
		fail "$archive failed attestation verification"
}

# download_with_curl downloads the archive into $dir and verifies it against
# the release's checksums.txt.
download_with_curl() {
	local tag="$1" archive="$2" dir="$3"
	local base want got
	base="https://github.com/$REPO/releases/download/$tag"
	log "Downloading $archive"
	curl -fsSL -o "$dir/$archive" "$base/$archive"
	curl -fsSL -o "$dir/checksums.txt" "$base/checksums.txt"
	log "Verifying the checksum"
	want=$(awk -v f="$archive" '$2 == f { print $1 }' "$dir/checksums.txt")
	[ -n "$want" ] || fail "checksums.txt does not list $archive"
	got=$(sha256 "$dir/$archive")
	[ "$got" = "$want" ] || fail "$archive: checksum mismatch: got $got, checksums.txt says $want"
}

sha256() {
	if has sha256sum; then
		sha256sum "$1" | awk '{ print $1 }'
	elif has shasum; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	else
		fail "need sha256sum or shasum to verify the download"
	fi
}

# install_binary extracts the binary from the archive and moves it into
# place, so a running lite-sandbox keeps its old image.
install_binary() {
	local archive="$1" dir="$2" dest_dir="$3"
	local tmp
	tar -xzf "$archive" -C "$dir" "$BINARY"
	mkdir -p "$dest_dir"
	tmp="$dest_dir/.$BINARY.tmp.$$"
	# The EXIT trap removes it if anything below fails.
	staged=$tmp
	cp "$dir/$BINARY" "$tmp"
	chmod 755 "$tmp"
	mv -f "$tmp" "$dest_dir/$BINARY"
}

# physical_dir prints dir with symlinks and extra slashes resolved.
physical_dir() {
	(CDPATH='' cd -- "$1" 2>/dev/null && pwd -P)
}

# on_path reports whether dir is a PATH entry.
on_path() {
	local dir="$1" entry
	local IFS=:
	for entry in $PATH; do
		[ -n "$entry" ] && [ "$(physical_dir "$entry")" = "$dir" ] && return 0
	done
	return 1
}

# runs_installed reports whether `lite-sandbox` on PATH is the one in dir.
runs_installed() {
	local dir="$1" found
	found=$(command -v "$BINARY" 2>/dev/null) || return 1
	[ "$(physical_dir "${found%/*}")" = "$dir" ]
}

# check_path warns when the installed binary is not what `lite-sandbox`
# runs: its directory is missing from PATH, or another lite-sandbox on PATH
# would run instead.
check_path() {
	local dest_dir="$1" found
	if ! on_path "$dest_dir"; then
		log ""
		log "warning: $dest_dir is not on your PATH. Add it to your shell profile:"
		log "  export PATH=\"$dest_dir:\$PATH\""
	fi
	found=$(command -v "$BINARY" 2>/dev/null || true)
	if [ -n "$found" ] && ! runs_installed "$dest_dir"; then
		log ""
		log "warning: \`$BINARY\` runs $found instead of $dest_dir/$BINARY."
		log "Remove it, or put $dest_dir earlier in PATH."
	fi
}

main() {
	version=""
	dest_dir=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--version)
			[ $# -ge 2 ] || fail "--version needs a value"
			version=$2
			shift 2
			;;
		--dir)
			[ $# -ge 2 ] && [ -n "$2" ] || fail "--dir needs a value"
			dest_dir=$2
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage >&2
			fail "unknown argument: $1"
			;;
		esac
	done
	[ -n "$dest_dir" ] || dest_dir="${HOME:?HOME is not set; pass --dir}/.local/bin"

	use_gh=0
	if gh_available; then
		use_gh=1
	else
		has curl || fail "need curl (or a logged-in gh) to download the release"
		log "gh $GH_MIN_MAJOR.$GH_MIN_MINOR+ is not installed or not logged in: skipping attestation verification, checking checksums.txt instead"
	fi

	platform=$(detect_platform)
	[ -n "$version" ] || version=$(latest_tag)
	case "$version" in
	v[0-9]*) ;;
	[0-9]*) version="v$version" ;;
	*) fail "could not determine the release to install (got \"$version\")" ;;
	esac
	archive="${BINARY}_${version#v}_${platform}.tar.gz"

	staged=""
	work=$(mktemp -d)
	trap 'rm -rf "$work" ${staged:+"$staged"}' EXIT

	if [ "$use_gh" = 1 ]; then
		download_with_gh "$version" "$archive" "$work"
	else
		download_with_curl "$version" "$archive" "$work"
	fi
	install_binary "$work/$archive" "$work" "$dest_dir"
	# Absolute and symlink-free, so the PATH check and the messages are exact.
	dest_dir=$(physical_dir "$dest_dir")

	log "Installed $BINARY $version to $dest_dir/$BINARY"
	check_path "$dest_dir"
	cmd="$dest_dir/$BINARY"
	! runs_installed "$dest_dir" || cmd=$BINARY
	log ""
	log "Next: run \`$cmd install\` to configure your agent CLIs (or restart them after an upgrade)."
}

main "$@"
